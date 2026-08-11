//! `shellflow deploy` — standardized multi-host service deployment.
//!
//! Composes an [`ExecutionPlan`] in memory from a conventional repository
//! layout and runs it through the existing executor (fan-out, dry-run/diff,
//! masking, timeouts).
//!
//! Layout conventions (all overridable by flags):
//!
//! ```text
//! <repo>/
//!   hosts/inventory.sh              # @server / @group directives
//!   services/<service>/
//!     env/*.env.age                 # merged lexically; common before specific
//!     units/*.service               # systemd unit templates
//!     configs/*                     # non-secret configuration
//! ```

use std::{
    fs,
    path::{Path, PathBuf},
};

use eyre::{Context as _, Result, bail, eyre};
use shellflow_core::{CopyStep, EnvEntry, ExecutionPlan, RemoteStep, Step, Target, parse_script};
use shellflow_secrets::{
    crypto::decrypt_bytes,
    env::parse_env_file,
    identity::{effective_identity_path, load_x25519_identity},
};

use crate::cli::DeployArgs;

/// Remote staging directory used by the copy + install steps.
const STAGE_DIR: &str = "/tmp/shellflow";

/// Build the deployment plan for `args`.
///
/// # Errors
///
/// Fails when the inventory is missing/empty, the target group is unknown,
/// the binary is missing, no env files exist, decryption fails, or a shared
/// key has conflicting values across services.
pub(crate) fn build_plan(args: &DeployArgs) -> Result<ExecutionPlan> {
    // 1) Inventory: reuse the parser to collect @server/@group.
    let inventory = fs::read_to_string(&args.inventory)
        .wrap_err_with(|| format!("failed to read inventory `{}`", args.inventory.display()))?;
    let mut plan = parse_script(&inventory).map_err(|err| eyre!("{err}"))?;
    if plan.servers.is_empty() {
        bail!("inventory `{}` declares no `@server` entries", args.inventory.display());
    }
    if !plan.groups.contains_key(&args.group) && !plan.servers.contains_key(&args.group) {
        bail!("target `{}` is neither a group nor a server in the inventory", args.group);
    }
    let target = Target::new(args.group.clone());

    // 2) Binary.
    let binary =
        args.binary.clone().unwrap_or_else(|| PathBuf::from("target/release").join(&args.service));
    if !binary.is_file() {
        bail!("binary not found: {} (use `--binary`)", binary.display());
    }

    // 3) Decrypt + merge env files (lexical order; later files win).
    let svc_dir = args.service_dir.join(&args.service);
    let env_dir = svc_dir.join("env");
    let id_path = effective_identity_path(args.flags.identity.as_deref());
    let identity = load_x25519_identity(&id_path)
        .map_err(|err| eyre!("{err} (identity: {})", id_path.display()))?;

    let merged = merge_env(&env_dir, &identity)?;
    if merged.is_empty() {
        bail!("no decrypted env entries in `{}`", env_dir.display());
    }
    check_cross_service(&args.service_dir, &args.service, &merged, &identity)?;

    let env_entries: Vec<EnvEntry> = merged
        .iter()
        .map(|(key, value)| EnvEntry::Literal { key: key.clone(), value: value.clone() })
        .collect();
    // The executor masks literal `plan.env` values; mirror them here so the
    // injected secrets never appear in previews, traces, or logs.
    plan.env.clone_from(&env_entries);

    // 4) Units + configs.
    let units_dir = svc_dir.join("units");
    let configs_dir = svc_dir.join("configs");
    let has_units = units_dir.is_dir();
    let has_configs = configs_dir.is_dir();
    let mut units: Vec<String> = Vec::new();
    if has_units {
        units = fs::read_dir(&units_dir)
            .wrap_err("failed to list units directory")?
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".service"))
            .collect();
        units.sort();
    }

    let stage = format!("{STAGE_DIR}/{}", args.service);

    // 5) Steps.
    plan.steps.push(Step::Copy(CopyStep {
        name: Some("ship-binary".to_string()),
        src: binary.display().to_string(),
        dst: format!("{stage}/app"),
        target: target.clone(),
        delete: false,
        guard: None,
        timeout: None,
    }));
    if has_units {
        plan.steps.push(Step::Copy(CopyStep {
            name: Some("ship-units".to_string()),
            src: units_dir.display().to_string(),
            dst: format!("{stage}/units"),
            target: target.clone(),
            delete: false,
            guard: None,
            timeout: None,
        }));
    }
    if has_configs {
        plan.steps.push(Step::Copy(CopyStep {
            name: Some("ship-configs".to_string()),
            src: configs_dir.display().to_string(),
            dst: format!("{stage}/configs"),
            target: target.clone(),
            delete: false,
            guard: None,
            timeout: None,
        }));
    }

    let keys: Vec<String> = merged.iter().map(|(key, _)| key.clone()).collect();
    plan.steps.push(Step::Remote(RemoteStep {
        name: Some("install".to_string()),
        target: target.clone(),
        script: install_script(&args.service, &keys),
        guard: Some(format!("test -f {stage}/app")),
        timeout: Some(600),
        env: env_entries,
    }));

    if let Some(first) = units.first() {
        plan.steps.push(Step::Remote(RemoteStep {
            name: Some("restart".to_string()),
            target,
            script: restart_script(&units),
            guard: Some(format!("test -f /etc/systemd/system/{first}")),
            timeout: Some(300),
            env: Vec::new(),
        }));
    }

    Ok(plan)
}

/// Decrypt and merge all `*.env.age` files in `env_dir` (lexical order; later
/// files win on key conflicts).
fn merge_env(env_dir: &Path, identity: &age::x25519::Identity) -> Result<Vec<(String, String)>> {
    let mut files: Vec<PathBuf> = if env_dir.is_dir() {
        fs::read_dir(env_dir)
            .wrap_err("failed to list env directory")?
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|ext| ext == "age"))
            .collect()
    } else {
        Vec::new()
    };
    files.sort();

    let mut merged: Vec<(String, String)> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for file in files {
        let cipher = fs::read(&file)
            .wrap_err_with(|| format!("failed to read env file `{}`", file.display()))?;
        let plain = decrypt_bytes(&cipher, identity)
            .wrap_err_with(|| format!("failed to decrypt `{}`", file.display()))?;
        let plain = String::from_utf8(plain)
            .wrap_err_with(|| format!("decrypted `{}` is not valid UTF-8", file.display()))?;
        for (key, value) in parse_env_file(&plain)
            .wrap_err_with(|| format!("malformed env file `{}`", file.display()))?
        {
            if let Some(idx) = seen.iter().position(|k| k == &key) {
                merged[idx] = (key, value);
            } else {
                seen.push(key.clone());
                merged.push((key, value));
            }
        }
    }
    Ok(merged)
}

/// Fail when a key shared with another service has a conflicting value —
/// systemd credential stores are global per host, so identical names must
/// carry identical values.
fn check_cross_service(
    service_dir: &Path,
    current: &str,
    current_env: &[(String, String)],
    identity: &age::x25519::Identity,
) -> Result<()> {
    if !service_dir.is_dir() {
        return Ok(());
    }
    for sibling in fs::read_dir(service_dir).wrap_err("failed to list services")?.flatten() {
        let name = sibling.file_name().to_string_lossy().into_owned();
        if name == current || !sibling.path().is_dir() {
            continue;
        }
        let other = merge_env(&sibling.path().join("env"), identity)?;
        for (key, value) in current_env {
            if let Some((_, other_value)) = other.iter().find(|(k, _)| k == key) &&
                other_value != value
            {
                bail!(
                    "key `{key}` has conflicting values in services `{current}` and `{name}`; \
                     systemd credential stores are global, so shared keys must agree \
                     (rename one of them)"
                );
            }
        }
    }
    Ok(())
}

/// The credential→environment wrapper installed on every target.
///
/// Export each file in `$CREDENTIALS_DIRECTORY` as an environment variable
/// named after the file, then `exec` the real binary. This lets units run
/// third-party/closed-source applications (which read env vars directly)
/// with **zero application changes** — the same tmpfs-backed, per-unit,
/// host-key-bound protection as the in-app loader (§8.3 of the design doc).
///
/// The script lives at `scripts/cred-wrap` in the repository; `include_str!`
/// keeps the deployed artifact identical to the committed file.
pub(crate) const CRED_WRAP_PATH: &str = "/usr/local/libexec/shellflow/cred-wrap";

const CRED_WRAP: &str = include_str!("../../../scripts/cred-wrap");

/// The remote install script: install the cred-wrap helper, binary, units,
/// and configs; write one host-key-bound credential per env key; then clean
/// up the staging dir.
fn install_script(service: &str, keys: &[String]) -> String {
    let keys = keys.join(" ");
    format!(
        r#"set -eu
sudo install -d -m 0700 -o root -g root /etc/credstore.encrypted
sudo install -d -m 0755 -o root -g root /opt/{service}/bin /opt/{service}/config
sudo install -d -m 0755 -o root -g root /usr/local/libexec/shellflow
cat > /tmp/shellflow/{service}/cred-wrap <<'SHELLFLOW_CRED_WRAP'
{cred_wrap}SHELLFLOW_CRED_WRAP
sudo install -m 0755 -o root -g root /tmp/shellflow/{service}/cred-wrap {cred_wrap_path}
sudo install -m 0755 -o root -g root /tmp/shellflow/{service}/app /opt/{service}/bin/app
if [ -d /tmp/shellflow/{service}/units ] && compgen -G '/tmp/shellflow/{service}/units/*.service' >/dev/null; then
  sudo install -m 0644 -o root -g root -t /etc/systemd/system /tmp/shellflow/{service}/units/*.service
fi
if [ -d /tmp/shellflow/{service}/configs ] && compgen -G '/tmp/shellflow/{service}/configs/*' >/dev/null; then
  sudo install -m 0644 -o root -g root -t /opt/{service}/config /tmp/shellflow/{service}/configs/*
fi
for key in {keys}; do
  printf '%s' "${{!key}}" | sudo systemd-creds encrypt --with-key=host --name="$key" - "/etc/credstore.encrypted/${{key}}"
  sudo chmod 0600 "/etc/credstore.encrypted/${{key}}"
done
rm -rf /tmp/shellflow/{service}
"#,
        cred_wrap = CRED_WRAP,
        cred_wrap_path = CRED_WRAP_PATH,
    )
}

/// The remote restart script for the deployed units.
fn restart_script(units: &[String]) -> String {
    let units = units.join(" ");
    format!(
        "set -eu\n\
         sudo systemctl daemon-reload\n\
         sudo systemctl enable {units}\n\
         sudo systemctl restart {units}\n\
         sudo systemctl --no-pager --quiet is-active {units}\n"
    )
}

#[cfg(test)]
mod tests {
    use super::{CRED_WRAP_PATH, install_script, restart_script};

    #[test]
    fn install_script_embeds_keys_without_exposure_in_argv() {
        let script = install_script("demo", &["API_KEY".to_string(), "SECRET".to_string()]);
        assert!(script.contains("for key in API_KEY SECRET; do"));
        // Indirect expansion reads the value from the env header at runtime.
        assert!(script.contains("${!key}"));
        assert!(script.contains("/opt/demo/bin/app"));
    }

    #[test]
    fn install_script_installs_cred_wrap() {
        let script = install_script("demo", &["API_KEY".to_string()]);
        // The wrapper is installed once per target for third-party apps.
        assert!(script.contains("SHELLFLOW_CRED_WRAP"));
        assert!(script.contains(&format!("cred-wrap {CRED_WRAP_PATH}")));
        assert!(script.contains("export \"$key=$(cat \"$f\")\""));
        assert!(script.contains("exec \"$@\""));
    }

    #[test]
    fn restart_script_lists_units() {
        let script = restart_script(&["demo-a.service".to_string(), "demo-b.service".to_string()]);
        assert!(script.contains("systemctl enable demo-a.service demo-b.service"));
        assert!(script.contains("is-active demo-a.service demo-b.service"));
    }
}
