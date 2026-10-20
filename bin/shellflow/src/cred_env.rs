//! `shellflow cred-env` — target-side credential helpers.
//!
//! These subcommands run **on the target host** (the binary is installed once
//! per host by a deploy playbook). They are deliberately self-contained: no
//! age identities, no network, no playbook parsing — only
//! `$CREDENTIALS_DIRECTORY` (systemd), the environment a playbook block
//! injected, and `systemd-creds` (which owns the host-key encryption format).
//!
//! | Subcommand | Replaces |
//! |---|---|
//! | `exec <cmd>` | the per-service `bin/<svc>-start` export loop |
//! | `render <tmpl> <out>` | the per-service tmpfs config heredoc |
//! | `credstore-install <svc>` | the deploy-time credential re-seal loop |
//!
//! The bash fallback (`shellflow emit cred-env`) implements the same
//! semantics for targets that cannot host the binary; the integration tests
//! run both against one shared fixture set.

use std::{
    collections::HashMap,
    env,
    ffi::OsStr,
    fs,
    io::Write as _,
    os::unix::{ffi::OsStrExt as _, process::CommandExt as _},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use eyre::{Context, Result, bail, eyre};

use crate::{cli::CredEnvCmd, fsx::write_secret_file};

/// `systemd` sets this for units that declare credentials.
const CREDENTIALS_DIRECTORY: &str = "CREDENTIALS_DIRECTORY";
/// `shellflow @secrets` exports this space-separated key list into blocks.
const SECRET_KEYS_VAR: &str = "LT_SECRET_KEYS";
/// Default root of the per-service host-key-bound credential store.
const DEFAULT_STORE_ROOT: &str = "/etc/credstore.encrypted";

/// Run a `cred-env` subcommand.
///
/// # Errors
///
/// Propagates I/O, template, and `systemd-creds` failures.
pub(crate) fn run(cmd: &CredEnvCmd) -> Result<()> {
    match cmd {
        CredEnvCmd::Exec(args) => exec(&args.command),
        CredEnvCmd::Render(args) => render(&args.template, &args.output),
        CredEnvCmd::CredstoreInstall(args) => {
            credstore_install(&args.service, args.store_dir.as_deref())
        }
    }
}

/// True for `[a-z][a-z0-9-]*` without `--`: service names become a directory
/// component, so `.`, `..`, `/`, whitespace, and leading `-` are rejected.
pub(crate) fn is_valid_service_name(name: &str) -> bool {
    if name.is_empty() || name.contains("--") {
        return false;
    }
    let mut chars = name.chars();
    match chars.next() {
        Some(first) if first.is_ascii_lowercase() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// True for `[A-Za-z_][A-Za-z0-9_]*` — the exact shape `parse_env_file`
/// accepts, so credential filenames can only ever be valid variable names.
pub(crate) fn is_valid_var_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() || first == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// One credential: filename (the variable name) and its raw bytes.
struct Credential {
    name: String,
    bytes: Vec<u8>,
}

/// The credential directory, or fail closed.
///
/// `$CREDENTIALS_DIRECTORY` is set by systemd for every unit that declares
/// credentials, so an unset (or non-directory) value means the unit declared
/// none — running `cred-env` then is a misconfiguration, not a no-op.
fn credential_dir() -> Result<PathBuf> {
    let dir = env::var_os(CREDENTIALS_DIRECTORY).unwrap_or_default();
    if dir.is_empty() {
        bail!("cred-env: ${CREDENTIALS_DIRECTORY} is not set (no credentials imported?)");
    }
    let path = PathBuf::from(dir);
    if !path.is_dir() {
        bail!("cred-env: ${CREDENTIALS_DIRECTORY} `{}` is not a directory", path.display());
    }
    Ok(path)
}

/// Read the credential directory into credential pairs (sorted by name).
///
/// # Errors
///
/// Returns when `$CREDENTIALS_DIRECTORY` is unset or unreadable, or when a
/// credential file cannot be read.
fn load_credentials() -> Result<Vec<Credential>> {
    let dir = credential_dir()?;
    let mut out: Vec<Credential> = Vec::new();
    let entries = fs::read_dir(&dir).wrap_err_with(|| {
        format!("cred-env: cannot read ${CREDENTIALS_DIRECTORY} `{}`", dir.display())
    })?;
    for entry in entries {
        let entry = entry.wrap_err("cred-env: cannot read credential directory entry")?;
        // Mirror the bash fallback (`[ -f "$f" ] || continue`): skip
        // subdirectories and other non-regular files instead of failing.
        let file_type = entry.file_type().wrap_err("cred-env: cannot stat credential entry")?;
        if !file_type.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if !is_valid_var_name(&name) {
            continue;
        }
        let bytes = fs::read(entry.path())
            .wrap_err_with(|| format!("cred-env: cannot read credential `{name}`"))?;
        out.push(Credential { name, bytes });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// Credential values as strings, for template rendering.
///
/// # Errors
///
/// Names the credential when its bytes are not valid UTF-8 — a config
/// template is text, so a non-UTF-8 value cannot be substituted safely.
fn credential_strings(creds: &[Credential]) -> Result<Vec<(String, String)>> {
    let mut out = Vec::with_capacity(creds.len());
    for cred in creds {
        let value = String::from_utf8(cred.bytes.clone())
            .map_err(|_| eyre!("cred-env: credential `{}` is not valid UTF-8", cred.name))?;
        out.push((cred.name.clone(), value));
    }
    Ok(out)
}

/// Export every credential as an env var (filename = variable name) and exec
/// the command. Never returns on success: `exec` replaces this process, so
/// systemd's main PID, signals, and supervision all apply to the real
/// program.
///
/// # Errors
/// Returns when the command cannot be spawned or `exec` fails.
pub(crate) fn exec(command: &[String]) -> Result<()> {
    let Some((program, args)) = command.split_first() else {
        bail!("cred-env exec: missing command");
    };
    let creds = load_credentials()?;
    let mut cmd = Command::new(program);
    cmd.args(args);
    for cred in &creds {
        // Env values may hold arbitrary bytes, so stay in `OsStr` land.
        cmd.env(&cred.name, OsStr::from_bytes(&cred.bytes));
    }
    let error = cmd.exec();
    // `exec` only returns on failure.
    Err(eyre!("cred-env exec {program}: {error}"))
}

/// Render `${KEY}` placeholders from `$CREDENTIALS_DIRECTORY` into `output`.
///
/// Fails closed: if any referenced credential is missing (or not valid
/// UTF-8), nothing is written — a service must never start with a
/// half-substituted config.
///
/// # Errors
///
/// Returns on unreadable template/credentials, non-UTF-8 values, missing
/// keys, or I/O failures.
pub(crate) fn render(template: &Path, output: &Path) -> Result<()> {
    let content = fs::read_to_string(template)
        .wrap_err_with(|| format!("cred-env: cannot read template `{}`", template.display()))?;
    let creds = load_credentials()?;
    let values = credential_strings(&creds)?;
    let map: HashMap<String, String> = values.into_iter().collect();
    let rendered = shellflow_core::render_template(&content, &map).map_err(|missing| {
        eyre!("cred-env: template references missing credential(s): {}", missing.join(", "))
    })?;
    write_secret_file(output, rendered.as_bytes())
}

/// Install the environment's credentials into a per-service host-key-bound
/// store (`/etc/credstore.encrypted/<SVC>/<KEY>` by default).
///
/// Mirrors the playbook contract: the store is cleared first (so rotation and
/// key removal take effect), then every key in `$LT_SECRET_KEYS` is sealed
/// with `systemd-creds encrypt --with-key=host`. Values travel on stdin —
/// never argv, never a file.
///
/// An **unset** `$LT_SECRET_KEYS` is a caller error (the store would be wiped
/// for nothing); a **set-but-empty** list is an explicit "this service has no
/// credentials" and clears the store.
///
/// Privilege handling: writing the store needs root. When invoked
/// unprivileged, the command re-executes itself under
/// `sudo --preserve-env=<exact key list>` — only `LT_SECRET_KEYS` and the
/// credential values cross the boundary (never `sudo -E`, which would leak
/// the whole playbook environment into root). Playbooks call it as plain
/// `sudo shellflow cred-env credstore-install <svc>`.
///
/// # Errors
///
/// Returns when a key is missing or empty in the environment, when its name
/// is invalid, or when any `sudo`/`systemd-creds` invocation fails.
pub(crate) fn credstore_install(service: &str, store_dir: Option<&Path>) -> Result<()> {
    if !is_valid_service_name(service) {
        // Service names become a directory component; keep them strict so `.`
        // (which resolves to the store root) or `a/b` can never cause the
        // `find -delete` below to wipe other services.
        bail!("cred-env credstore-install: unsafe service name `{service}`");
    }
    let Some(raw_keys) = env::var_os(SECRET_KEYS_VAR) else {
        bail!(
            "cred-env credstore-install: ${SECRET_KEYS_VAR} is not set — run inside a \
             shellflow `@secrets` block (a set-but-empty list clears the store)"
        );
    };
    let keys: Vec<String> =
        raw_keys.to_string_lossy().split_whitespace().map(ToOwned::to_owned).collect();
    for key in &keys {
        if !is_valid_var_name(key) {
            bail!("cred-env credstore-install: invalid credential key `{key}`");
        }
    }
    // Privilege boundary: the store is root-only. Instead of `sudo -E`
    // (which would leak the whole playbook environment into root), values
    // are piped to a re-executed self over stdin — never argv, never env.
    ensure_elevation(service, store_dir, &keys)?;

    seal_into_store(service, store_dir, &keys)
}

/// Atomic staging-swap installer shared by the env path
/// (`credstore-install`) and the piped-bundle path (`__seal-bundle`).
fn seal_into_store(service: &str, store_dir: Option<&Path>, keys: &[String]) -> Result<()> {
    let default_store = format!("{DEFAULT_STORE_ROOT}/{service}");
    let store = store_dir.map_or_else(|| PathBuf::from(&default_store), Path::to_path_buf);
    // Build the whole new store beside the live one, then swap it in. The
    // previous behaviour cleared `/etc/credstore.encrypted/<svc>/` first, so a
    // failure part-way through (full disk, missing `systemd-creds`, expired
    // sudo) left the service with an empty or half-written credential store
    // and every unit depending on it broken.
    let store = PathBuf::from(&store);
    let staging = store.with_file_name(format!(
        "{}.new",
        store.file_name().map_or_else(|| "store".into(), |n| n.to_string_lossy().into_owned())
    ));

    sudo(&["install", "-d", "-m", "0700", &store.to_string_lossy()])?;
    let _ = fs::remove_dir_all(&staging);
    sudo(&["install", "-d", "-m", "0700", &staging.to_string_lossy()])?;

    let seal_result = seal_all(keys, &staging);
    if let Err(err) = seal_result {
        // The live store was never touched; drop the partial staging tree.
        let _ = fs::remove_dir_all(&staging);
        return Err(err);
    }

    // Every credential is sealed: swap the staging tree and the live store.
    // Where the platform supports an atomic exchange, the two paths are
    // swapped in one syscall — there is no window in which the credential
    // store does not exist, so a unit that starts during the swap still
    // finds its credentials. Elsewhere the store is renamed aside and the
    // staging tree renamed into place; the failure paths restore the
    // previous store, so the residual is a very short availability gap
    // rather than a data-loss risk.
    if exchange_dirs(&staging, &store) {
        let _ = fs::remove_dir_all(&staging);
        return Ok(());
    }

    let retired = store.with_extension("old");
    let _ = fs::remove_dir_all(&retired);
    let had_previous = store.exists();
    if had_previous && fs::rename(&store, &retired).is_err() {
        let _ = fs::remove_dir_all(&staging);
        bail!(
            "cred-env credstore-install: cannot retire the previous store at `{}`",
            store.display()
        );
    }
    if let Err(err) = fs::rename(&staging, &store) {
        // Put the previous store back so the service is never left without one.
        if had_previous {
            let _ = fs::rename(&retired, &store);
        }
        let _ = fs::remove_dir_all(&staging);
        bail!(
            "cred-env credstore-install: cannot install the new store at `{}`: {err}",
            store.display()
        );
    }
    let _ = fs::remove_dir_all(&retired);
    Ok(())
}

/// Exchange two directories atomically, if the platform supports it.
///
/// Returns `false` when the exchange is unavailable or failed, in which case
/// the caller falls back to the two-rename swap.
fn exchange_dirs(a: &Path, b: &Path) -> bool {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        use nix::fcntl::RenameFlags;

        let (Some(parent), Some(a_name), Some(b_name)) = (a.parent(), a.file_name(), b.file_name())
        else {
            return false;
        };
        if a.parent() != b.parent() {
            return false;
        }
        // A directory fd avoids `AT_FDCWD` and keeps the call safe: no
        // `unsafe` is needed anywhere in this crate.
        let Ok(dir) = fs::File::open(parent) else {
            return false;
        };
        nix::fcntl::renameat2(&dir, a_name, &dir, b_name, RenameFlags::RENAME_EXCHANGE).is_ok()
    }
    #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
    {
        // Atomic exchange is a Linux extension. Elsewhere the caller falls
        // back to the two-rename swap, whose failure paths restore the
        // previous store. `Path::exists` is not `const`, which keeps this
        // function out of the `const fn` candidate set.
        let _ = a.exists() && b.exists();
        false
    }
}

/// Re-execute `credstore-install` under `sudo` when the store is not directly
/// writable, preserving exactly `LT_SECRET_KEYS` plus the listed credential
/// values — and nothing else (never `sudo -E`, whose whole-environment
/// preservation is broader than necessary). Writable stores (tests,
/// already-root runs) pass through untouched, so this is a no-op unless
/// elevation is actually needed. Playbooks call it WITHOUT sudo:
/// `shellflow cred-env credstore-install <svc>` (no `sudo -E`, no `sudo`).
/// A marker variable prevents re-exec loops if `sudo` fails to elevate.
fn ensure_elevation(service: &str, store_dir: Option<&Path>, keys: &[String]) -> Result<()> {
    if nix::unistd::Uid::effective().is_root() {
        return Ok(());
    }
    if env::var_os("SHELLFLOW_CREDSTORE_ELEVATED").is_some() {
        bail!("cred-env credstore-install: elevation failed (still unprivileged)");
    }
    let store = store_dir.map_or_else(
        || PathBuf::from(format!("{DEFAULT_STORE_ROOT}/{service}")),
        Path::to_path_buf,
    );
    // Probe writability (not mere existence: `create_dir_all` succeeds on
    // an existing root-owned directory even when we cannot write into it).
    //
    // Creating the store during the probe is safe here: the deploy user
    // already holds `sudo` over `credstore-install`, so they can already
    // write any credential into the store — a user-owned directory grants no
    // additional capability. The default layout
    // (`/etc/credstore.encrypted/<svc>`) has a root-owned parent, so
    // `create_dir_all` fails with `PermissionDenied` and the store is
    // created by `sudo install -d` instead.
    let probe = store.join(format!(".writetest-{}", std::process::id()));
    match fs::create_dir_all(&store).and_then(|()| fs::write(&probe, b"")) {
        Ok(()) => {
            let _ = fs::remove_file(&probe);
            return Ok(());
        }
        Err(err) if err.kind() != std::io::ErrorKind::PermissionDenied => {
            return Err(err)
                .wrap_err_with(|| format!("cred-env: cannot access store `{}`", store.display()));
        }
        Err(_) => {}
    }
    let mut preserve = String::from(SECRET_KEYS_VAR);
    for key in keys {
        preserve.push(',');
        preserve.push_str(key);
    }
    let exe = env::current_exe().wrap_err("cred-env: cannot locate own binary")?;
    let mut cmd = Command::new("sudo");
    cmd.arg(format!("--preserve-env={preserve}"));
    cmd.arg(exe).arg("cred-env").arg("credstore-install").arg(service);
    if let Some(dir) = store_dir {
        cmd.arg("--store-dir").arg(dir);
    }
    cmd.env("SHELLFLOW_CREDSTORE_ELEVATED", "1");
    // Values travel in the preserved environment (never argv); stdio
    // inherits so `sudo` password prompts (if any) still work.
    let status =
        cmd.status().wrap_err("cred-env credstore-install: cannot run `sudo` for elevation")?;
    if !status.success() {
        bail!("cred-env credstore-install: elevated install failed (status {status})");
    }
    std::process::exit(0);
}

/// Seal every key in `keys` into `store`, one `systemd-creds encrypt` per key.
///
/// Values travel on stdin — never argv, never a temporary file.
fn seal_all(keys: &[String], store: &Path) -> Result<()> {
    for key in keys {
        if !is_valid_var_name(key) {
            bail!("cred-env credstore-install: invalid credential key `{key}`");
        }
        // `env::var` (not `var_os`): `@secrets` values are UTF-8 by
        // construction, and a missing key must fail loudly here.
        let value = env::var(key).map_err(|_| {
            eyre!("cred-env credstore-install: credential `{key}` is not set in the environment")
        })?;
        if value.is_empty() {
            bail!("cred-env credstore-install: credential `{key}` is empty");
        }
        let store_arg = store.to_string_lossy().into_owned();
        let path = format!("{store_arg}/{key}");
        let mut child = Command::new("sudo")
            .args(["systemd-creds", "encrypt", "--with-key=host", "--name", key, "-", &path])
            .stdin(Stdio::piped())
            .spawn()
            .wrap_err("cred-env credstore-install: cannot run `sudo systemd-creds encrypt`")?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(value.as_bytes())
                .wrap_err("cred-env: cannot write to systemd-creds stdin")?;
        }
        let status = child.wait().wrap_err("cred-env: systemd-creds did not finish")?;
        if !status.success() {
            bail!("cred-env credstore-install: systemd-creds failed for `{key}` (status {status})");
        }
        sudo(&["chmod", "0600", &path])?;
        println!("==> credential written: {key}");
    }
    Ok(())
}

/// Run a command under `sudo` (the deploy user has NOPASSWD sudo).
fn sudo(args: &[&str]) -> Result<()> {
    let status = Command::new("sudo")
        .args(args)
        .status()
        .wrap_err_with(|| format!("cred-env: cannot run `sudo {}`", args.first().unwrap_or(&"")))?;
    if !status.success() {
        bail!("cred-env: `sudo {}` failed (status {status})", args.first().unwrap_or(&""));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{is_valid_service_name, is_valid_var_name};

    #[test]
    fn var_name_validation_matches_the_env_parser() {
        assert!(is_valid_var_name("A"));
        assert!(is_valid_var_name("_private"));
        assert!(is_valid_var_name("Z9_Key"));
        assert!(!is_valid_var_name(""));
        assert!(!is_valid_var_name("1BAD"));
        assert!(!is_valid_var_name("BAD-NAME"));
        assert!(!is_valid_var_name("BAD NAME"));
        assert!(!is_valid_var_name("BAD.NAME"));
    }

    #[test]
    fn service_name_validation_rejects_unsafe_names() {
        assert!(is_valid_service_name("myapp"));
        assert!(is_valid_service_name("a"));
        assert!(is_valid_service_name("secret-app"));
        assert!(is_valid_service_name("zenoh2"));
        assert!(!is_valid_service_name(""));
        assert!(!is_valid_service_name("."));
        assert!(!is_valid_service_name(".."));
        assert!(!is_valid_service_name("../evil"));
        assert!(!is_valid_service_name("a/b"));
        assert!(!is_valid_service_name("-lead"));
        assert!(!is_valid_service_name("UPPER"));
        assert!(!is_valid_service_name("a b"));
        assert!(!is_valid_service_name("a--b"));
    }
}
