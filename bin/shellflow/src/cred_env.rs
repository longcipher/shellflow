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
    os::unix::{
        ffi::OsStrExt as _,
        fs::{OpenOptionsExt as _, PermissionsExt as _},
        process::CommandExt as _,
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use eyre::{Context, Result, bail, eyre};

use crate::cli::CredEnvCmd;

/// `systemd` sets this for units that declare credentials.
const CREDENTIALS_DIRECTORY: &str = "CREDENTIALS_DIRECTORY";
/// `shellflow @secrets` exports this space-separated key list into blocks.
const SECRET_KEYS_VAR: &str = "LT_SECRET_KEYS";
/// Default root of the per-service host-key-bound credential store.
const DEFAULT_STORE_ROOT: &str = "/etc/credstore.encrypted";
/// Permission bits for rendered config files and the credential store.
const SECRET_FILE_MODE: u32 = 0o600;

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

/// Write `bytes` to `path` with mode 0600 via a same-directory temp file and
/// an atomic rename, so a reader never observes a partial render and the
/// plaintext never exists under any other name.
///
/// The temp name carries pid + time-nanos + attempt counter and is created
/// with `create_new` (no symlink following, no pre-plant race).
fn write_secret_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent =
        path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    let base = path.file_name().map_or_else(|| "out".into(), |n| n.to_string_lossy().into_owned());
    let pid = std::process::id();
    // Try a few unpredictable names; `create_new` fails when the name (or a
    // planted symlink at that name) already exists.
    let mut last_err: Option<eyre::Report> = None;
    for attempt in 0..10u128 {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(attempt, |d| d.as_nanos() ^ attempt);
        let temp = parent.join(format!(".{base}.tmp.{pid}.{nonce}"));
        let result = (|| -> Result<()> {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(SECRET_FILE_MODE)
                .open(&temp)
                .wrap_err_with(|| format!("cred-env: cannot create `{}`", temp.display()))?;
            file.write_all(bytes).wrap_err("cred-env: cannot write render output")?;
            file.flush().wrap_err("cred-env: cannot flush render output")?;
            drop(file);
            fs::set_permissions(&temp, fs::Permissions::from_mode(SECRET_FILE_MODE)).ok();
            fs::rename(&temp, path).wrap_err_with(|| {
                format!("cred-env: cannot move render into `{}`", path.display())
            })?;
            Ok(())
        })();
        match result {
            Ok(()) => return Ok(()),
            Err(err) => {
                let _ = fs::remove_file(&temp);
                // Retry only on collision; other I/O errors fail immediately.
                let msg = format!("{err:#}");
                if msg.contains("already exists") || msg.contains("File exists") {
                    last_err = Some(err);
                    continue;
                }
                return Err(err);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| eyre!("cred-env: cannot create temp file")))
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
    let store = store_dir.map_or_else(
        || PathBuf::from(format!("{DEFAULT_STORE_ROOT}/{service}")),
        Path::to_path_buf,
    );
    let store = store.to_string_lossy().into_owned();

    let Some(raw_keys) = env::var_os(SECRET_KEYS_VAR) else {
        bail!(
            "cred-env credstore-install: ${SECRET_KEYS_VAR} is not set — run inside a \
             shellflow `@secrets` block (a set-but-empty list clears the store)"
        );
    };
    let keys: Vec<String> =
        raw_keys.to_string_lossy().split_whitespace().map(ToOwned::to_owned).collect();

    sudo(&["install", "-d", "-m", "0700", &store])?;
    sudo(&["find", &store, "-mindepth", "1", "-delete"])?;

    for key in &keys {
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
        let path = format!("{store}/{key}");
        let mut child = Command::new("sudo")
            .args(["systemd-creds", "encrypt", "--with-key=host", "--name", key, "-", &path])
            .stdin(Stdio::piped())
            .spawn()
            .wrap_err("cred-env credstore-install: cannot run `sudo systemd-creds encrypt`")?;
        if let Some(stdin) = child.stdin.take() {
            let mut stdin = stdin;
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
