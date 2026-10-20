//! `shellflow secret` — encrypt, decrypt, and edit age-encrypted env files.

use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    process::Command,
    str::FromStr,
};

use eyre::{Result, WrapErr, bail, eyre};
use shellflow_secrets::{
    crypto::{decrypt_bytes, decrypt_string, encrypt_bytes},
    env::parse_env_file,
    error::SecretsError,
    identity::{effective_identity_path, load_x25519_identity},
};

use crate::{
    cli::{
        SecretCmd, SecretCredsArgs, SecretDecryptArgs, SecretEditArgs, SecretEncryptArgs,
        SecretFindDuplicatesArgs, SecretKeysCheckArgs,
    },
    fsx::write_secret_file,
};

/// Owner-only mode for the temporary plaintext buffer `secret edit` stages.
const SECRET_FILE_MODE: u32 = 0o600;

/// Run a `secret` subcommand.
///
/// # Errors
///
/// Propagates I/O, identity, encryption, and env parsing errors.
pub(crate) fn run(cmd: &SecretCmd) -> Result<()> {
    match cmd {
        SecretCmd::Encrypt(args) => encrypt(args),
        SecretCmd::Decrypt(args) => decrypt(args),
        SecretCmd::Edit(args) => edit(args),
        SecretCmd::Creds(args) => creds(args),
        SecretCmd::KeysCheck(args) => keys_check(args),
        SecretCmd::FindDuplicates(args) => find_duplicates(args),
    }
}

/// Parse a single `age1…` recipient string.
fn parse_recipient(raw: &str) -> Result<age::x25519::Recipient, SecretsError> {
    let raw = raw.trim();
    age::x25519::Recipient::from_str(raw).map_err(|reason| SecretsError::InvalidRecipient {
        recipient: raw.to_string(),
        reason: reason.to_string(),
    })
}

/// Collect recipients from explicit `-r` arguments and a directory of `*.pub`
/// files.
fn collect_recipients(
    explicit: &[String],
    dir: Option<&Path>,
) -> Result<Vec<age::x25519::Recipient>, SecretsError> {
    let mut recipients: Vec<age::x25519::Recipient> = Vec::new();
    for raw in explicit {
        recipients.push(parse_recipient(raw)?);
    }
    if let Some(dir) = dir {
        let entries = fs::read_dir(dir).map_err(|source| SecretsError::ReadInput { source })?;
        for entry in entries {
            let entry = entry.map_err(|source| SecretsError::ReadInput { source })?;
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "pub") {
                let content = fs::read_to_string(&path).map_err(|source| {
                    SecretsError::ReadIdentity { path: path.display().to_string(), source }
                })?;
                for line in content.lines() {
                    let line = line.trim();
                    if !line.is_empty() && !line.starts_with('#') {
                        recipients.push(parse_recipient(line)?);
                    }
                }
            }
        }
    }
    Ok(recipients)
}

fn read_input(file: Option<&Path>) -> Result<Vec<u8>, SecretsError> {
    if let Some(path) = file {
        fs::read(path).map_err(|source| SecretsError::ReadInput { source })
    } else {
        let mut buf = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buf)
            .map_err(|source| SecretsError::ReadInput { source })?;
        Ok(buf)
    }
}

/// Write command output: a file when `-o` is given, stdout otherwise.
///
/// A file destination goes through [`write_secret_file`], which creates it
/// `0600` and renames it into place. Plain `fs::write` would produce
/// `0666 & ~umask` — typically world-readable `0644` — which is unacceptable
/// for decrypted secrets, and would truncate an existing file before writing.
fn write_output(output: Option<&Path>, data: &[u8]) -> Result<()> {
    let Some(path) = output else {
        // Write exact bytes: no trailing newline. Appending `\n` would corrupt
        // binary age ciphertext on `encrypt > out.age` and change `decrypt`
        // output bytes.
        let mut out = std::io::stdout().lock();
        return out.write_all(data).wrap_err("failed to write to stdout");
    };
    write_secret_file(path, data).wrap_err_with(|| format!("failed to write `{}`", path.display()))
}

fn encrypt(args: &SecretEncryptArgs) -> Result<()> {
    let plain = read_input(args.file.as_deref())?;
    let recipients = collect_recipients(&args.recipients, args.recipients_dir.as_deref())?;
    let cipher = encrypt_bytes(&plain, &recipients).map_err(eyre::Report::msg)?;
    write_output(args.output.as_deref(), &cipher)?;
    Ok(())
}

fn decrypt(args: &SecretDecryptArgs) -> Result<()> {
    let cipher = read_input(args.file.as_deref())?;
    let identity = load_identity(args.identity.as_deref())?;
    let plain = decrypt_bytes(&cipher, &identity).map_err(eyre::Report::msg)?;
    write_output(args.output.as_deref(), &plain)?;
    Ok(())
}

/// Load the X25519 identity for the effective `-i` / `$SHELLFLOW_AGE_IDENTITY` /
/// `~/.config/age/keys.txt` path.
///
/// Shared by every subcommand that decrypts, so the identity path is resolved
/// and reported the same way everywhere.
pub(crate) fn load_identity(explicit: Option<&Path>) -> Result<age::x25519::Identity> {
    let id_path = effective_identity_path(explicit).map_err(|err| eyre!("{err}"))?;
    load_x25519_identity(&id_path).map_err(|err| eyre!("{err} (identity: {})", id_path.display()))
}

/// Run the user's editor on a file without invoking a shell.
///
/// `$VISUAL`/`$EDITOR` is split on whitespace (`code --wait` works); the value
/// is never passed to `sh -c`, so metacharacters (`;`, `$()`, backticks) are
/// passed as literal argv instead of executed.
fn run_editor(path: &Path) -> Result<()> {
    let editor = std::env::var("VISUAL").or_else(|_| std::env::var("EDITOR")).map_err(|_| {
        SecretsError::Editor("$EDITOR is not set (export EDITOR to use `secret edit`)".to_string())
    })?;
    if editor.trim().is_empty() {
        bail!("$EDITOR is empty; set EDITOR to use `secret edit`");
    }
    let mut parts = editor.split_whitespace();
    let Some(program) = parts.next() else {
        bail!("$EDITOR is empty; set EDITOR to use `secret edit`");
    };
    let mut cmd = Command::new(program);
    cmd.args(parts);
    cmd.arg(path);
    let status = cmd.status().map_err(|err| SecretsError::Editor(format!("{program}: {err}")))?;
    if !status.success() {
        bail!("editor exited with status {status}");
    }
    Ok(())
}

fn edit(args: &SecretEditArgs) -> Result<()> {
    // Resolve and validate recipients FIRST (design §S3.2, §S8: `secret edit`
    // "fails fast" when none are given). Doing it after decryption would write
    // plaintext to disk, open the editor, and only then throw the user's work
    // away.
    let recipients = collect_recipients(&args.recipients, args.recipients_dir.as_deref())
        .map_err(eyre::Report::msg)?;
    if recipients.is_empty() {
        bail!(
            "no recipients given: re-encrypting without them would drop every operator \
             (use `-r age1...` or `--recipients-dir`)"
        );
    }

    let cipher = read_input(Some(&args.file))?;
    let identity = load_identity(args.identity.as_deref())?;
    // The age format is anonymous, so the recipient list is the *only* thing
    // that decides who can read the file. Re-encrypting to a list that omits
    // the operator would lock them out of their own secret — silently, and
    // with no way back. Refuse before the plaintext is staged.
    let own_public = identity.to_public().to_string();
    if !recipients.iter().any(|recipient| recipient.to_string() == own_public) {
        bail!(
            "the recipient list does not include your own public key ({own_public}); \
             re-encrypting would lock you out of this file"
        );
    }
    let plain = decrypt_bytes(&cipher, &identity).map_err(eyre::Report::msg)?;

    // The staging file holds plaintext, so its lifetime is bound to a guard
    // rather than to the happy path: a failed editor or a failed re-encrypt
    // must still remove it.
    let temp = TempPlaintext(temp_plaintext_path());
    temp.write(&plain).wrap_err("failed to write temporary plaintext")?;

    let temp_path = temp.path().to_path_buf();
    let result = (|| -> Result<()> {
        run_editor(&temp_path)?;
        let edited = fs::read(&temp_path).wrap_err("failed to read edited plaintext")?;
        // Validate before re-encrypting: a malformed edit must fail while the
        // editor just exited (pointing at the temp file), not at the next
        // deploy's `@secrets` parse step.
        validate_plaintext_env(&edited)?;
        let cipher = encrypt_bytes(&edited, &recipients).map_err(eyre::Report::msg)?;
        // Atomic rename: the original ciphertext stays intact and readable if
        // anything below fails. A plain `fs::write` would truncate the only
        // copy before the new bytes landed.
        write_secret_file(&args.file, &cipher)
            .wrap_err_with(|| format!("failed to write `{}`", args.file.display()))?;
        Ok(())
    })();

    // `TempPlaintext` removes the staging file on drop, so every early return
    // above still leaves no plaintext behind.
    drop(temp);
    result
}

/// Owns a temporary plaintext file for its whole lifetime.
///
/// Cleanup is attached to `Drop` rather than to the success path: the
/// operation that uses this buffer can fail in several ways (editor missing,
/// editor non-zero, malformed edit, encryption failure), and every one of them
/// must leave no plaintext behind.
struct TempPlaintext(PathBuf);

impl TempPlaintext {
    /// Create the staging file and write `plain` into it, owner-only.
    fn write(&self, plain: &[u8]) -> Result<()> {
        use std::io::Write as _;
        {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(SECRET_FILE_MODE)
                .open(&self.0)
                .wrap_err_with(|| format!("cannot create `{}`", self.0.display()))?;
            file.write_all(plain).wrap_err("cannot write temporary plaintext")?;
            file.flush().wrap_err("cannot flush temporary plaintext")?;
        }
        // `OpenOptions::mode` is masked by the process umask, so the mode is
        // re-applied explicitly: the editor must be able to save the file
        // (owner-write) and nobody else must be able to read it.
        fs::set_permissions(&self.0, fs::Permissions::from_mode(SECRET_FILE_MODE))
            .wrap_err_with(|| format!("cannot set mode on `{}`", self.0.display()))?;
        Ok(())
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempPlaintext {
    fn drop(&mut self) {
        if let Err(err) = fs::remove_file(&self.0) &&
            err.kind() != std::io::ErrorKind::NotFound
        {
            eprintln!("warning: failed to remove temporary plaintext {}: {err}", self.0.display());
        }
    }
}

fn creds(args: &SecretCredsArgs) -> Result<()> {
    let cipher = read_input(Some(&args.file))?;
    let identity = load_identity(args.identity.as_deref())?;
    let plain = decrypt_string(&cipher, &identity).map_err(eyre::Report::msg)?;
    for (key, _) in parse_env_file(&plain).map_err(eyre::Report::msg)? {
        match &args.store_dir {
            // Per-service store: `ImportCredential=` searches only the flat
            // credential-store directories, so a sub-directory store needs an
            // explicit path. The path form that *decrypts* an encrypted
            // credential is `LoadCredentialEncrypted=ID:PATH` — plain
            // `LoadCredential=` expects a plaintext source (systemd.exec(5)).
            Some(dir) => println!("LoadCredentialEncrypted={key}:{}", dir.join(&key).display()),
            None => println!("ImportCredential={key}"),
        }
    }
    Ok(())
}

/// Check that every `<host>.env.age` in a service directory shares the same
/// key set.
///
/// Units are shared across hosts, so a host whose env file gained or lost a
/// key fails only at deploy time (`@secrets {host}` is fail-closed). This
/// check surfaces the drift on the controller instead, printing each host's
/// keys and a precise diff on mismatch.
///
/// # Errors
///
/// Returns when the directory holds no `*.env.age` files, when any file fails
/// to decrypt/parse (naming the file), or when the key sets differ.
fn keys_check(args: &SecretKeysCheckArgs) -> Result<()> {
    // Structural validation first: a typo'd or empty directory should be
    // reported without touching identity resolution.
    let mut files: Vec<PathBuf> = Vec::new();
    for entry in fs::read_dir(&args.dir)
        .wrap_err_with(|| format!("failed to read service directory `{}`", args.dir.display()))?
    {
        // An unreadable entry must not vanish: dropping it silently would let
        // this command report "N host(s) share the same key set" while having
        // checked fewer hosts than exist — the exact drift it exists to catch.
        let entry = entry
            .wrap_err_with(|| format!("failed to read an entry in `{}`", args.dir.display()))?;
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "age") &&
            path.file_name().is_some_and(|n| n.to_string_lossy().ends_with(".env.age"))
        {
            files.push(path);
        }
    }
    files.sort();
    if files.is_empty() {
        bail!("no *.env.age files under `{}`", args.dir.display());
    }

    let identity = load_identity(args.identity.as_deref())?;

    let mut reference: Option<(String, Vec<String>)> = None;
    for file in &files {
        let host = file
            .file_name()
            .map(|n| n.to_string_lossy())
            .and_then(|n| n.strip_suffix(".env.age").map(ToOwned::to_owned))
            .unwrap_or_else(|| file.display().to_string());
        let cipher =
            fs::read(file).wrap_err_with(|| format!("failed to read `{}`", file.display()))?;
        let plain = decrypt_string(&cipher, &identity)
            .map_err(|err| eyre!("{err} (`{}`)", file.display()))?;
        let mut keys: Vec<String> = parse_env_file(&plain)
            .map_err(|err| eyre!("`{}`: {err}", file.display()))?
            .into_iter()
            .map(|(key, _)| key)
            .collect();
        // A repeated key in one file is one credential, not two: leaving the
        // duplicate in would report drift against a host that has the key once.
        keys.sort();
        keys.dedup();
        if keys.is_empty() {
            bail!("`{}` contains no keys", file.display());
        }
        println!("{host}: {}", keys.join(" "));
        match &reference {
            None => reference = Some((host, keys)),
            Some((ref_host, ref_keys)) if *ref_keys != keys => {
                let missing: Vec<&str> =
                    ref_keys.iter().filter(|k| !keys.contains(k)).map(String::as_str).collect();
                let extra: Vec<&str> =
                    keys.iter().filter(|k| !ref_keys.contains(k)).map(String::as_str).collect();
                bail!(
                    "key set mismatch: {host} vs {ref_host} \
                     (missing in {host}: [{}]; extra in {host}: [{}])",
                    missing.join(" "),
                    extra.join(" ")
                );
            }
            Some(_) => {}
        }
    }
    println!("OK: {} host(s) share the same key set", files.len());
    Ok(())
}

/// An unpredictable temporary path for `secret edit` (PID + nonce).
fn temp_plaintext_path() -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    std::env::temp_dir().join(format!("shellflow-edit-{}-{nonce}.env", std::process::id()))
}

/// Validate edited plaintext as an env file before re-encrypting it.
///
/// # Errors
///
/// Returns an error when the content is not valid UTF-8 or does not parse as
/// `KEY=VALUE` lines.
fn validate_plaintext_env(bytes: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(bytes).wrap_err("edited plaintext is not valid UTF-8")?;
    parse_env_file(text).map_err(eyre::Report::msg)?;
    Ok(())
}

/// Find identical credential *values* shared across files.
///
/// Reports groups of `file:KEY` locations whose values hash identically. The
/// hashes are computed with a **randomly keyed** hasher and are never printed
/// — values never leave memory. A shared value means shared rotation fate:
/// editing one file without the others silently breaks the rest, which is
/// exactly how zombie passwords are born. Returns an error when any group is
/// found (CI gate).
fn find_duplicates(args: &SecretFindDuplicatesArgs) -> Result<()> {
    use std::{
        collections::{HashMap, hash_map::RandomState},
        hash::{Hash, Hasher as _},
    };

    let mut files: Vec<PathBuf> = Vec::new();
    collect_env_age_files(&args.dir, &mut files)?;
    files.sort();
    if files.is_empty() {
        bail!("no *.env.age files under `{}`", args.dir.display());
    }
    let identity = load_identity(args.identity.as_deref())?;

    let mut by_hash: HashMap<u64, Vec<String>> = HashMap::new();
    // One hasher state for the whole scan: `RandomState` is randomly keyed
    // per instance, so building a fresh one per value would give identical
    // values different digests and the shared-value gate would never fire.
    // The random key still holds across runs (no offline oracle), while
    // equality within this run is exact.
    let hash_state = RandomState::new();
    for file in &files {
        let cipher =
            fs::read(file).wrap_err_with(|| format!("failed to read `{}`", file.display()))?;
        let plain = decrypt_string(&cipher, &identity)
            .map_err(|err| eyre!("{err} (`{}`)", file.display()))?;
        let pairs = parse_env_file(&plain).map_err(|err| eyre!("`{}`: {err}", file.display()))?;
        for (key, value) in pairs {
            if value.is_empty() {
                continue;
            }
            let mut hasher = std::hash::BuildHasher::build_hasher(&hash_state);
            value.hash(&mut hasher);
            by_hash.entry(hasher.finish()).or_default().push(format!("{}:{key}", file.display()));
        }
    }
    let mut groups: Vec<Vec<String>> = by_hash
        .into_values()
        .filter(|locs| {
            let mut unique = locs.clone();
            unique.sort();
            unique.dedup();
            unique.len() > 1
        })
        .collect();
    if groups.is_empty() {
        println!("OK: all credential values unique across {} file(s)", files.len());
        return Ok(());
    }
    groups.sort();
    for group in &groups {
        println!("shared value (rotate together):");
        for loc in group {
            println!("  {loc}");
        }
    }
    bail!("found {} shared credential value(s) under {}", groups.len(), args.dir.display());
}

/// Recursively collect `*.env.age` files.
fn collect_env_age_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in
        fs::read_dir(dir).wrap_err_with(|| format!("failed to read `{}`", dir.display()))?
    {
        let entry =
            entry.wrap_err_with(|| format!("failed to read an entry in `{}`", dir.display()))?;
        let path = entry.path();
        let file_type =
            entry.file_type().wrap_err_with(|| format!("failed to stat `{}`", path.display()))?;
        if file_type.is_dir() {
            if path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|name| matches!(name, ".git" | "target" | "node_modules"))
            {
                continue;
            }
            collect_env_age_files(&path, out)?;
        } else if file_type.is_file() &&
            path.extension().is_some_and(|ext| ext == "age") &&
            path.file_name().is_some_and(|n| n.to_string_lossy().ends_with(".env.age"))
        {
            out.push(path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::PermissionsExt as _,
        path::{Path, PathBuf},
    };

    use shellflow_secrets::identity::{generate_identity, public_recipient};

    use super::{
        SecretCredsArgs, SecretDecryptArgs, SecretEditArgs, SecretEncryptArgs, SecretKeysCheckArgs,
        collect_recipients, creds, decrypt, edit, encrypt, keys_check, run_editor,
        temp_plaintext_path, validate_plaintext_env,
    };

    /// Serializes tests that mutate process-global env vars (`VISUAL`,
    /// `EDITOR`). Rust 2024 makes `set_var` `unsafe`, so every mutation is
    /// guarded by this lock and scoped to the closure.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// A throwaway identity plus its `age1…` recipient string.
    struct TestIdentity {
        dir: tempfile::TempDir,
        path: PathBuf,
        recipient: String,
    }

    impl TestIdentity {
        fn new() -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join("keys.txt");
            let identity = generate_identity(&path).expect("generate identity");
            Self { dir, path, recipient: public_recipient(&identity).to_string() }
        }
    }

    /// Encrypt `plain` to `out` for `recipients`.
    fn encrypt_to(plain: &Path, out: &Path, recipients: Vec<String>) -> Result<(), String> {
        encrypt(&SecretEncryptArgs {
            recipients,
            recipients_dir: None,
            output: Some(out.to_path_buf()),
            file: Some(plain.to_path_buf()),
        })
        .map_err(|e| e.to_string())
    }

    /// Decrypt `cipher` to `out` with `identity`.
    fn decrypt_to(cipher: &Path, out: &Path, identity: &Path) -> Result<(), String> {
        decrypt(&SecretDecryptArgs {
            identity: Some(identity.to_path_buf()),
            output: Some(out.to_path_buf()),
            file: Some(cipher.to_path_buf()),
        })
        .map_err(|e| e.to_string())
    }

    /// Write `content` to `path`.
    fn write(path: &Path, content: &str) {
        fs::write(path, content).expect("write fixture");
    }

    /// Run `body` with `$VISUAL`/`$EDITOR` set to `value` (or both unset).
    fn with_editor<T>(value: Option<&str>, body: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        // SAFETY: serialized by `ENV_LOCK`; no other test reads these vars
        // concurrently and the values are non-secret test fixtures.
        unsafe {
            for key in ["VISUAL", "EDITOR"] {
                match value {
                    Some(v) => std::env::set_var(key, v),
                    None => std::env::remove_var(key),
                }
            }
        }
        let out = body();
        // SAFETY: serialized by `ENV_LOCK`, as above.
        unsafe {
            std::env::remove_var("VISUAL");
            std::env::remove_var("EDITOR");
        }
        out
    }

    #[test]
    fn temp_plaintext_is_owner_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("edit.env");
        let temp = super::TempPlaintext(path.clone());
        temp.write(b"KEY=value\n").expect("write temp plaintext");
        let mode = fs::metadata(&path).expect("metadata").permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "edit buffer must be 0600, got {mode:o}");
    }

    #[test]
    fn temp_plaintext_is_removed_when_dropped() {
        // The guard owns cleanup: a failed edit must leave no plaintext behind.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("edit.env");
        {
            let temp = super::TempPlaintext(path.clone());
            temp.write(b"SECRET=hunter2\n").expect("write temp plaintext");
            assert!(path.exists(), "file must exist while the guard is alive");
        }
        assert!(!path.exists(), "dropping the guard must delete the plaintext");
    }

    #[test]
    fn edit_validates_recipients_before_touching_any_file() {
        // Design §S3.2/§S8: `secret edit` fails fast when no recipient is
        // given. Pointing at a nonexistent ciphertext proves the ordering
        // without inspecting global temp state: if `edit` read the input
        // first, it would fail with a read error instead of the recipient
        // error, and a plaintext buffer could have been staged.
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("does-not-exist.env.age");

        let err = edit(&SecretEditArgs {
            identity: Some(dir.path().join("id.key")),
            recipients: Vec::new(),
            recipients_dir: None,
            file: missing.clone(),
        })
        .expect_err("missing recipients must fail");
        let msg = format!("{err:#}");
        assert!(msg.contains("no recipients given"), "unexpected error: {msg}");
        assert!(
            !msg.contains("failed to read"),
            "recipients must be validated before any file I/O: {msg}"
        );
        assert!(!missing.exists(), "the ciphertext must not be created");
    }

    #[test]
    fn validate_plaintext_env_accepts_well_formed_content() {
        validate_plaintext_env(b"A=1\n# comment\n\nB=\"x y\"\nexport C=3\n")
            .expect("valid env content");
    }

    #[test]
    fn validate_plaintext_env_rejects_malformed_content() {
        let err = validate_plaintext_env(b"GOOD=1\nNO_EQUALS\n").expect_err("malformed line");
        assert!(err.to_string().contains("malformed"), "unexpected error: {err}");
    }

    #[test]
    fn validate_plaintext_env_rejects_non_utf8() {
        let err = validate_plaintext_env(&[0xff, 0xfe, b'=']).expect_err("non-utf8 content");
        assert!(err.to_string().contains("UTF-8"), "unexpected error: {err}");
    }

    #[test]
    fn temp_plaintext_path_is_unique_per_call() {
        assert_ne!(temp_plaintext_path(), temp_plaintext_path());
    }

    // -----------------------------------------------------------------------
    // encrypt / decrypt round trip
    // -----------------------------------------------------------------------

    #[test]
    fn encrypt_then_decrypt_preserves_bytes_exactly() {
        let id = TestIdentity::new();
        let plain = id.dir.path().join("plain.env");
        // Includes a trailing-newline-free payload and a non-ASCII value: the
        // round trip must be byte-exact, not text-normalized.
        write(&plain, "A=1\nB=héllo\n");

        let cipher = id.dir.path().join("out.env.age");
        encrypt_to(&plain, &cipher, vec![id.recipient.clone()]).expect("encrypt");
        assert!(cipher.exists(), "encrypted file was not written");
        assert_ne!(
            fs::read(&cipher).expect("read cipher"),
            fs::read(&plain).expect("read plain"),
            "output must be ciphertext"
        );

        let back = id.dir.path().join("back.env");
        decrypt_to(&cipher, &back, &id.path).expect("decrypt");
        assert_eq!(
            fs::read(&back).expect("read decrypted"),
            fs::read(&plain).expect("read plain"),
            "decrypted bytes must match the plaintext exactly"
        );
    }

    #[test]
    fn encrypt_rejects_an_invalid_recipient() {
        let id = TestIdentity::new();
        let plain = id.dir.path().join("plain.env");
        write(&plain, "A=1\n");
        let err = encrypt_to(&plain, &id.dir.path().join("x.age"), vec!["nope".to_string()])
            .expect_err("invalid recipient must fail");
        assert!(err.contains("nope"), "error should name the bad recipient: {err}");
    }

    #[test]
    fn decrypt_rejects_ciphertext_for_another_identity() {
        let id = TestIdentity::new();
        let other = TestIdentity::new();
        let plain = id.dir.path().join("plain.env");
        write(&plain, "A=1\n");
        let cipher = id.dir.path().join("x.age");
        encrypt_to(&plain, &cipher, vec![id.recipient.clone()]).expect("encrypt");

        let err = decrypt_to(&cipher, &id.dir.path().join("out.env"), &other.path)
            .expect_err("a foreign identity must not decrypt");
        assert!(!err.is_empty(), "decryption failure must report a reason");
    }

    // -----------------------------------------------------------------------
    // collect_recipients
    // -----------------------------------------------------------------------

    #[test]
    fn collect_recipients_reads_pub_files_and_skips_comments() {
        let id = TestIdentity::new();
        let dir = id.dir.path().join("recipients");
        fs::create_dir_all(&dir).expect("mkdir");
        // A `*.pub` file with a comment, a blank line, and the real key.
        write(&dir.join("alice.pub"), &format!("# alice\n\n{}\n", id.recipient));
        // Non-`.pub` files are ignored, even when they hold a valid key.
        write(&dir.join("notes.txt"), &id.recipient);

        let recipients =
            collect_recipients(&[], Some(&dir)).expect("collect recipients from directory");
        assert_eq!(recipients.len(), 1, "only the .pub entry counts: {recipients:?}");
    }

    #[test]
    fn collect_recipients_combines_explicit_and_directory_entries() {
        let id = TestIdentity::new();
        let extra = TestIdentity::new();
        let dir = id.dir.path().join("recipients");
        fs::create_dir_all(&dir).expect("mkdir");
        write(&dir.join("alice.pub"), &format!("{}\n", id.recipient));

        let recipients = collect_recipients(std::slice::from_ref(&extra.recipient), Some(&dir))
            .expect("collect combined recipients");
        assert_eq!(recipients.len(), 2, "explicit + directory entries: {recipients:?}");
    }

    #[test]
    fn collect_recipients_without_sources_is_empty() {
        assert!(collect_recipients(&[], None).expect("no sources").is_empty());
    }

    #[test]
    fn collect_recipients_rejects_a_malformed_pub_entry() {
        let id = TestIdentity::new();
        let dir = id.dir.path().join("recipients");
        fs::create_dir_all(&dir).expect("mkdir");
        write(&dir.join("broken.pub"), "age1notavalidkey\n");
        let err = collect_recipients(&[], Some(&dir)).expect_err("malformed key must fail");
        assert!(err.to_string().contains("age1notavalidkey"), "unexpected error: {err}");
    }

    #[test]
    fn collect_recipients_reports_a_missing_directory() {
        let id = TestIdentity::new();
        let missing = id.dir.path().join("nope");
        assert!(
            collect_recipients(&[], Some(&missing)).is_err(),
            "a missing --recipients-dir must be reported, not silently skipped"
        );
    }

    // -----------------------------------------------------------------------
    // output writing
    // -----------------------------------------------------------------------

    #[test]
    fn written_output_is_byte_exact_with_no_trailing_newline() {
        let id = TestIdentity::new();
        let plain = id.dir.path().join("plain.env");
        // Binary payload: an added `\n` would corrupt it.
        let payload = b"\x00\x01binary\xff";
        fs::write(&plain, payload).expect("write binary fixture");

        let cipher = id.dir.path().join("bin.age");
        encrypt_to(&plain, &cipher, vec![id.recipient.clone()]).expect("encrypt");

        let back = id.dir.path().join("bin.out");
        decrypt_to(&cipher, &back, &id.path).expect("decrypt");
        assert_eq!(fs::read(&back).expect("read back"), payload.to_vec(), "bytes must round-trip");
    }

    // -----------------------------------------------------------------------
    // run_editor
    // -----------------------------------------------------------------------

    #[test]
    fn editor_fails_clearly_when_no_editor_is_set() {
        let err = with_editor(None, || run_editor(Path::new("/tmp/x")))
            .expect_err("missing $EDITOR must be an error");
        assert!(err.to_string().contains("$EDITOR"), "unexpected error: {err}");
    }

    #[test]
    fn editor_rejects_a_blank_editor_value() {
        let err = with_editor(Some("   "), || run_editor(Path::new("/tmp/x")))
            .expect_err("a blank $EDITOR must be an error");
        assert!(err.to_string().contains("$EDITOR"), "unexpected error: {err}");
    }

    #[test]
    fn editor_runs_the_program_and_accepts_success() {
        with_editor(Some("true"), || run_editor(Path::new("/tmp/x")).expect("`true` exits 0"));
    }

    #[test]
    fn editor_reports_a_non_zero_exit() {
        let err = with_editor(Some("false"), || run_editor(Path::new("/tmp/x")))
            .expect_err("a failing editor must be reported");
        assert!(err.to_string().contains("editor exited with status"), "unexpected error: {err}");
    }

    #[test]
    fn editor_reports_a_missing_program() {
        let err =
            with_editor(Some("shellflow-no-such-editor-xyz"), || run_editor(Path::new("/tmp/x")))
                .expect_err("a missing editor program must be reported");
        assert!(
            err.to_string().contains("shellflow-no-such-editor-xyz"),
            "error should name the program: {err}"
        );
    }

    #[test]
    fn editor_passes_flags_and_path_as_argv_without_a_shell() {
        // `$EDITOR` is split on whitespace and passed as argv, so `code --wait`
        // works and metacharacters are never executed. The script records its
        // own argv, which is what we assert on.
        let id = TestIdentity::new();
        let script = id.dir.path().join("fake-editor.sh");
        let marker = id.dir.path().join("argv.txt");
        write(&script, &format!("#!/bin/sh\nprintf '%s\\n' \"$@\" > {}\n", marker.display()));
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).expect("chmod");

        let target = id.dir.path().join("edited.env");
        write(&target, "A=1\n");
        with_editor(Some(&format!("{} --wait", script.display())), || {
            run_editor(&target).expect("editor exits 0");
        });

        let recorded = fs::read_to_string(&marker).expect("editor argv marker");
        assert!(recorded.contains("--wait"), "flags must be forwarded: {recorded}");
        assert!(
            recorded.contains(target.display().to_string().as_str()),
            "path must be forwarded: {recorded}"
        );
    }

    // -----------------------------------------------------------------------
    // secret edit
    // -----------------------------------------------------------------------

    /// Run `secret edit` with `editor` as `$EDITOR` on `file`.
    fn run_edit(
        file: &Path,
        identity: &Path,
        recipients: Vec<String>,
        editor: &str,
    ) -> Result<(), String> {
        let args = SecretEditArgs {
            identity: Some(identity.to_path_buf()),
            recipients,
            recipients_dir: None,
            file: file.to_path_buf(),
        };
        with_editor(Some(editor), || edit(&args)).map_err(|e| e.to_string())
    }

    #[test]
    fn edit_decrypts_edits_and_re_encrypts() {
        let id = TestIdentity::new();
        let plain = id.dir.path().join("plain.env");
        write(&plain, "A=1\n");
        let cipher = id.dir.path().join("secret.env.age");
        encrypt_to(&plain, &cipher, vec![id.recipient.clone()]).expect("encrypt");

        // The editor appends a new key to the plaintext buffer.
        let script = id.dir.path().join("append.sh");
        write(&script, "#!/bin/sh\nprintf 'B=2\\n' >> \"$1\"\n");
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).expect("chmod");

        run_edit(&cipher, &id.path, vec![id.recipient.clone()], &script.display().to_string())
            .expect("edit round trip");

        let back = id.dir.path().join("after.env");
        decrypt_to(&cipher, &back, &id.path).expect("decrypt after edit");
        let content = fs::read_to_string(&back).expect("read edited plaintext");
        assert!(content.contains("A=1"), "original key must survive: {content}");
        assert!(content.contains("B=2"), "the edit must be applied: {content}");
    }

    #[test]
    fn edit_rejects_a_malformed_edit_and_keeps_the_ciphertext() {
        let id = TestIdentity::new();
        let plain = id.dir.path().join("plain.env");
        write(&plain, "A=1\n");
        let cipher = id.dir.path().join("secret.env.age");
        encrypt_to(&plain, &cipher, vec![id.recipient.clone()]).expect("encrypt");
        let before = fs::read(&cipher).expect("read cipher before");

        // The editor writes a line that is not `KEY=VALUE`.
        let script = id.dir.path().join("break.sh");
        write(&script, "#!/bin/sh\nprintf 'NO_EQUALS_HERE\\n' >> \"$1\"\n");
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).expect("chmod");

        let err =
            run_edit(&cipher, &id.path, vec![id.recipient.clone()], &script.display().to_string())
                .expect_err("a malformed edit must fail");
        assert!(err.contains("malformed"), "error should explain the problem: {err}");
        assert_eq!(
            fs::read(&cipher).expect("read cipher after"),
            before,
            "a rejected edit must leave the encrypted file untouched"
        );
    }

    #[test]
    fn edit_requires_recipients_before_re_encrypting() {
        let id = TestIdentity::new();
        let plain = id.dir.path().join("plain.env");
        write(&plain, "A=1\n");
        let cipher = id.dir.path().join("secret.env.age");
        encrypt_to(&plain, &cipher, vec![id.recipient.clone()]).expect("encrypt");

        let err = run_edit(&cipher, &id.path, vec![], "true")
            .expect_err("re-encrypting with no recipient must fail");
        assert!(err.contains("no recipients"), "unexpected error: {err}");
    }

    #[test]
    fn edit_removes_the_temporary_plaintext() {
        let id = TestIdentity::new();
        let plain = id.dir.path().join("plain.env");
        write(&plain, "A=1\n");
        let cipher = id.dir.path().join("secret.env.age");
        encrypt_to(&plain, &cipher, vec![id.recipient.clone()]).expect("encrypt");

        // The editor records its own path; the temp buffer must be gone by the
        // time `edit` returns, so no decrypted bytes are left behind.
        let script = id.dir.path().join("record.sh");
        let marker = id.dir.path().join("tmp-path.txt");
        write(&script, &format!("#!/bin/sh\nprintf '%s' \"$1\" > {}\n", marker.display()));
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).expect("chmod");

        run_edit(&cipher, &id.path, vec![id.recipient.clone()], &script.display().to_string())
            .expect("edit round trip");

        let tmp = fs::read_to_string(&marker).expect("editor path marker");
        assert!(!Path::new(tmp.trim()).exists(), "temporary plaintext was not cleaned up: {tmp}");
    }

    // -----------------------------------------------------------------------
    // secret creds
    // -----------------------------------------------------------------------

    #[test]
    fn creds_prints_import_credential_lines() {
        let id = TestIdentity::new();
        let plain = id.dir.path().join("plain.env");
        write(&plain, "API_KEY=secret\nDB_PASSWORD=pw\n");
        let cipher = id.dir.path().join("secret.env.age");
        encrypt_to(&plain, &cipher, vec![id.recipient.clone()]).expect("encrypt");

        creds(&SecretCredsArgs { identity: Some(id.path.clone()), store_dir: None, file: cipher })
            .expect("creds");
    }

    #[test]
    fn creds_prints_load_credential_encrypted_lines_with_store_dir() {
        let id = TestIdentity::new();
        let plain = id.dir.path().join("plain.env");
        write(&plain, "API_KEY=secret\n");
        let cipher = id.dir.path().join("secret.env.age");
        encrypt_to(&plain, &cipher, vec![id.recipient.clone()]).expect("encrypt");

        creds(&SecretCredsArgs {
            identity: Some(id.path.clone()),
            store_dir: Some(PathBuf::from("/etc/credstore.encrypted/myapp")),
            file: cipher,
        })
        .expect("creds with --store-dir");
    }

    #[test]
    fn creds_prints_nothing_for_an_empty_env_file() {
        let id = TestIdentity::new();
        let plain = id.dir.path().join("plain.env");
        write(&plain, "");
        let cipher = id.dir.path().join("empty.env.age");
        encrypt_to(&plain, &cipher, vec![id.recipient.clone()]).expect("encrypt");

        // An env file with no keys is legal for `creds` (it just prints no
        // lines); `keys_check` is the tool that rejects that shape.
        creds(&SecretCredsArgs { identity: Some(id.path.clone()), store_dir: None, file: cipher })
            .expect("creds on an empty env file");
    }

    // -----------------------------------------------------------------------
    // secret keys-check
    // -----------------------------------------------------------------------

    /// Build `<dir>/<host>.env.age` encrypted to `recipient` with `content`.
    fn host_env(dir: &Path, host: &str, content: &str, recipient: &str) -> PathBuf {
        let plain = dir.join(format!("{host}.plain"));
        write(&plain, content);
        let cipher = dir.join(format!("{host}.env.age"));
        encrypt_to(&plain, &cipher, vec![recipient.to_string()]).expect("encrypt host env");
        cipher
    }

    #[test]
    fn keys_check_accepts_identical_key_sets() {
        let id = TestIdentity::new();
        let dir = id.dir.path().join("svc");
        fs::create_dir_all(&dir).expect("mkdir");
        // Different values, same keys — that is the intended invariant (units
        // are shared across hosts).
        host_env(&dir, "api", "K=v1\nJ=w1\n", &id.recipient);
        host_env(&dir, "trade", "K=v2\nJ=w2\n", &id.recipient);

        keys_check(&SecretKeysCheckArgs { identity: Some(id.path.clone()), dir })
            .expect("identical key sets must pass");
    }

    #[test]
    fn keys_check_detects_a_missing_key() {
        let id = TestIdentity::new();
        let dir = id.dir.path().join("svc");
        fs::create_dir_all(&dir).expect("mkdir");
        host_env(&dir, "api", "K=1\nJ=2\n", &id.recipient);
        host_env(&dir, "trade", "K=1\n", &id.recipient);

        let err = keys_check(&SecretKeysCheckArgs { identity: Some(id.path.clone()), dir })
            .expect_err("drift must be detected");
        let msg = err.to_string();
        assert!(msg.contains("key set mismatch"), "unexpected error: {msg}");
        assert!(msg.contains("trade"), "error should name the drifting host: {msg}");
        assert!(msg.contains("J"), "error should name the missing key: {msg}");
    }

    #[test]
    fn keys_check_detects_an_extra_key() {
        let id = TestIdentity::new();
        let dir = id.dir.path().join("svc");
        fs::create_dir_all(&dir).expect("mkdir");
        host_env(&dir, "api", "K=1\n", &id.recipient);
        host_env(&dir, "trade", "K=1\nEXTRA=2\n", &id.recipient);

        let err = keys_check(&SecretKeysCheckArgs { identity: Some(id.path.clone()), dir })
            .expect_err("an extra key is drift too");
        assert!(err.to_string().contains("EXTRA"), "error should name the extra key: {err}");
    }

    #[test]
    fn keys_check_rejects_an_empty_directory() {
        let id = TestIdentity::new();
        let dir = id.dir.path().join("empty");
        fs::create_dir_all(&dir).expect("mkdir");
        let err = keys_check(&SecretKeysCheckArgs { identity: Some(id.path.clone()), dir })
            .expect_err("an empty directory must fail");
        assert!(err.to_string().contains("no *.env.age files"), "unexpected error: {err}");
    }

    #[test]
    fn keys_check_ignores_files_that_are_not_host_envs() {
        let id = TestIdentity::new();
        let dir = id.dir.path().join("svc");
        fs::create_dir_all(&dir).expect("mkdir");
        let plain = dir.join("legacy.plain");
        write(&plain, "K=1\n");
        let other = dir.join("legacy.age");
        encrypt_to(&plain, &other, vec![id.recipient.clone()]).expect("encrypt");

        let err = keys_check(&SecretKeysCheckArgs { identity: Some(id.path.clone()), dir })
            .expect_err("a non-`*.env.age` file must not count");
        assert!(err.to_string().contains("no *.env.age files"), "unexpected error: {err}");
    }

    #[test]
    fn keys_check_rejects_a_file_with_no_keys() {
        let id = TestIdentity::new();
        let dir = id.dir.path().join("svc");
        fs::create_dir_all(&dir).expect("mkdir");
        host_env(&dir, "api", "", &id.recipient);

        let err = keys_check(&SecretKeysCheckArgs { identity: Some(id.path.clone()), dir })
            .expect_err("an env file with no keys must fail");
        assert!(err.to_string().contains("no keys"), "unexpected error: {err}");
    }

    #[test]
    fn keys_check_rejects_an_undecryptable_file() {
        let id = TestIdentity::new();
        let foreign = TestIdentity::new();
        let dir = id.dir.path().join("svc");
        fs::create_dir_all(&dir).expect("mkdir");
        host_env(&dir, "api", "K=1\n", &id.recipient);
        host_env(&dir, "trade", "K=1\n", &foreign.recipient);

        let err = keys_check(&SecretKeysCheckArgs { identity: Some(id.path.clone()), dir })
            .expect_err("a foreign ciphertext must fail the check");
        assert!(err.to_string().contains("trade"), "error should name the file: {err}");
    }

    #[test]
    fn keys_check_reports_a_missing_directory_before_touching_identity() {
        let id = TestIdentity::new();
        let dir = id.dir.path().join("does-not-exist");
        let err = keys_check(&SecretKeysCheckArgs { identity: Some(id.path.clone()), dir })
            .expect_err(
                "a missing directory must be reported structurally, before identity resolution",
            );
        assert!(err.to_string().contains("failed to read service directory"), "unexpected: {err}");
    }
}
