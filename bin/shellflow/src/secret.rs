//! `shellflow secret` — encrypt, decrypt, and edit age-encrypted env files.

use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::Command,
    str::FromStr,
};

use eyre::{Result, WrapErr, bail, eyre};
use shellflow_secrets::{
    crypto::{decrypt_bytes, encrypt_bytes},
    env::parse_env_file,
    error::SecretsError,
    identity::{effective_identity_path, load_x25519_identity},
};

use crate::cli::{
    SecretCmd, SecretCredsArgs, SecretDecryptArgs, SecretEditArgs, SecretEncryptArgs,
    SecretKeysCheckArgs,
};

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

fn write_output(output: Option<&Path>, data: &[u8]) -> Result<(), SecretsError> {
    if let Some(path) = output {
        fs::write(path, data).map_err(|source| SecretsError::WriteIdentity {
            path: path.display().to_string(),
            source,
        })
    } else {
        // Write exact bytes: no trailing newline. Appending `\n` would corrupt
        // binary age ciphertext on `encrypt > out.age` and change `decrypt`
        // output bytes.
        let mut out = std::io::stdout().lock();
        out.write_all(data).map_err(|source| SecretsError::ReadInput { source })
    }
}

fn encrypt(args: &SecretEncryptArgs) -> Result<()> {
    let plain = read_input(args.file.as_deref())?;
    let recipients = collect_recipients(&args.recipients, args.recipients_dir.as_deref())?;
    let cipher = encrypt_bytes(&plain, &recipients).map_err(eyre::Report::msg)?;
    write_output(args.output.as_deref(), &cipher).map_err(eyre::Report::msg)?;
    Ok(())
}

fn decrypt(args: &SecretDecryptArgs) -> Result<()> {
    let cipher = read_input(args.file.as_deref())?;
    let id_path = effective_identity_path(args.identity.as_deref());
    let identity = load_x25519_identity(&id_path)
        .map_err(|err| eyre!("{err} (identity: {})", id_path.display()))?;
    let plain = decrypt_bytes(&cipher, &identity).map_err(eyre::Report::msg)?;
    write_output(args.output.as_deref(), &plain).map_err(eyre::Report::msg)?;
    Ok(())
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
    let cipher = read_input(Some(&args.file))?;
    let id_path = effective_identity_path(args.identity.as_deref());
    let identity = load_x25519_identity(&id_path)
        .map_err(|err| eyre!("{err} (identity: {})", id_path.display()))?;
    let plain = decrypt_bytes(&cipher, &identity).map_err(eyre::Report::msg)?;

    let temp = temp_plaintext_path();
    write_temp_plaintext(&temp, &plain).wrap_err("failed to write temporary plaintext")?;

    let result = (|| -> Result<()> {
        run_editor(&temp)?;
        let edited = fs::read(&temp).wrap_err("failed to read edited plaintext")?;
        // Validate before re-encrypting: a malformed edit must fail while the
        // editor just exited (pointing at the temp file), not at the next
        // deploy's `@secrets` parse step.
        validate_plaintext_env(&edited)?;
        let recipients = collect_recipients(&args.recipients, args.recipients_dir.as_deref())
            .map_err(eyre::Report::msg)?;
        if recipients.is_empty() {
            bail!(
                "no recipients given: re-encrypting without them would drop every operator \
                 (use `-r age1...` or `--recipients-dir`)"
            );
        }
        let cipher = encrypt_bytes(&edited, &recipients).map_err(eyre::Report::msg)?;
        fs::write(&args.file, &cipher).wrap_err("failed to write encrypted file")?;
        Ok(())
    })();

    let _ = fs::remove_file(&temp);
    result
}

fn creds(args: &SecretCredsArgs) -> Result<()> {
    let cipher = read_input(Some(&args.file))?;
    let id_path = effective_identity_path(args.identity.as_deref());
    let identity = load_x25519_identity(&id_path)
        .map_err(|err| eyre!("{err} (identity: {})", id_path.display()))?;
    let plain = decrypt_bytes(&cipher, &identity).map_err(eyre::Report::msg)?;
    let plain = String::from_utf8(plain).wrap_err("decrypted file is not valid UTF-8")?;
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
    let mut files: Vec<PathBuf> = fs::read_dir(&args.dir)
        .wrap_err_with(|| format!("failed to read service directory `{}`", args.dir.display()))?
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension().is_some_and(|ext| ext == "age") &&
                path.file_name().is_some_and(|n| n.to_string_lossy().ends_with(".env.age"))
        })
        .collect();
    files.sort();
    if files.is_empty() {
        bail!("no *.env.age files under `{}`", args.dir.display());
    }

    let id_path = effective_identity_path(args.identity.as_deref());
    let identity = load_x25519_identity(&id_path)
        .map_err(|err| eyre!("{err} (identity: {})", id_path.display()))?;

    let mut reference: Option<(String, Vec<String>)> = None;
    for file in &files {
        let host = file
            .file_name()
            .map(|n| n.to_string_lossy().trim_end_matches(".env.age").to_string())
            .unwrap_or_default();
        let cipher =
            fs::read(file).wrap_err_with(|| format!("failed to read `{}`", file.display()))?;
        let plain = decrypt_bytes(&cipher, &identity)
            .map_err(|err| eyre!("{err} (`{}`)", file.display()))?;
        let plain = String::from_utf8(plain)
            .wrap_err_with(|| format!("`{}` is not valid UTF-8", file.display()))?;
        let mut keys: Vec<String> = parse_env_file(&plain)
            .map_err(eyre::Report::msg)?
            .into_iter()
            .map(|(key, _)| key)
            .collect();
        keys.sort();
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

/// Write the plaintext edit buffer with owner-only permissions.
///
/// `fs::write` would create the file `0666 & ~umask` (typically world-readable
/// `0644`), but the buffer holds decrypted secrets, so it is created `0600`
/// with `create_new` (no symlink following, no pre-plant race).
///
/// # Errors
///
/// Returns an I/O error when the file cannot be created or written.
fn write_temp_plaintext(path: &Path, plain: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .wrap_err_with(|| format!("failed to create {}", path.display()))?;
    file.write_all(plain).wrap_err("failed to write temporary plaintext")?;
    Ok(())
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

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use super::{temp_plaintext_path, validate_plaintext_env, write_temp_plaintext};

    #[test]
    fn temp_plaintext_is_owner_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("edit.env");
        write_temp_plaintext(&path, b"KEY=value\n").expect("write temp plaintext");
        let mode = fs::metadata(&path).expect("metadata").permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "edit buffer must be 0600, got {mode:o}");
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
}
