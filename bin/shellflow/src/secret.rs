//! `shellflow secret` — encrypt, decrypt, and edit age-encrypted env files.

use std::{
    fs,
    io::{Read, Write},
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
        for entry in entries.flatten() {
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
        let mut out = std::io::stdout().lock();
        out.write_all(data)
            .and_then(|()| out.write_all(b"\n"))
            .map_err(|source| SecretsError::ReadInput { source })
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

/// Run the user's editor on a file.
fn run_editor(path: &Path) -> Result<()> {
    let editor = std::env::var("VISUAL").or_else(|_| std::env::var("EDITOR")).map_err(|_| {
        SecretsError::Editor("$EDITOR is not set (export EDITOR to use `secret edit`)".to_string())
    })?;
    if editor.trim().is_empty() {
        bail!("$EDITOR is empty; set EDITOR to use `secret edit`");
    }
    let quoted = path.display().to_string().replace('\'', "'\\''");
    let status = Command::new("sh")
        .arg("-c")
        .arg(format!("{editor} '{quoted}'"))
        .status()
        .map_err(|err| SecretsError::Editor(format!("{editor}: {err}")))?;
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
    fs::write(&temp, &plain).wrap_err("failed to write temporary plaintext")?;

    let result = (|| -> Result<()> {
        run_editor(&temp)?;
        let edited = fs::read(&temp).wrap_err("failed to read edited plaintext")?;
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
        println!("ImportCredential={key}");
    }
    Ok(())
}

/// An unpredictable temporary path for `secret edit` (PID + nonce).
fn temp_plaintext_path() -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    std::env::temp_dir().join(format!("shellflow-edit-{}-{nonce}.env", std::process::id()))
}
