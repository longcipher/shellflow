//! Recipient parsing and collection for `age` encryption.
//!
//! This module owns the recipient surface of the crate (design §S7): parsing
//! `age1…` keys from argv, and collecting them from a directory of `*.pub`
//! files. The CLI consumes it instead of talking to the `age` crate directly,
//! so there is exactly one place that knows what a valid recipient is.

use std::{fs, path::Path, str::FromStr};

use crate::error::SecretsError;

/// Parse a single `age1…` recipient string.
///
/// # Errors
///
/// Returns [`SecretsError::InvalidRecipient`] when `raw` is not a valid
/// X25519 recipient key.
pub fn parse_recipient(raw: &str) -> Result<age::x25519::Recipient, SecretsError> {
    let raw = raw.trim();
    age::x25519::Recipient::from_str(raw).map_err(|reason| SecretsError::InvalidRecipient {
        recipient: raw.to_string(),
        reason: reason.to_string(),
    })
}

/// Collect recipients from explicit `-r` arguments and a directory of `*.pub`
/// files.
///
/// Every non-blank, non-comment line of a `*.pub` file is one recipient, so a
/// team key directory is a single flat list.
///
/// # Errors
///
/// Returns [`SecretsError::InvalidRecipient`] for a malformed key,
/// [`SecretsError::ReadInput`] when the directory cannot be listed, and
/// [`SecretsError::ReadIdentity`] when a `*.pub` file cannot be read.
pub fn collect_recipients(
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

#[cfg(test)]
mod tests {
    use super::{collect_recipients, parse_recipient};

    #[test]
    fn parses_a_valid_recipient_and_trims_whitespace() {
        let identity = age::x25519::Identity::generate();
        let raw = identity.to_public().to_string();
        let parsed = parse_recipient(&format!("  {raw}\n")).expect("valid recipient");
        assert_eq!(parsed.to_string(), raw);
    }

    #[test]
    fn rejects_a_malformed_recipient() {
        let err = parse_recipient("not-a-key").expect_err("must reject");
        assert!(err.to_string().contains("not-a-key"), "{err}");
    }

    #[test]
    fn collects_explicit_and_directory_recipients() {
        let dir = tempfile::tempdir().expect("tempdir");
        let a = age::x25519::Identity::generate().to_public().to_string();
        let b = age::x25519::Identity::generate().to_public().to_string();
        std::fs::write(dir.path().join("alice.pub"), format!("# team key\n{a}\n"))
            .expect("write pub");
        std::fs::write(dir.path().join("bob.pub"), format!("{b}\n")).expect("write pub");
        std::fs::write(dir.path().join("ignored.txt"), "nope\n").expect("write txt");

        let c = age::x25519::Identity::generate().to_public().to_string();
        let recipients =
            collect_recipients(std::slice::from_ref(&c), Some(dir.path())).expect("collect");
        let mut keys: Vec<String> = recipients.iter().map(|r| r.to_string()).collect();
        keys.sort();
        let mut expected = vec![a, b, c];
        expected.sort();
        assert_eq!(keys, expected, "one recipient per `*.pub` line plus explicit");
    }

    #[test]
    fn directory_recipients_must_parse() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("bad.pub"), "not-a-key\n").expect("write pub");
        assert!(collect_recipients(&[], Some(dir.path())).is_err());
    }

    #[test]
    fn recipient_string_forms_are_standard() {
        let identity = age::x25519::Identity::generate();
        let pubkey = identity.to_public().to_string();
        assert!(pubkey.starts_with("age1"), "got {pubkey}");
    }
}
