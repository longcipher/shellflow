//! Resolution of `@secrets` encrypted env files into run-state environment
//! variables and mask values.
//!
//! Decryption happens once, before the first step runs. The decrypted values
//! are injected into the run-state env (the same layer as `@export`, so an
//! explicit `@env KEY=value` still wins on conflicts) and every value is
//! registered for masking in previews, traces, and `--log-file`.

use std::{fs, path::Path};

use eyre::{Context as _, Result, eyre};
use shellflow_core::SecretEntry;
use shellflow_secrets::{
    crypto::decrypt_bytes,
    env::parse_env_file,
    identity::{effective_identity_path, load_x25519_identity},
};

/// The space-separated list of keys exported after resolving `@secrets`.
pub(crate) const SECRET_KEYS_VAR: &str = "LT_SECRET_KEYS";

/// Resolved secrets: ordered `(key, value)` pairs plus the values to mask.
pub(crate) type ResolvedSecrets = (Vec<(String, String)>, Vec<String>);

/// Resolve every `@secrets` entry into ordered `(key, value)` pairs and a
/// list of values to mask.
///
/// # Errors
///
/// Returns an error when the identity is missing or invalid, a file cannot be
/// read/decrypted, or an env file is malformed.
pub(crate) fn resolve_secrets(
    entries: &[SecretEntry],
    identity: Option<&Path>,
    mask_min_len: usize,
) -> Result<ResolvedSecrets> {
    let id_path = effective_identity_path(identity);
    let identity = load_x25519_identity(&id_path)
        .map_err(|err| eyre!("{err} (identity: {})", id_path.display()))?;

    let mut env: Vec<(String, String)> = Vec::new();
    let mut masks: Vec<String> = Vec::new();
    let mut keys: Vec<String> = Vec::new();

    for entry in entries {
        let cipher = fs::read(&entry.file)
            .wrap_err_with(|| format!("failed to read secrets file `{}`", entry.file))?;
        let plain = decrypt_bytes(&cipher, &identity)
            .wrap_err_with(|| format!("failed to decrypt `{}`", entry.file))?;
        let plain = String::from_utf8(plain)
            .wrap_err_with(|| format!("secrets file `{}` is not valid UTF-8", entry.file))?;
        let pairs = parse_env_file(&plain)
            .wrap_err_with(|| format!("malformed env file `{}`", entry.file))?;
        for (key, value) in pairs {
            if value.len() >= mask_min_len {
                masks.push(value.clone());
            }
            keys.push(key.clone());
            env.push((key, value));
        }
    }

    env.push((SECRET_KEYS_VAR.to_string(), keys.join(" ")));
    Ok((env, masks))
}
