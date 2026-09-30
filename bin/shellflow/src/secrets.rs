//! Resolution of `@secrets` encrypted env files into run-state environment
//! variables and mask values.
//!
//! Decryption happens once, before the first step runs. The decrypted values
//! are injected into the run-state env (the same layer as `@export`, so an
//! explicit `@env KEY=value` still wins on conflicts) and every value is
//! registered for masking in previews, traces, and `--log-file`.

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

use age::x25519::Identity;
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
/// Identity precedence is *most specific wins*: the `--identity` attached to
/// the `@secrets` line, then the run-wide `--identity` flag, then
/// `$SHELLFLOW_AGE_IDENTITY`, then `~/.config/age/keys.txt`. Identities are
/// loaded lazily and cached, so a playbook whose every file carries its own
/// identity never touches the default path, and a repeated path is read once.
///
/// # Errors
///
/// Returns an error when the resolved identity for an entry is missing or
/// invalid, a file cannot be read/decrypted, or an env file is malformed.
pub(crate) fn resolve_secrets(
    entries: &[SecretEntry],
    identity: Option<&Path>,
    mask_min_len: usize,
) -> Result<ResolvedSecrets> {
    let mut cache: HashMap<PathBuf, Identity> = HashMap::new();
    let mut env: Vec<(String, String)> = Vec::new();
    let mut masks: Vec<String> = Vec::new();
    let mut keys: Vec<String> = Vec::new();

    for entry in entries {
        let id_path = entry
            .identity
            .as_deref()
            .map_or_else(|| effective_identity_path(identity), PathBuf::from);
        if !cache.contains_key(&id_path) {
            let loaded = load_x25519_identity(&id_path)
                .map_err(|err| eyre!("{err} (identity: {})", id_path.display()))?;
            cache.insert(id_path.clone(), loaded);
        }
        let identity = cache.get(&id_path).ok_or_else(|| {
            eyre!("failed to load identity {} (identity: {})", id_path.display(), id_path.display())
        })?;

        let cipher = fs::read(&entry.file)
            .wrap_err_with(|| format!("failed to read secrets file `{}`", entry.file))?;
        let plain = decrypt_bytes(&cipher, identity)
            .wrap_err_with(|| format!("failed to decrypt `{}`", entry.file))?;
        let plain = String::from_utf8(plain)
            .wrap_err_with(|| format!("secrets file `{}` is not valid UTF-8", entry.file))?;
        let pairs = parse_env_file(&plain)
            .wrap_err_with(|| format!("malformed env file `{}`", entry.file))?;
        for (key, value) in pairs {
            // De-duplicate masks so repeated values are not redundantly
            // replaced; `mask_line` also sorts longest-first to avoid prefix
            // leakage.
            if value.len() >= mask_min_len && !masks.contains(&value) {
                masks.push(value.clone());
            }
            // A key present in two files appears once in the exported list,
            // but keeps the last value (matching `source` semantics).
            if !keys.contains(&key) {
                keys.push(key.clone());
            }
            env.retain(|(existing, _)| existing != &key);
            env.push((key, value));
        }
    }

    env.push((SECRET_KEYS_VAR.to_string(), keys.join(" ")));
    Ok((env, masks))
}

#[cfg(test)]
mod tests {
    use age::x25519::Identity;
    use shellflow_core::SecretEntry;
    use shellflow_secrets::{
        crypto::encrypt_bytes,
        identity::{generate_identity, public_recipient},
    };

    use super::{SECRET_KEYS_VAR, resolve_secrets};

    type TestResult<T> = std::result::Result<T, String>;

    /// Generate an identity at `<dir>/<name>.key`.
    fn new_identity(dir: &std::path::Path, name: &str) -> TestResult<Identity> {
        generate_identity(&dir.join(format!("{name}.key"))).map_err(|err| err.to_string())
    }

    /// Write an age-encrypted env file for `identity` and return its path.
    fn write_secrets(
        dir: &std::path::Path,
        name: &str,
        identity: &Identity,
        plain: &str,
    ) -> TestResult<std::path::PathBuf> {
        let cipher = encrypt_bytes(plain.as_bytes(), &[public_recipient(identity)])
            .map_err(|err| err.to_string())?;
        let path = dir.join(format!("{name}.age"));
        std::fs::write(&path, cipher).map_err(|err| err.to_string())?;
        Ok(path)
    }

    /// A sealed env file plus its own dedicated identity.
    fn fixture(
        dir: &std::path::Path,
        name: &str,
        plain: &str,
    ) -> TestResult<(std::path::PathBuf, std::path::PathBuf)> {
        let identity_path = dir.join(format!("{name}.key"));
        let identity = generate_identity(&identity_path).map_err(|err| err.to_string())?;
        let file = write_secrets(dir, name, &identity, plain)?;
        Ok((file, identity_path))
    }

    fn entry(file: &std::path::Path, identity: Option<&std::path::Path>) -> SecretEntry {
        SecretEntry {
            file: file.display().to_string(),
            identity: identity.map(|path| path.display().to_string()),
        }
    }

    fn value_of<'a>(env: &'a [(String, String)], key: &str) -> &'a str {
        env.iter().find(|(name, _)| name == key).map_or("", |(_, value)| value.as_str())
    }

    #[test]
    fn per_entry_identity_is_used_over_the_run_flag() -> TestResult<()> {
        let dir = tempfile::tempdir().map_err(|err| err.to_string())?;
        let (main_file, main_identity) = fixture(dir.path(), "main", "A=frommain\n")?;
        let (other_file, other_identity) = fixture(dir.path(), "other", "B=fromother\n")?;

        // The run-wide identity decrypts `main`; the entry pins `other` to
        // its own key. Before the fix, `other` was opened with `main`'s key
        // and the run aborted.
        let entries = vec![entry(&main_file, None), entry(&other_file, Some(&other_identity))];
        let (env, _masks) =
            resolve_secrets(&entries, Some(&main_identity), 6).map_err(|err| format!("{err:#}"))?;

        assert_eq!(value_of(&env, "A"), "frommain");
        assert_eq!(value_of(&env, "B"), "fromother", "per-entry identity was ignored");
        assert_eq!(value_of(&env, SECRET_KEYS_VAR), "A B");
        Ok(())
    }

    #[test]
    fn missing_run_identity_is_not_consulted_when_every_entry_pins_one() -> TestResult<()> {
        let dir = tempfile::tempdir().map_err(|err| err.to_string())?;
        let (file, identity) = fixture(dir.path(), "pinned", "A=1\n")?;
        let entries = vec![entry(&file, Some(&identity))];
        let absent = std::path::Path::new("/nonexistent/keys.txt");

        let (env, _masks) =
            resolve_secrets(&entries, Some(absent), 6).map_err(|err| format!("{err:#}"))?;
        assert_eq!(value_of(&env, "A"), "1");
        Ok(())
    }

    #[test]
    fn later_file_wins_and_key_list_is_deduplicated() -> TestResult<()> {
        let dir = tempfile::tempdir().map_err(|err| err.to_string())?;
        let identity = new_identity(dir.path(), "shared")?;
        let first = write_secrets(dir.path(), "a", &identity, "A=one\nB=keep\n")?;
        let second = write_secrets(dir.path(), "b", &identity, "A=two\n")?;
        let entries = vec![entry(&first, None), entry(&second, None)];

        let shared_identity = dir.path().join("shared.key");
        let (env, _masks) = resolve_secrets(&entries, Some(&shared_identity), 6)
            .map_err(|err| format!("{err:#}"))?;
        assert_eq!(value_of(&env, "A"), "two", "later file must win");
        assert_eq!(value_of(&env, "B"), "keep");
        assert_eq!(value_of(&env, SECRET_KEYS_VAR), "A B", "key list must be deduplicated");
        Ok(())
    }

    #[test]
    fn short_values_below_the_threshold_are_not_masked() -> TestResult<()> {
        let dir = tempfile::tempdir().map_err(|err| err.to_string())?;
        let (file, identity) = fixture(dir.path(), "short", "S=abc\n")?;
        let entries = vec![entry(&file, None)];

        let (_env, masks) =
            resolve_secrets(&entries, Some(&identity), 6).map_err(|err| format!("{err:#}"))?;
        assert!(masks.is_empty(), "a 3-char value must not be masked at threshold 6");

        let (_env, masks) =
            resolve_secrets(&entries, Some(&identity), 3).map_err(|err| format!("{err:#}"))?;
        assert_eq!(masks, vec!["abc".to_string()]);
        Ok(())
    }

    #[test]
    fn unresolvable_identity_is_a_hard_error() -> TestResult<()> {
        let dir = tempfile::tempdir().map_err(|err| err.to_string())?;
        let (file, _) = fixture(dir.path(), "x", "A=1\n")?;
        let entries = vec![entry(&file, None)];
        let absent = std::path::Path::new("/nonexistent/shellflow-key");

        let Err(err) = resolve_secrets(&entries, Some(absent), 6) else {
            return Err("a missing identity must fail the run, not silently skip".to_string());
        };
        let rendered = format!("{err:#}");
        assert!(rendered.contains("/nonexistent/shellflow-key"), "unexpected error: {rendered}");
        Ok(())
    }
}
