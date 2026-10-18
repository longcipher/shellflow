//! Resolution of `@secrets` encrypted env files into run-state environment
//! variables and mask values.
//!
//! Decryption happens once, before the first step runs. Shared (non-`{host}`)
//! entries are injected into the run-state env (the same layer as `@export`,
//! so an explicit `@env KEY=value` still wins on conflicts). Entries whose
//! path contains the `{host}` placeholder expand to one encrypted file per
//! targeted `@server` alias; each host receives only its own values, and a
//! targeted host whose file is missing fails the run (fail closed). Every
//! decrypted value is registered for masking in previews, traces, and
//! `--log-file`.

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
    identity::{effective_identity_path, expand_home, load_x25519_identity},
};

/// The space-separated list of keys exported after resolving `@secrets`.
pub(crate) const SECRET_KEYS_VAR: &str = "LT_SECRET_KEYS";

/// Resolved secrets: shared pairs injected into run-state, per-host pairs
/// layered onto each host's payload, and every value to mask.
pub(crate) struct ResolvedSecrets {
    shared: Vec<(String, String)>,
    per_host: HashMap<String, Vec<(String, String)>>,
    masks: Vec<String>,
}

impl ResolvedSecrets {
    /// Empty result for playbooks with no `@secrets` directive.
    ///
    /// No `LT_SECRET_KEYS` var is injected: `credstore-install` treats
    /// set-but-empty as "explicit no credentials, clear the store", so
    /// exporting an empty list here would let a secrets-less playbook wipe a
    /// service store. Absent var fails closed instead (no wipe).
    pub(crate) fn empty() -> Self {
        Self { shared: Vec::new(), per_host: HashMap::new(), masks: Vec::new() }
    }

    /// Whether any entry used the `{host}` placeholder (needs a single
    /// `--local` target to resolve unambiguously).
    pub(crate) fn has_per_host(&self) -> bool {
        !self.per_host.is_empty()
    }

    /// Shared `(key, value)` pairs for run-state env injection.
    pub(crate) fn shared_env(&self) -> &[(String, String)] {
        &self.shared
    }

    pub(crate) fn masks(&self) -> &[String] {
        &self.masks
    }

    /// This host's `{host}` pairs, if it had any per-host `@secrets` entries.
    pub(crate) fn host_pairs(&self, alias: &str) -> Option<&[(String, String)]> {
        self.per_host.get(alias).map(Vec::as_slice)
    }

    /// Layer this host's `{host}` pairs onto `env` (a later value wins on a
    /// duplicate key), and extend `LT_SECRET_KEYS` with this host's keys.
    pub(crate) fn overlay(&self, env: &mut Vec<(String, String)>, alias: &str) {
        let Some(pairs) = self.per_host.get(alias) else {
            return;
        };
        let mut host_keys: Vec<String> = Vec::new();
        for (k, v) in pairs {
            if let Some(slot) = env.iter_mut().find(|(ek, _)| ek == k) {
                slot.1.clone_from(v);
            } else {
                env.push((k.clone(), v.clone()));
            }
            if !host_keys.contains(k) {
                host_keys.push(k.clone());
            }
        }

        // Merge host keys into the exported LT_SECRET_KEYS list.
        let mut all: Vec<String> = env
            .iter()
            .find(|(k, _)| k == SECRET_KEYS_VAR)
            .map_or_default(|(_, v)| v.split_whitespace().map(String::from).collect());
        for k in &host_keys {
            if !all.contains(k) {
                all.push(k.clone());
            }
        }
        let joined = all.join(" ");
        if let Some(slot) = env.iter_mut().find(|(k, _)| k == SECRET_KEYS_VAR) {
            slot.1 = joined;
        } else {
            env.push((SECRET_KEYS_VAR.to_string(), joined));
        }
    }
}

/// Resolve every `@secrets` entry into shared pairs, per-host pairs, and a
/// list of values to mask.
///
/// `host_aliases` are the host aliases the selected steps actually target
/// (after `--target` restriction); a `{host}` entry expands against exactly
/// this set, so a host no selected step touches never requires a file.
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
/// invalid, a file cannot be read/decrypted (including a targeted host whose
/// `{host}` file is absent), or an env file is malformed.
pub(crate) fn resolve_secrets(
    entries: &[SecretEntry],
    host_aliases: &[String],
    identity: Option<&Path>,
    mask_min_len: usize,
) -> Result<ResolvedSecrets> {
    let mut cache: HashMap<PathBuf, Identity> = HashMap::new();
    let mut shared: Vec<(String, String)> = Vec::new();
    let mut shared_keys: Vec<String> = Vec::new();
    let mut per_host: HashMap<String, Vec<(String, String)>> = HashMap::new();
    let mut masks: Vec<String> = Vec::new();

    for entry in entries {
        // Per-entry `--identity` also expands `~/` (same as the run-wide
        // flag); previously it used `PathBuf::from` directly, so
        // `@secrets x.age --identity ~/keys.txt` read a literal `~` path.
        let id_path = entry
            .identity
            .as_deref()
            .map_or_else(|| effective_identity_path(identity), |s| expand_home(Path::new(s)));
        if !cache.contains_key(&id_path) {
            let loaded = load_x25519_identity(&id_path)
                .map_err(|err| eyre!("{err} (identity: {})", id_path.display()))?;
            cache.insert(id_path.clone(), loaded);
        }
        let identity = cache.get(&id_path).ok_or_else(|| {
            eyre!("failed to load identity {} (identity: {})", id_path.display(), id_path.display())
        })?;

        if entry.file.contains("{host}") {
            // Per-host: one file per targeted alias; a missing file is a
            // hard error (fail closed) rather than a guessed placeholder.
            for alias in host_aliases {
                let path = entry.file.replace("{host}", alias);
                let pairs = decrypt_file(&path, identity, &mut masks, mask_min_len)?;
                per_host.entry(alias.clone()).or_default().extend(pairs);
            }
        } else {
            let pairs = decrypt_file(&entry.file, identity, &mut masks, mask_min_len)?;
            for (key, _) in &pairs {
                if !shared_keys.contains(key) {
                    shared_keys.push(key.clone());
                }
            }
            // Later files override earlier ones (last `@secrets` wins), and the
            // key list stays deduplicated.
            for (key, value) in pairs {
                shared.retain(|(ek, _)| ek != &key);
                shared.push((key, value));
            }
        }
    }

    shared.push((SECRET_KEYS_VAR.to_string(), shared_keys.join(" ")));
    Ok(ResolvedSecrets { shared, per_host, masks })
}

/// Read, decrypt, and parse one age-encrypted env file, registering any value
/// at or above `mask_min_len` for masking.
fn decrypt_file(
    path: &str,
    identity: &Identity,
    masks: &mut Vec<String>,
    mask_min_len: usize,
) -> Result<Vec<(String, String)>> {
    let cipher =
        fs::read(path).wrap_err_with(|| format!("failed to read secrets file `{path}`"))?;
    let plain =
        decrypt_bytes(&cipher, identity).wrap_err_with(|| format!("failed to decrypt `{path}`"))?;
    let plain = String::from_utf8(plain)
        .wrap_err_with(|| format!("secrets file `{path}` is not valid UTF-8"))?;
    let pairs = parse_env_file(&plain).wrap_err_with(|| format!("malformed env file `{path}`"))?;
    let mut out = Vec::new();
    for (key, value) in pairs {
        // De-duplicate masks so repeated values are not redundantly replaced;
        // `mask_line` also sorts longest-first to avoid prefix leakage.
        if value.len() >= mask_min_len && !masks.contains(&value) {
            masks.push(value.clone());
        }
        out.retain(|(existing, _)| existing != &key);
        out.push((key, value));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use age::x25519::Identity;
    use shellflow_core::SecretEntry;
    use shellflow_secrets::{crypto::encrypt_bytes, identity::generate_identity};

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
        let recipient = shellflow_secrets::identity::public_recipient(identity);
        let cipher =
            encrypt_bytes(plain.as_bytes(), &[recipient]).map_err(|err| err.to_string())?;
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
    fn masked_values_are_registered() -> TestResult<()> {
        let dir = tempfile::tempdir().map_err(|err| err.to_string())?;
        let (file, identity) = fixture(dir.path(), "masked", "SECRET=supersecret_value\n")?;
        let entries = vec![entry(&file, None)];

        let resolved =
            resolve_secrets(&entries, &[], Some(&identity), 6).map_err(|err| format!("{err:#}"))?;
        assert!(resolved.masks().contains(&"supersecret_value".to_string()));
        assert_eq!(value_of(resolved.shared_env(), "SECRET"), "supersecret_value");
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
        let resolved = resolve_secrets(&entries, &[], Some(&shared_identity), 6)
            .map_err(|err| format!("{err:#}"))?;
        let env = resolved.shared_env();
        assert_eq!(value_of(env, "A"), "two", "later file must win");
        assert_eq!(value_of(env, "B"), "keep");
        assert_eq!(value_of(env, SECRET_KEYS_VAR), "A B", "key list must be deduplicated");
        Ok(())
    }

    #[test]
    fn short_values_below_the_threshold_are_not_masked() -> TestResult<()> {
        let dir = tempfile::tempdir().map_err(|err| err.to_string())?;
        let (file, identity) = fixture(dir.path(), "short", "S=abc\n")?;
        let entries = vec![entry(&file, None)];

        let resolved =
            resolve_secrets(&entries, &[], Some(&identity), 6).map_err(|err| format!("{err:#}"))?;
        assert!(resolved.masks().is_empty(), "a 3-char value must not be masked at threshold 6");

        let resolved =
            resolve_secrets(&entries, &[], Some(&identity), 3).map_err(|err| format!("{err:#}"))?;
        assert_eq!(resolved.masks(), &["abc".to_string()]);
        Ok(())
    }

    #[test]
    fn unresolvable_identity_is_a_hard_error() -> TestResult<()> {
        let dir = tempfile::tempdir().map_err(|err| err.to_string())?;
        let (file, _) = fixture(dir.path(), "x", "A=1\n")?;
        let entries = vec![entry(&file, None)];
        let absent = std::path::Path::new("/nonexistent/shellflow-key");

        let Err(err) = resolve_secrets(&entries, &[], Some(absent), 6) else {
            return Err("a missing identity must fail the run, not silently skip".to_string());
        };
        let rendered = format!("{err:#}");
        assert!(rendered.contains("/nonexistent/shellflow-key"), "unexpected error: {rendered}");
        Ok(())
    }

    #[test]
    fn per_host_entries_expand_and_layer() -> TestResult<()> {
        let dir = tempfile::tempdir().map_err(|err| err.to_string())?;
        let identity_path = dir.path().join("common.key");
        let identity = generate_identity(&identity_path).map_err(|err| err.to_string())?;
        let common = write_secrets(dir.path(), "common", &identity, "SHARED=shared-value\n")?;
        let _api = write_secrets(dir.path(), "api", &identity, "API_KEY=api-value\n")?;
        let _trade = write_secrets(dir.path(), "trade", &identity, "API_KEY=trade-value\n")?;

        // Build per-host entries via the {host} placeholder.
        let common_entry = entry(&common, None);
        let host_entry = SecretEntry {
            file: dir.path().join("{host}.age").display().to_string(),
            identity: None,
        };
        let entries = vec![common_entry, host_entry];
        let aliases = vec!["api".to_string(), "trade".to_string()];

        let resolved = resolve_secrets(&entries, &aliases, Some(&identity_path), 6)
            .map_err(|err| format!("{err:#}"))?;
        assert!(resolved.has_per_host());

        // Shared env carries only the shared key.
        let env = resolved.shared_env();
        assert_eq!(value_of(env, "SHARED"), "shared-value");
        assert!(value_of(env, "API_KEY").is_empty());

        // api's payload gets api's value; trade never sees it.
        let mut api_env = env.to_vec();
        resolved.overlay(&mut api_env, "api");
        assert_eq!(value_of(&api_env, "API_KEY"), "api-value");
        assert_eq!(value_of(&api_env, SECRET_KEYS_VAR), "SHARED API_KEY");

        let mut trade_env = env.to_vec();
        resolved.overlay(&mut trade_env, "trade");
        assert_eq!(value_of(&trade_env, "API_KEY"), "trade-value");
        assert!(!trade_env.iter().any(|(k, v)| k == "API_KEY" && v == "api-value"));
        Ok(())
    }

    #[test]
    fn missing_per_host_file_fails_closed() -> TestResult<()> {
        let dir = tempfile::tempdir().map_err(|err| err.to_string())?;
        let (api, identity) = fixture(dir.path(), "api", "API_KEY=api-value\n")?;
        let _ = api;
        let host_entry = SecretEntry {
            file: dir.path().join("{host}.age").display().to_string(),
            identity: None,
        };
        let entries = vec![host_entry];
        // trade.env.age does not exist -> must error.
        let aliases = vec!["api".to_string(), "trade".to_string()];

        assert!(
            resolve_secrets(&entries, &aliases, Some(&identity), 6).is_err(),
            "a targeted host without its file must fail closed"
        );
        Ok(())
    }
}
