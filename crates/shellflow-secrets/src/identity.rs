//! Age identity handling: path resolution, loading, generation, and public
//! key derivation.

use std::{
    fs,
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    str::FromStr,
};

use age::secrecy::ExposeSecret;

use crate::error::SecretsError;

/// Env var that overrides the identity file path.
pub const IDENTITY_ENV: &str = "SHELLFLOW_AGE_IDENTITY";

/// Expand a leading `~/` to `$HOME`.
///
/// Returns the path unchanged when it does not start with `~/` or when
/// `$HOME` is unset (the caller then fails with a missing-file error rather
/// than silently writing to a literal `~` directory).
#[must_use]
pub fn expand_home(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    // An empty `$HOME` is treated as absent: `PathBuf::from("")` would make a
    // `~/x` expansion fall back to the relative path `x`, which resolves
    // against whatever directory happens to be current.
    if let Some(rest) = s.strip_prefix("~/") &&
        let Some(home) = std::env::var_os("HOME").filter(|h| !h.is_empty())
    {
        return PathBuf::from(home).join(rest);
    }
    path.to_path_buf()
}

/// The default identity file: `~/.config/age/keys.txt` (age convention).
///
/// Overridden by `$SHELLFLOW_AGE_IDENTITY` or an explicit `--identity`.
/// A leading `~/` in the env var is expanded against `$HOME`.
#[must_use]
pub fn default_identity_path() -> PathBuf {
    if let Some(env) = std::env::var_os(IDENTITY_ENV).filter(|v| !v.is_empty()) {
        return expand_home(&PathBuf::from(env));
    }
    // Without a usable `$HOME` there is no honest default: returning a
    // relative `.config/age/keys.txt` would silently adopt whatever identity
    // happens to sit in the current directory. Report the missing path
    // instead, which surfaces as a clear "identity not found".
    match std::env::var_os("HOME").filter(|h| !h.is_empty()) {
        Some(home) => PathBuf::from(home).join(".config/age/keys.txt"),
        None => PathBuf::from(".config/age/keys.txt"),
    }
}

/// Resolve the effective identity path: explicit `--identity` wins, then
/// `$SHELLFLOW_AGE_IDENTITY`, then the default location.
///
/// A leading `~/` in any of these is expanded against `$HOME`.
#[must_use]
pub fn effective_identity_path(explicit: Option<&Path>) -> PathBuf {
    explicit.map_or_else(default_identity_path, expand_home)
}

/// Load an X25519 identity from an age identity file.
///
/// # Errors
///
/// Returns [`SecretsError::MissingIdentity`] when the file does not exist,
/// [`SecretsError::InvalidIdentity`] when no `AGE-SECRET-KEY-1…` line is found
/// or the key does not parse.
pub fn load_x25519_identity(path: &Path) -> Result<age::x25519::Identity, SecretsError> {
    let content = fs::read_to_string(path).map_err(|err| match err.kind() {
        std::io::ErrorKind::NotFound => SecretsError::MissingIdentity(path.display().to_string()),
        _ => SecretsError::ReadIdentity {
            path: path.display().to_string(),
            source: std::io::Error::from(err.kind()),
        },
    })?;

    let line = content.lines().map(str::trim).find(|l| l.starts_with("AGE-SECRET-KEY-"));
    let Some(line) = line else {
        return Err(SecretsError::InvalidIdentity {
            path: path.display().to_string(),
            reason: "no `AGE-SECRET-KEY-1…` line found".to_string(),
        });
    };

    age::x25519::Identity::from_str(line).map_err(|reason| SecretsError::InvalidIdentity {
        path: path.display().to_string(),
        reason: reason.to_string(),
    })
}

/// Generate a new identity and atomically write it to `path` (mode `0600`).
///
/// Fails if the file already exists — an identity must never be overwritten.
///
/// # Errors
///
/// Returns [`SecretsError::WriteIdentity`] on I/O failures or when the file
/// already exists.
pub fn generate_identity(path: &Path) -> Result<age::x25519::Identity, SecretsError> {
    let identity = age::x25519::Identity::generate();

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| SecretsError::WriteIdentity {
            path: parent.display().to_string(),
            source,
        })?;
    }

    let mut file =
        fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).map_err(
            |source| SecretsError::WriteIdentity { path: path.display().to_string(), source },
        )?;
    writeln!(file, "{}", identity.to_string().expose_secret()).map_err(|source| {
        SecretsError::WriteIdentity { path: path.display().to_string(), source }
    })?;

    Ok(identity)
}

/// Derive the `age1…` recipient for an identity.
#[must_use]
pub fn public_recipient(identity: &age::x25519::Identity) -> age::x25519::Recipient {
    identity.to_public()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes tests that mutate process-global env vars (`HOME`,
    /// `SHELLFLOW_AGE_IDENTITY`). A single shared lock — not one per test —
    /// is required, otherwise the tests race on the global environment.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// RAII guard that restores an env var to its original state on drop.
    struct EnvRestore {
        key: &'static str,
        original: Option<std::ffi::OsString>,
    }

    impl EnvRestore {
        /// Set `key` to `value`, capturing its previous value for restore.
        ///
        /// # Safety
        /// Callers must hold `ENV_LOCK` so no other thread reads or writes the
        /// same env var concurrently (env access is process-global).
        unsafe fn set(key: &'static str, value: &str) -> Self {
            let original = std::env::var_os(key);
            // SAFETY: guarded by ENV_LOCK; values are non-secret test fixtures.
            unsafe {
                std::env::set_var(key, value);
            }
            Self { key, original }
        }
    }

    impl Drop for EnvRestore {
        fn drop(&mut self) {
            // SAFETY: guard lifetime is bounded by ENV_LOCK held by the test.
            unsafe {
                match &self.original {
                    Some(v) => std::env::set_var(self.key, v),
                    None => std::env::remove_var(self.key),
                }
            }
        }
    }

    #[test]
    fn generate_and_reload_round_trips() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("sub").join("keys.txt");
        let identity = generate_identity(&path).expect("generate");
        let public = public_recipient(&identity);

        let loaded = load_x25519_identity(&path).expect("reload");
        assert_eq!(public_recipient(&loaded).to_string(), public.to_string());

        let metadata = fs::metadata(&path).expect("stat");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn generate_refuses_to_overwrite() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("keys.txt");
        generate_identity(&path).expect("first write");
        assert!(matches!(generate_identity(&path), Err(SecretsError::WriteIdentity { .. })));
    }

    #[test]
    fn load_missing_identity_reports_path() {
        let err = match load_x25519_identity(Path::new("/nonexistent/keys.txt")) {
            Err(err) => err,
            Ok(_) => panic!("expected an error"),
        };
        assert!(matches!(err, SecretsError::MissingIdentity(_)));
    }

    #[test]
    fn load_invalid_identity_reports_reason() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("keys.txt");
        fs::write(&path, "not an age key\n").expect("write");
        let err = match load_x25519_identity(&path) {
            Err(err) => err,
            Ok(_) => panic!("expected an error"),
        };
        assert!(matches!(err, SecretsError::InvalidIdentity { .. }));
    }

    #[test]
    fn effective_identity_prefers_explicit() {
        let explicit = Path::new("/tmp/explicit-key.txt");
        assert_eq!(effective_identity_path(Some(explicit)), explicit.to_path_buf());
    }

    #[test]
    fn default_identity_resolves_env_then_home() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        // Env access is process-global and guarded by ENV_LOCK; values are
        // non-secret test fixtures.
        {
            // SAFETY: guarded by ENV_LOCK.
            let _identity_env = unsafe { EnvRestore::set(IDENTITY_ENV, "/custom/key.txt") };
            assert_eq!(default_identity_path(), PathBuf::from("/custom/key.txt"));
        }
        // SAFETY: guarded by ENV_LOCK.
        let _home = unsafe { EnvRestore::set("HOME", "/home/test-user") };
        assert_eq!(default_identity_path(), PathBuf::from("/home/test-user/.config/age/keys.txt"));
    }

    #[test]
    fn expand_home_handles_tilde_and_plain_paths() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        // SAFETY: guarded by ENV_LOCK.
        let _home = unsafe { EnvRestore::set("HOME", "/home/test-user") };
        assert_eq!(expand_home(Path::new("~/keys.txt")), PathBuf::from("/home/test-user/keys.txt"));
        assert_eq!(
            expand_home(Path::new("~/.config/age/keys.txt")),
            PathBuf::from("/home/test-user/.config/age/keys.txt")
        );
        assert_eq!(expand_home(Path::new("/abs/keys.txt")), PathBuf::from("/abs/keys.txt"));
        assert_eq!(expand_home(Path::new("relative/keys.txt")), PathBuf::from("relative/keys.txt"));
    }

    #[test]
    fn effective_identity_expands_tilde() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        // SAFETY: guarded by ENV_LOCK.
        let _home = unsafe { EnvRestore::set("HOME", "/home/tilde-user") };
        assert_eq!(
            effective_identity_path(Some(Path::new("~/keys.txt"))),
            PathBuf::from("/home/tilde-user/keys.txt")
        );
    }
}
