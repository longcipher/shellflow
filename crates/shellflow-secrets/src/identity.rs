//! Age identity handling: path resolution, loading, generation, and public
//! key derivation.

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    str::FromStr,
};

use age::secrecy::ExposeSecret;
use zeroize::Zeroizing;

use crate::error::SecretsError;

/// Env var that overrides the identity file path.
pub const IDENTITY_ENV: &str = "SHELLFLOW_AGE_IDENTITY";

/// Env var that allows loading an identity file that other local users can
/// read.
///
/// The opt-out is an environment variable rather than a flag so that it
/// applies to every subcommand that touches an identity (`secret`,
/// `keys`, `template`, `deploy`) without threading a flag through each of
/// them.
pub const ALLOW_UNSAFE_IDENTITY_ENV: &str = "SHELLFLOW_ALLOW_UNSAFE_IDENTITY";

/// Whether the operator explicitly accepted a laxly-permissioned identity.
///
/// Only an affirmative value enables the override. Anything else — including
/// `false`, `no` and an unrecognized string — leaves the refusal in place:
/// the env var gates the acceptance of a file that holds the master key for
/// every sealed env file, so it must fail closed.
///
/// The value is an environment variable rather than a flag so that it applies
/// to every subcommand that touches an identity (`secret`, `keys`, `template`,
/// `deploy`) without threading a flag through each of them.
fn allow_unsafe_identity() -> bool {
    matches!(std::env::var(ALLOW_UNSAFE_IDENTITY_ENV).as_deref(), Ok("1" | "true" | "yes" | "on"))
}

/// Expand a leading `~/` to `$HOME`.
///
/// # Errors
///
/// Returns [`SecretsError::NoHome`] when the path starts with `~/` and
/// `$HOME` is unset or empty. Leaving the path unchanged would make it
/// *relative*, and a relative path is resolved against the current working
/// directory — so a planted `./…` file could be adopted as the operator's
/// identity. A bare `~` or `~user/...` is not expanded and is rejected as
/// [`SecretsError::InvalidIdentity`]-class usage by the caller validating the
/// path; here it is passed through unchanged so the filesystem error names the
/// literal path.
pub fn expand_home(path: &Path) -> Result<PathBuf, SecretsError> {
    let s = path.to_string_lossy();
    // An empty `$HOME` is treated as absent: `PathBuf::from("")` would make a
    // `~/x` expansion fall back to the relative path `x`, which resolves
    // against whatever directory happens to be current.
    if let Some(rest) = s.strip_prefix("~/") &&
        let Some(home) = std::env::var_os("HOME").filter(|h| !h.is_empty())
    {
        return Ok(PathBuf::from(home).join(rest));
    }
    if s.starts_with("~/") {
        return Err(SecretsError::NoHome);
    }
    // `~` alone and `~user/...` are not expanded by this helper by design;
    // they pass through unchanged so the filesystem error names the literal
    // path.
    Ok(path.to_path_buf())
}

/// The default identity file: `~/.config/age/keys.txt` (age convention).
///
/// Overridden by `$SHELLFLOW_AGE_IDENTITY` or an explicit `--identity`.
///
/// # Errors
///
/// Returns [`SecretsError::NoHome`] when neither `$SHELLFLOW_AGE_IDENTITY`
/// nor a usable `$HOME` is available. Without a usable `$HOME` there is no
/// honest default: a *relative* path would silently adopt whatever identity
/// happens to sit in the current directory, so the path is reported as
/// undefined instead. A whitespace-only `$SHELLFLOW_AGE_IDENTITY` is treated
/// as unset.
pub fn default_identity_path() -> Result<PathBuf, SecretsError> {
    if let Some(env) = std::env::var_os(IDENTITY_ENV)
        .map(|v| v.to_string_lossy().trim().to_string())
        .filter(|v| !v.is_empty())
    {
        return expand_home(&PathBuf::from(env));
    }
    let home = std::env::var_os("HOME").filter(|h| !h.is_empty()).ok_or(SecretsError::NoHome)?;
    Ok(PathBuf::from(home).join(".config/age/keys.txt"))
}

/// Resolve the effective identity path: explicit `--identity` wins, then
/// `$SHELLFLOW_AGE_IDENTITY`, then the default location.
///
/// A leading `~/` in any of these is expanded against `$HOME`.
///
/// # Errors
///
/// Returns [`SecretsError::NoHome`] when no path can be determined — see
/// [`default_identity_path`].
pub fn effective_identity_path(explicit: Option<&Path>) -> Result<PathBuf, SecretsError> {
    match explicit {
        Some(path) => expand_home(path),
        None => default_identity_path(),
    }
}

/// Load an X25519 identity from an age identity file.
///
/// The identity is the master key for every sealed env file the operator
/// owns: anyone who can read it can decrypt all of them. Generation enforces
/// mode `0600`, so a lax mode here is an accident (a shell redirect, an
/// editor save, a restore from a lax backup) rather than a choice — the
/// loader refuses it unless the operator sets
/// [`ALLOW_UNSAFE_IDENTITY_ENV`].
///
/// # Errors
///
/// Returns [`SecretsError::MissingIdentity`] when the file does not exist,
/// [`SecretsError::InvalidIdentity`] when no `AGE-SECRET-KEY-1…` line is found,
/// the key does not parse, or the file is readable by other local users.
pub fn load_x25519_identity(path: &Path) -> Result<age::x25519::Identity, SecretsError> {
    // The file is opened once and inspected through the open descriptor.
    // Stat-then-open would allow the file to be replaced in between, so the
    // mode that was checked could belong to a different file than the one
    // that is actually read.
    let mut file = fs::File::open(path).map_err(|err| match err.kind() {
        std::io::ErrorKind::NotFound => SecretsError::MissingIdentity(path.display().to_string()),
        _ => SecretsError::ReadIdentity { path: path.display().to_string(), source: err },
    })?;
    let metadata = file.metadata().map_err(|source| SecretsError::ReadIdentity {
        path: path.display().to_string(),
        source,
    })?;
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 && !allow_unsafe_identity() {
        return Err(SecretsError::InvalidIdentity {
            path: path.display().to_string(),
            reason: format!(
                "identity file is group/world-accessible (mode {mode:o}); run `chmod 600 {}` \
                 (or set {ALLOW_UNSAFE_IDENTITY_ENV}=1 to override)",
                path.display()
            ),
        });
    }

    // The identity file holds the master key for every sealed env file the
    // operator owns: the buffer is scrubbed when it is dropped, like every
    // other secret in this crate.
    let mut content = Zeroizing::new(String::new());
    std::io::Read::read_to_string(&mut file, &mut content).map_err(|source| {
        SecretsError::ReadIdentity { path: path.display().to_string(), source }
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
/// Returns [`SecretsError::WriteFile`] on I/O failures or when the file
/// already exists.
pub fn generate_identity(path: &Path) -> Result<age::x25519::Identity, SecretsError> {
    let identity = age::x25519::Identity::generate();

    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(|source| SecretsError::WriteFile {
            path: parent.display().to_string(),
            source,
        })?;
    }

    // The key is staged in a sibling temp file and then linked into place:
    // a crash cannot leave a truncated identity behind, and the link fails
    // when the destination already exists, so the "never overwrite" rule is
    // enforced by the filesystem instead of a check-then-write race.
    let secret = identity.to_string();
    crate::fsx::write_new_file(path, secret.expose_secret().as_bytes(), 0o600)?;

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

        /// Remove an env var for the duration of the guard.
        ///
        /// # Safety
        /// Callers must hold `ENV_LOCK` so no other thread reads or writes the
        /// same env var concurrently (env access is process-global).
        unsafe fn clear(key: &'static str) -> Self {
            let original = std::env::var_os(key);
            // SAFETY: guarded by ENV_LOCK.
            unsafe {
                std::env::remove_var(key);
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
        assert!(matches!(generate_identity(&path), Err(SecretsError::WriteFile { .. })));
    }

    #[test]
    fn a_group_readable_identity_is_refused() {
        // The identity is the master key for every sealed env file the
        // operator owns: anyone who can read it can decrypt all of them.
        let _lock = ENV_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("keys.txt");
        generate_identity(&path).expect("generate");

        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("loosen");
        let err = match load_x25519_identity(&path) {
            Err(err) => err,
            Ok(_) => panic!("a world-readable identity must be refused"),
        };
        let SecretsError::InvalidIdentity { reason, .. } = &err else {
            panic!("expected an invalid-identity error, got {err:?}");
        };
        assert!(reason.contains("group/world-accessible"), "reason: {reason}");
    }

    #[test]
    fn a_group_readable_identity_is_accepted_with_the_opt_out() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("keys.txt");
        generate_identity(&path).expect("generate");

        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("loosen");

        // SAFETY: guarded by ENV_LOCK.
        let _opt_out = unsafe { EnvRestore::set(ALLOW_UNSAFE_IDENTITY_ENV, "1") };
        assert!(load_x25519_identity(&path).is_ok(), "the opt-out must allow the load");
    }

    #[test]
    fn the_opt_out_fails_closed_for_a_negative_value() {
        // `false` / `no` / an unrecognized string must leave the refusal in
        // place: the env var gates the acceptance of the master key file.
        let _lock = ENV_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("keys.txt");
        generate_identity(&path).expect("generate");

        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("loosen");

        for value in ["false", "no", "off", "0", "maybe", ""] {
            // SAFETY: guarded by ENV_LOCK.
            let _opt_out = unsafe { EnvRestore::set(ALLOW_UNSAFE_IDENTITY_ENV, value) };
            assert!(
                load_x25519_identity(&path).is_err(),
                "`{value}` must not enable the unsafe-identity override"
            );
        }
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
        assert_eq!(
            effective_identity_path(Some(explicit)).expect("explicit path"),
            explicit.to_path_buf()
        );
    }

    #[test]
    fn default_identity_resolves_env_then_home() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        // Env access is process-global and guarded by ENV_LOCK; values are
        // non-secret test fixtures.
        {
            // SAFETY: guarded by ENV_LOCK.
            let _identity_env = unsafe { EnvRestore::set(IDENTITY_ENV, "/custom/key.txt") };
            assert_eq!(
                default_identity_path().expect("env override"),
                PathBuf::from("/custom/key.txt")
            );
        }
        // SAFETY: guarded by ENV_LOCK.
        let _home = unsafe { EnvRestore::set("HOME", "/home/test-user") };
        assert_eq!(
            default_identity_path().expect("home default"),
            PathBuf::from("/home/test-user/.config/age/keys.txt")
        );
    }

    #[test]
    fn an_unset_home_yields_no_identity_path() {
        // The default identity location is undefined without a usable `$HOME`.
        // It must NOT degrade to a relative path: a relative path is resolved
        // against the current working directory, so a planted
        // `./.config/age/keys.txt` would be adopted as the operator's identity.
        let _guard = ENV_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        {
            // SAFETY: guarded by ENV_LOCK.
            let _identity_env = unsafe { EnvRestore::clear(IDENTITY_ENV) };
            // SAFETY: guarded by ENV_LOCK.
            let _home = unsafe { EnvRestore::clear("HOME") };
            assert!(matches!(default_identity_path(), Err(SecretsError::NoHome)));
            assert!(matches!(effective_identity_path(None), Err(SecretsError::NoHome)));
            assert!(matches!(expand_home(Path::new("~/keys.txt")), Err(SecretsError::NoHome)));
        }
    }

    #[test]
    fn expand_home_handles_tilde_and_plain_paths() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        // SAFETY: guarded by ENV_LOCK.
        let _home = unsafe { EnvRestore::set("HOME", "/home/test-user") };
        assert_eq!(
            expand_home(Path::new("~/keys.txt")).expect("tilde"),
            PathBuf::from("/home/test-user/keys.txt")
        );
        assert_eq!(
            expand_home(Path::new("~/.config/age/keys.txt")).expect("tilde"),
            PathBuf::from("/home/test-user/.config/age/keys.txt")
        );
        assert_eq!(
            expand_home(Path::new("/abs/keys.txt")).expect("absolute"),
            PathBuf::from("/abs/keys.txt")
        );
        assert_eq!(
            expand_home(Path::new("relative/keys.txt")).expect("relative"),
            PathBuf::from("relative/keys.txt")
        );
    }

    #[test]
    fn effective_identity_expands_tilde() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        // SAFETY: guarded by ENV_LOCK.
        let _home = unsafe { EnvRestore::set("HOME", "/home/tilde-user") };
        assert_eq!(
            effective_identity_path(Some(Path::new("~/keys.txt"))).expect("tilde"),
            PathBuf::from("/home/tilde-user/keys.txt")
        );
    }
}
