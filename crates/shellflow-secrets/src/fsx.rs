//! Atomic file writes with an explicit permission mode.
//!
//! Every path in `shellflow` that persists bytes the user cares about —
//! decrypted plaintext, an age ciphertext, an identity — goes through here.
//! Three properties are non-negotiable and are therefore enforced once, in
//! one place, instead of being re-derived per call site:
//!
//! 1. **0600 by default.** `std::fs::write` creates `0666 & ~umask`, so a `secret decrypt -o env`
//!    would leave secrets group/world readable.
//! 2. **Atomic.** Content is staged in a same-directory temp file and renamed into place
//!    (`write_atomic`), or hard-linked into place when refusing to overwrite (`write_new_file`), so
//!    a failure never truncates the previous contents and a reader never observes a partial write.
//! 3. **Mode enforced on every write, not just on create.** `OpenOptions::mode` only applies when
//!    the file is created; re-writing an existing 0644 file would otherwise silently keep the old
//!    mode.
//!
//! Unix only: the staging primitive sets POSIX modes. This matches the
//! supported targets (Bash + OpenSSH hosts) and is documented intentionally.

use std::{
    fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use crate::error::SecretsError;

/// How many distinct temp names to try before giving up on a name collision.
const NAME_ATTEMPTS: u32 = 10;

/// Write `bytes` to `path` with `mode`, atomically, replacing any existing
/// file.
///
/// The content is staged in a uniquely named sibling temp file, forced to
/// `mode`, then renamed over `path`. A reader never observes a partial write
/// and a failure never truncates the previous contents.
///
/// # Errors
///
/// Returns [`SecretsError::WriteFile`] on I/O failures.
pub fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<(), SecretsError> {
    let temp = stage(path, bytes, mode)?;
    match fs::rename(&temp, path) {
        Ok(()) => Ok(()),
        Err(source) => {
            let _ = fs::remove_file(&temp);
            Err(SecretsError::WriteFile { path: path.display().to_string(), source })
        }
    }
}

/// Write `bytes` to `path` with `mode`, atomically, **refusing to overwrite**
/// an existing file.
///
/// The content is staged in a sibling temp file and then linked into place.
/// A hard link fails when the destination already exists, so the "refuse to
/// overwrite" guarantee is enforced by the filesystem rather than by a
/// check-then-write race.
///
/// # Errors
///
/// Returns [`SecretsError::WriteFile`] on I/O failures, including when
/// `path` already exists.
pub fn write_new_file(path: &Path, bytes: &[u8], mode: u32) -> Result<(), SecretsError> {
    let temp = stage(path, bytes, mode)?;
    match fs::hard_link(&temp, path) {
        Ok(()) => {
            let _ = fs::remove_file(&temp);
            Ok(())
        }
        Err(source) => {
            let _ = fs::remove_file(&temp);
            Err(SecretsError::WriteFile { path: path.display().to_string(), source })
        }
    }
}

/// Stage `bytes` in a uniquely named sibling temp file with `mode`.
///
/// The returned path must be published (renamed or linked into place) or
/// removed by the caller.
fn stage(path: &Path, bytes: &[u8], mode: u32) -> Result<PathBuf, SecretsError> {
    stage_with(path, bytes, mode, staging_nonce())
}

/// The current time in nanoseconds since the epoch.
///
/// The clock is only a *seed*: the attempt counter is mixed in, so two calls
/// can never pick the same name even when the clock does not advance between
/// them.
fn staging_nonce() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0u128, |d| d.as_nanos())
}

/// Stage `bytes`, with the nonce seed injected.
///
/// The seed is a parameter so the collision path can be exercised
/// deterministically: the retry only ever happens when a name is already
/// taken, and a test cannot arrange that with a wall-clock seed.
fn stage_with(path: &Path, bytes: &[u8], mode: u32, seed: u128) -> Result<PathBuf, SecretsError> {
    let parent =
        path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    let base = path.file_name().map_or_else(|| "out".into(), |n| n.to_string_lossy().into_owned());
    let pid = std::process::id();

    let mut last_err: Option<SecretsError> = None;
    for attempt in 0..NAME_ATTEMPTS {
        // The attempt is mixed into the seed, so every retry picks a name the
        // previous attempt could not have used.
        let nonce = seed ^ u128::from(attempt);
        // Dots keep the staging file out of directory listings that glob
        // `*`, and `create_new` below means a planted name cannot be reused.
        let temp = parent.join(format!(".{base}.tmp.{pid}.{nonce}"));
        match stage_file(&temp, bytes, mode) {
            Ok(()) => return Ok(temp),
            Err(err) => {
                // The staging file is only removed when *this* call created
                // it. A name collision means somebody else owns that path —
                // deleting it would destroy a file shellflow never wrote.
                if !is_name_collision(&err) {
                    let _ = fs::remove_file(&temp);
                }
                // Retry only on a name collision; any other I/O error is real.
                if is_name_collision(&err) {
                    last_err = Some(err);
                    continue;
                }
                return Err(err);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| SecretsError::WriteFile {
        path: path.display().to_string(),
        source: std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "cannot create a temporary file next to the destination",
        ),
    }))
}

/// Create the staging file with `mode`, write `bytes` into it, and flush it
/// to disk.
fn stage_file(temp: &Path, bytes: &[u8], mode: u32) -> Result<(), SecretsError> {
    let err = |source: std::io::Error| SecretsError::WriteFile {
        path: temp.display().to_string(),
        source,
    };
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(temp)
            .map_err(err)?;
        file.write_all(bytes).map_err(err)?;
        file.flush().map_err(err)?;
        file.sync_all().map_err(err)?;
    }
    // `create_new` applies `mode` only at creation; set it explicitly so the
    // staging file's mode is guaranteed even under a restrictive umask.
    fs::set_permissions(temp, fs::Permissions::from_mode(mode)).map_err(err)?;
    Ok(())
}

/// Whether the failure only warrants trying another temp name.
fn is_name_collision(err: &SecretsError) -> bool {
    matches!(err, SecretsError::WriteFile { source, .. }
        if source.kind() == std::io::ErrorKind::AlreadyExists)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_atomic_creates_the_file_with_the_requested_mode() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("secret.txt");
        write_atomic(&path, b"payload", 0o600).expect("write");
        assert_eq!(std::fs::read(&path).expect("read"), b"payload");
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "a secret-bearing file must be owner-only");
    }

    #[test]
    fn write_atomic_replaces_an_existing_file_and_corrects_its_mode() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("secret.txt");
        std::fs::write(&path, b"old").expect("seed");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("loosen");
        write_atomic(&path, b"new", 0o600).expect("write");
        assert_eq!(std::fs::read(&path).expect("read"), b"new");
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the mode must be re-applied on every write");
    }

    #[test]
    fn write_new_file_refuses_to_overwrite() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("key.txt");
        write_new_file(&path, b"first", 0o600).expect("write");
        assert!(write_new_file(&path, b"second", 0o600).is_err(), "must refuse to overwrite");
        assert_eq!(std::fs::read(&path).expect("read"), b"first");
    }

    #[test]
    fn no_staging_file_is_left_behind() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("secret.txt");
        write_atomic(&path, b"payload", 0o600).expect("write");
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .expect("read dir")
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty(), "staging files left behind: {leftovers:?}");
    }

    #[test]
    fn the_staging_nonce_carries_a_timestamp() {
        // The staging name must not be derivable from the pid alone: pids
        // are reused, and two processes must never pick the same name.
        assert!(staging_nonce() > 1_000_000_000, "the nonce must carry a timestamp");
    }

    /// The staging file name a given seed and attempt produce.
    fn staging_name(path: &Path, seed: u128, attempt: u32) -> PathBuf {
        let parent =
            path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
        let base =
            path.file_name().map_or_else(|| "out".into(), |n| n.to_string_lossy().into_owned());
        parent.join(format!(".{base}.tmp.{}.{}", std::process::id(), seed ^ u128::from(attempt)))
    }

    #[test]
    fn a_taken_name_is_retried_with_a_fresh_one() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("secret.txt");
        // The name of the first attempt is planted, so the first attempt
        // collides and the staging must move on to the next name.
        let planted = staging_name(&path, 1, 0);
        std::fs::write(&planted, b"planted").expect("plant");
        let staged = stage_with(&path, b"payload", 0o600, 1).expect("stage");
        assert_ne!(staged, planted, "the retry must use a fresh name");
        assert_eq!(
            staged.file_name().and_then(|n| n.to_str()),
            Some(format!(".secret.txt.tmp.{}.0", std::process::id()).as_str()),
            "the retry must use the next attempt's name"
        );
        assert!(planted.exists(), "the planted file must not be removed");
        assert_eq!(std::fs::read(&staged).expect("read"), b"payload");
    }

    #[test]
    fn a_real_io_error_is_reported_on_the_first_attempt() {
        // The staging directory does not exist: the failure is real, not a
        // name collision, so it must be reported immediately instead of
        // being retried.
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("missing").join("secret.txt");
        let err = stage_with(&path, b"payload", 0o600, 1).expect_err("staging must fail");
        let crate::error::SecretsError::WriteFile { path: reported, .. } = &err else {
            panic!("unexpected error: {err}");
        };
        assert_eq!(
            *reported,
            staging_name(&path, 1, 0).display().to_string(),
            "the first attempt must be the one reported"
        );
    }
}
