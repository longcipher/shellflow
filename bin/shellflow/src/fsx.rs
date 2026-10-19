//! Atomic file writes with an explicit permission mode.
//!
//! Every path in `shellflow` that persists bytes the user cares about —
//! decrypted plaintext, an age ciphertext, an embedded helper asset — goes
//! through here. Three properties are non-negotiable and are therefore
//! enforced once, in one place, instead of being re-derived per call site:
//!
//! 1. **0600 by default.** `std::fs::write` creates `0666 & ~umask`, so a `secret decrypt -o env`
//!    would leave secrets group/world readable.
//! 2. **Atomic.** Content is staged in a same-directory temp file and renamed into place, so a
//!    failure never truncates the previous contents and a reader never observes a partial write.
//! 3. **Mode enforced on every write, not just on create.** `OpenOptions::mode` only applies when
//!    the file is created; re-writing an existing 0644 file would otherwise silently keep the old
//!    mode.

use std::{
    fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};

use eyre::{Result, WrapErr};

/// Owner-only, the mode any plaintext-bearing file must have.
const SECRET_MODE: u32 = 0o600;
/// Owner-runnable, for helper scripts installed on targets.
const EXECUTABLE_MODE: u32 = 0o755;
/// How many distinct temp names to try before giving up on a name collision.
const NAME_ATTEMPTS: u32 = 10;

/// Write `bytes` to `path` with mode 0600, atomically.
pub(crate) fn write_secret_file(path: &Path, bytes: &[u8]) -> Result<()> {
    write_atomic(path, bytes, SECRET_MODE)
}

/// Write `bytes` to `path` with mode 0755, atomically.
///
/// Used for the embedded `cred-env` helper: design §S12.2 makes the per-host
/// install idempotent, so re-emitting over an existing file must still leave
/// it executable.
pub(crate) fn write_executable_file(path: &Path, bytes: &[u8]) -> Result<()> {
    write_atomic(path, bytes, EXECUTABLE_MODE)
}

/// Stage `bytes` in a uniquely named sibling temp file, force `mode`, then
/// rename it over `path`.
fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let parent =
        path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    let base = path.file_name().map_or_else(|| "out".into(), |n| n.to_string_lossy().into_owned());
    let pid = std::process::id();

    let mut last_err: Option<eyre::Report> = None;
    for attempt in 0..NAME_ATTEMPTS {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0u128, |d| d.as_nanos() ^ u128::from(attempt));
        // Dots keep the staging file out of directory listings that glob
        // `*`, and `create_new` below means a planted name cannot be reused.
        let temp = parent.join(format!(".{base}.tmp.{pid}.{nonce}"));

        match stage_and_rename(&temp, path, bytes, mode) {
            Ok(()) => return Ok(()),
            Err(err) => {
                let _ = fs::remove_file(&temp);
                // Retry only on a name collision; any other I/O error is real.
                if err.is_name_collision() {
                    last_err = Some(err);
                    continue;
                }
                return Err(err);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| {
        eyre::eyre!("cannot create a temporary file next to `{}`", path.display())
    }))
}

/// A failure that only warrants trying another temp name.
trait NameCollision {
    fn is_name_collision(&self) -> bool;
}

impl NameCollision for eyre::Report {
    fn is_name_collision(&self) -> bool {
        self.downcast_ref::<std::io::Error>()
            .is_some_and(|err| err.kind() == std::io::ErrorKind::AlreadyExists)
    }
}

fn stage_and_rename(temp: &Path, dest: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(temp)
            .wrap_err_with(|| format!("cannot create `{}`", temp.display()))?;
        file.write_all(bytes).wrap_err("cannot write contents")?;
        file.flush().wrap_err("cannot flush contents")?;
        file.sync_all().wrap_err("cannot sync contents to disk")?;
    }
    // `create_new` applies `mode` only at creation; set it explicitly so the
    // staging file's mode is guaranteed even under a restrictive umask.
    fs::set_permissions(temp, fs::Permissions::from_mode(mode))
        .wrap_err_with(|| format!("cannot set mode on `{}`", temp.display()))?;
    fs::rename(temp, dest)
        .wrap_err_with(|| format!("cannot move contents into `{}`", dest.display()))?;
    Ok(())
}
