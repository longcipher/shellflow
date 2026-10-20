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
//!
//! The staging primitive itself lives in `shellflow-secrets::fsx`, so the
//! identity file (which is written by that crate) and the files written here
//! share one implementation.

use std::path::Path;

use eyre::Result;

/// Owner-only, the mode any plaintext-bearing file must have.
const SECRET_MODE: u32 = 0o600;
/// Owner-runnable, for helper scripts installed on targets.
const EXECUTABLE_MODE: u32 = 0o755;

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
    shellflow_secrets::fsx::write_atomic(path, bytes, mode).map_err(|err| eyre::eyre!("{err}"))
}
