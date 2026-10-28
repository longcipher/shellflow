//! `shellflow emit` — print embedded target-side helper assets.
//!
//! The controller writes these helpers to the targets during a deploy so
//! services never hand-roll their own credential plumbing.

use std::io::Write;

use eyre::{Result, WrapErr};

use crate::{
    cli::{EmitCmd, EmitCredEnvArgs},
    fsx::write_executable_file,
};

/// The embedded `cred-env` helper (see `assets/cred-env.sh` for the contract).
const CRED_ENV: &str = include_str!("../assets/cred-env.sh");

/// Run an `emit` subcommand.
///
/// # Errors
///
/// Propagates I/O errors when writing to a file.
pub(crate) fn run(cmd: &EmitCmd) -> Result<()> {
    match cmd {
        EmitCmd::CredEnv(args) => cred_env(args),
    }
}

fn cred_env(args: &EmitCredEnvArgs) -> Result<()> {
    if let Some(path) = &args.output {
        // Atomic, and the 0755 mode is re-applied on every write: design
        // §S12.2 makes the per-host install idempotent, so re-emitting over a
        // file that already exists (e.g. one first created by a plain
        // `> cred-env` redirect) must still leave it executable.
        // `OpenOptions::mode` alone would only apply at creation time.
        write_executable_file(path, CRED_ENV.as_bytes())?;
        crate::ui::report!("wrote cred-env to {}", path.display());
    } else {
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(CRED_ENV.as_bytes()).wrap_err("failed to write to stdout")?;
        stdout.flush().wrap_err("failed to flush stdout")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::{CRED_ENV, write_executable_file};

    #[test]
    fn written_helper_is_executable_and_complete() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("cred-env");
        write_executable_file(&path, CRED_ENV.as_bytes()).expect("write helper");
        let mode = std::fs::metadata(&path).expect("metadata").permissions().mode();
        assert_eq!(mode & 0o777, 0o755, "helper must be runnable, got {mode:o}");
        let written = std::fs::read_to_string(&path).expect("read back");
        assert_eq!(written, CRED_ENV, "helper must round-trip byte for byte");
    }

    #[test]
    fn re_emit_repairs_the_execute_bit() {
        // Idempotent re-install (design §S12.2): an existing non-executable
        // file must come out executable, which `OpenOptions::mode` alone
        // does not guarantee.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("cred-env");
        std::fs::write(&path, "stale").expect("seed non-executable file");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod 644");

        write_executable_file(&path, CRED_ENV.as_bytes()).expect("re-emit");
        let mode = std::fs::metadata(&path).expect("metadata").permissions().mode();
        assert_eq!(mode & 0o111, 0o111, "re-emit must restore the execute bit, got {mode:o}");
    }
}
