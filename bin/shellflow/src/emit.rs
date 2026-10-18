//! `shellflow emit` — print embedded target-side helper assets.
//!
//! The controller writes these helpers to the targets during a deploy so
//! services never hand-roll their own credential plumbing.

use std::{fs, io::Write, os::unix::fs::OpenOptionsExt, path::Path};

use eyre::{Result, WrapErr};

use crate::cli::{EmitCmd, EmitCredEnvArgs};

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
        write_executable(path, CRED_ENV)?;
        println!("wrote cred-env to {}", path.display());
    } else {
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(CRED_ENV.as_bytes()).wrap_err("failed to write to stdout")?;
        stdout.flush().wrap_err("failed to flush stdout")?;
    }
    Ok(())
}

/// Write `content` to `path` with owner-executable permissions (0755).
///
/// # Errors
///
/// Returns an I/O error when the file cannot be created or written.
fn write_executable(path: &Path, content: &str) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o755)
        .open(path)
        .wrap_err_with(|| format!("failed to create {}", path.display()))?;
    file.write_all(content.as_bytes())
        .wrap_err_with(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

    use super::{CRED_ENV, write_executable};

    #[test]
    fn written_helper_is_executable_and_complete() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path: PathBuf = dir.path().join("cred-env");
        write_executable(&path, CRED_ENV).expect("write helper");
        let mode = fs::metadata(&path).expect("metadata").permissions().mode();
        assert_eq!(mode & 0o777, 0o755, "helper must be runnable, got {mode:o}");
        let written = fs::read_to_string(&path).expect("read back");
        assert_eq!(written, CRED_ENV, "helper must round-trip byte for byte");
    }
}
