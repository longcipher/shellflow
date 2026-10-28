//! Privileged filesystem and `systemctl` operations.
//!
//! Each helper reads (or writes) directly when the caller has the rights and
//! elevates only on a permission failure, so an unprivileged target needs no
//! `sudo` at all.

use super::{Command, HostError, Path, PathBuf, Stdio, Write, fs};

/// Map the shared `systemctl` error into this command's vocabulary: a usage
/// error keeps exit 1, a failed operation is exit 3 (the condition did not
/// hold), and a spawn failure is an internal error (exit 1).
pub(super) fn into_host_error(err: crate::systemctl::SystemctlError) -> HostError {
    match err {
        crate::systemctl::SystemctlError::Usage(_) => HostError::usage(err.to_string()),
        crate::systemctl::SystemctlError::Failed { .. } => HostError::failed(err.to_string()),
        crate::systemctl::SystemctlError::Spawn(_) => HostError::internal(err.to_string()),
    }
}

/// Run `systemctl`, elevating when the caller is not root.
pub(super) fn systemctl_output(args: &[&str]) -> Result<std::process::Output, HostError> {
    crate::systemctl::output(args).map_err(into_host_error)
}

/// Run `systemctl`, mapping a failure to an error.
pub(super) fn run_systemctl(args: &[&str]) -> Result<(), HostError> {
    crate::systemctl::run(args).map_err(into_host_error)
}

/// A `sudo -n <program>` invocation with no stdin.
///
/// `-n` is not negotiable: without it a target that needs a password blocks
/// forever on a terminal the payload does not have, and the deploy hangs
/// instead of failing. Every elevation goes through this constructor so the
/// flag cannot be forgotten at one call site.
fn sudo(program: &str) -> Command {
    let mut cmd = Command::new("sudo");
    cmd.arg("-n").arg(program).stdin(Stdio::null());
    cmd
}

/// Run `sudo -n <args>` and return its output.
///
/// For the callers that need nothing but a finished child: `systemd-creds`,
/// `systemctl show`, and friends. `-n` and the null stdin come from [`sudo`].
pub(super) fn sudo_output(args: &[&str]) -> std::io::Result<std::process::Output> {
    let mut cmd = sudo(args[0]);
    cmd.args(&args[1..]).output()
}

/// Turn a non-zero exit into an error, letting the caller word the message.
///
/// The stderr text is the only diagnostic a failed `sudo` gives, so it is
/// always part of the message; the caller supplies the verb and the subject.
fn command_failed(
    out: &std::process::Output,
    is_error: impl Fn(&str) -> HostError,
) -> Option<HostError> {
    if out.status.success() {
        return None;
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    Some(is_error(stderr.trim()))
}

/// Read a file, elevating when the caller may not read it.
///
/// A backup snapshots files the service owns -- a rendered config can be
/// root-owned 0600 -- so an unelevated read fails exactly where the backup
/// matters most. The direct read comes first (it works for unit files and
/// costs no fork); only a permission failure escalates. The contents are
/// never printed, only written into the snapshot or sealed.
pub(super) fn read_file_maybe_elevated(path: &Path) -> Result<Vec<u8>, HostError> {
    match fs::read(path) {
        Ok(contents) => return Ok(contents),
        Err(err) if err.kind() != std::io::ErrorKind::PermissionDenied => {
            return Err(HostError::internal(format!("cannot read `{}`: {err}", path.display())));
        }
        Err(_) => {}
    }
    if nix::unistd::Uid::effective().is_root() {
        return Err(HostError::failed(format!(
            "cannot read `{}`: permission denied",
            path.display()
        )));
    }
    let out = sudo("cat")
        .arg("--")
        .arg(path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|err| HostError::internal(format!("cannot read `{}`: {err}", path.display())))?;
    if let Some(err) = command_failed(&out, |stderr| {
        HostError::failed(format!("cannot read `{}`: {stderr}", path.display()))
    }) {
        return Err(err);
    }
    Ok(out.stdout)
}

/// List a directory, sorted, elevating when the caller is not root.
///
/// The credential store is root-owned and 0700, so an unelevated read sees
/// nothing -- and "nothing" reads as "the store does not exist".
pub(super) fn list_dir_elevated(path: &Path) -> Result<Vec<PathBuf>, HostError> {
    // The plain listing first: it works when the caller may read the
    // directory, and it is the cheap path. Only when it fails does the
    // elevation matter.
    match list_dir(path) {
        Ok(entries) => return Ok(entries),
        Err(err) => {
            if nix::unistd::Uid::effective().is_root() {
                return Err(err);
            }
        }
    }
    let out = sudo("ls")
        .arg("-1A")
        .arg("--")
        .arg(path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|err| HostError::internal(format!("cannot list `{}`: {err}", path.display())))?;
    if let Some(err) = command_failed(&out, |stderr| {
        HostError::failed(format!("cannot list `{}`: {stderr}", path.display()))
    }) {
        return Err(err);
    }
    let mut entries: Vec<PathBuf> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| path.join(line))
        .collect();
    entries.sort();
    Ok(entries)
}

/// Whether a directory exists, elevating when the caller is not root.
pub(super) fn dir_exists_elevated(path: &Path) -> bool {
    if path.is_dir() {
        return true;
    }
    if nix::unistd::Uid::effective().is_root() {
        return false;
    }
    sudo("test")
        .arg("-d")
        .arg(path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// List a directory, sorted.
pub(super) fn list_dir(path: &Path) -> Result<Vec<PathBuf>, HostError> {
    let mut entries: Vec<PathBuf> = fs::read_dir(path)
        .map_err(|err| HostError::internal(format!("cannot list `{}`: {err}", path.display())))?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .collect();
    entries.sort();
    Ok(entries)
}

/// Create a directory (and its parents), elevating when needed.
pub(super) fn create_dir_all_elevated(path: &Path, mode: u32) -> Result<(), HostError> {
    if path.exists() {
        return Ok(());
    }
    if nix::unistd::Uid::effective().is_root() {
        return fs::create_dir_all(path).map_err(|err| {
            HostError::internal(format!("cannot create `{}`: {err}", path.display()))
        });
    }
    let out = sudo("install")
        .arg("-d")
        .arg(format!("-m{mode:o}"))
        .arg(path)
        .output()
        .map_err(|err| HostError::internal(format!("cannot run `install`: {err}")))?;
    if let Some(err) = command_failed(&out, |stderr| {
        HostError::internal(format!("cannot create `{}`: {stderr}", path.display()))
    }) {
        return Err(err);
    }
    Ok(())
}

/// Write a file with the given mode, elevating when needed.
pub(super) fn write_file_elevated(
    path: &Path,
    contents: &[u8],
    mode: u32,
) -> Result<(), HostError> {
    if nix::unistd::Uid::effective().is_root() {
        fs::write(path, contents).map_err(|err| {
            HostError::internal(format!("cannot write `{}`: {err}", path.display()))
        })?;
        return chmod_elevated(path, mode);
    }
    let mut child = sudo("install")
        .arg(format!("-m{mode:o}"))
        .arg("/dev/stdin")
        .arg(path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| HostError::internal(format!("cannot run `install`: {err}")))?;
    {
        let Some(stdin) = child.stdin.as_mut() else {
            return Err(HostError::internal("cannot write to `install`"));
        };
        stdin
            .write_all(contents)
            .map_err(|err| HostError::internal(format!("cannot write to `install`: {err}")))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|err| HostError::internal(format!("`install` failed: {err}")))?;
    if let Some(err) = command_failed(&out, |stderr| {
        HostError::internal(format!("cannot write `{}`: {stderr}", path.display()))
    }) {
        return Err(err);
    }
    Ok(())
}

/// Change a file's mode, elevating when needed.
pub(super) fn chmod_elevated(path: &Path, mode: u32) -> Result<(), HostError> {
    if nix::unistd::Uid::effective().is_root() {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)
            .map_err(|err| HostError::internal(format!("cannot stat `{}`: {err}", path.display())))?
            .permissions();
        perms.set_mode(mode);
        return fs::set_permissions(path, perms).map_err(|err| {
            HostError::internal(format!("cannot chmod `{}`: {err}", path.display()))
        });
    }
    let out = sudo("chmod")
        .arg(format!("{mode:o}"))
        .arg(path)
        .output()
        .map_err(|err| HostError::internal(format!("cannot run `chmod`: {err}")))?;
    if let Some(err) = command_failed(&out, |stderr| {
        HostError::internal(format!("cannot chmod `{}`: {stderr}", path.display()))
    }) {
        return Err(err);
    }
    Ok(())
}

/// Change a file's owner, elevating when needed.
pub(super) fn chown_elevated(path: &Path, owner: &str) -> Result<(), HostError> {
    let out = sudo("chown")
        .arg(owner)
        .arg(path)
        .output()
        .map_err(|err| HostError::internal(format!("cannot run `chown`: {err}")))?;
    if let Some(err) = command_failed(&out, |stderr| {
        HostError::internal(format!("cannot chown `{}` to {owner}: {stderr}", path.display()))
    }) {
        return Err(err);
    }
    Ok(())
}

/// Rename a file, elevating when needed.
///
/// The rename is the atomic step: the destination never exists in a partial
/// state.
pub(super) fn rename_elevated(from: &Path, to: &Path) -> Result<(), HostError> {
    if nix::unistd::Uid::effective().is_root() {
        return fs::rename(from, to).map_err(|err| {
            HostError::internal(format!(
                "cannot rename `{}` to `{}`: {err}",
                from.display(),
                to.display()
            ))
        });
    }
    let out = sudo("mv")
        .arg("-f")
        .arg(from)
        .arg(to)
        .output()
        .map_err(|err| HostError::internal(format!("cannot run `mv`: {err}")))?;
    if let Some(err) = command_failed(&out, |stderr| {
        HostError::internal(format!(
            "cannot rename `{}` to `{}`: {stderr}",
            from.display(),
            to.display()
        ))
    }) {
        return Err(err);
    }
    Ok(())
}
