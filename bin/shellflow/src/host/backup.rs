//! Snapshots: write, seal, prune, shred.
//!
//! A backup asserts on the files it wrote itself, so a failed copy cannot pass
//! as a snapshot that exists.

use super::{
    Command, HostBackupArgs, HostError, Path, PathBuf, Stdio, Write, fs,
    privileged::{
        chmod_elevated, create_dir_all_elevated, list_dir, list_dir_elevated,
        read_file_maybe_elevated, write_file_elevated,
    },
    unix_timestamp, validate_absolute_path, validate_unit,
};

/// Snapshot files for rollback, and keep the retention rule in one place.
///
/// The snapshot never contains a plaintext copy of a configuration file when
/// `--seal` is given: the file is encrypted with the host key, exactly like
/// the credential store, so a snapshot that leaves the machine is useless to
/// whoever finds it.
///
/// The "no plaintext left behind" guarantee is **structural**: the helper
/// knows every file it wrote, so it checks its own writes. The shell
/// spelling re-globbed the directory through `find … | grep -q .`, which
/// passes when the `find` fails.
pub(super) fn backup(args: &HostBackupArgs) -> Result<(), HostError> {
    if args.paths.is_empty() {
        return Err(HostError::usage("no paths to back up"));
    }
    let service = args.service.clone().unwrap_or_else(|| "backup".to_string());
    validate_unit(&service)?;
    let dir =
        args.dir.clone().unwrap_or_else(|| format!("/root/{service}-backup-{}", unix_timestamp()));
    validate_absolute_path(Path::new(&dir)).map_err(|err| {
        HostError::usage(format!("the snapshot directory is invalid (got `{dir}`): {err}"))
    })?;
    let dir_path = PathBuf::from(&dir);
    create_dir_all_elevated(&dir_path, 0o700)?;

    for path in &args.paths {
        validate_absolute_path(Path::new(path)).map_err(|err| {
            HostError::usage(format!("the path is invalid (got `{path}`): {err}"))
        })?;
        let source = Path::new(path);
        if !source.exists() {
            crate::ui::report!("==> {path} does not exist: nothing to back up");
            continue;
        }
        let name = source
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| HostError::usage(format!("`{path}` has no file name")))?;
        let target = if shellflow_text::is_unit_file(name) || !args.seal {
            // A unit file holds no secret; a configuration file does.
            dir_path.join(name)
        } else {
            dir_path.join(format!("{name}.enc"))
        };
        if args.seal && !shellflow_text::is_unit_file(name) {
            seal_file(source, &target)?;
        } else {
            let contents = read_file_maybe_elevated(source)
                .map_err(|err| HostError::internal(format!("cannot back up `{path}`: {err}")))?;
            write_file_elevated(&target, &contents, 0o600)?;
        }
        crate::ui::report!("==> backed up {path} -> {}", target.display());
    }

    // The guarantee the shell spelling could not make: every file in the
    // snapshot is either a unit file or an encrypted copy. The snapshot
    // directory is root-owned, so the listing is elevated.
    let unexpected: Vec<String> = list_dir_elevated(&dir_path)?
        .into_iter()
        .filter(|entry| {
            let name = entry.file_name().and_then(|n| n.to_str()).unwrap_or_default();
            !shellflow_text::is_unit_file(name) && !name.ends_with(".enc")
        })
        .map(|entry| entry.display().to_string())
        .collect();
    if !unexpected.is_empty() {
        return Err(HostError::failed(format!(
            "the snapshot directory {dir} holds files that are neither unit files nor encrypted \
             copies: {}",
            unexpected.join(", ")
        )));
    }
    if let Some(keep) = args.keep {
        prune_snapshots(&dir, &service, keep)?;
    }
    crate::ui::report!("==> snapshot ready: {dir}");
    Ok(())
}

/// Encrypt a file with the host key, so the snapshot holds no plaintext.
///
/// The value never reaches a command line: `systemd-creds encrypt` reads the
/// plaintext from stdin.
pub(super) fn seal_file(source: &Path, target: &Path) -> Result<(), HostError> {
    let contents = read_file_maybe_elevated(source)?;
    let mut child = Command::new("sudo")
        .arg("-n")
        .arg("systemd-creds")
        .arg("encrypt")
        .arg("--with-key=host")
        .arg("--name")
        .arg(source.file_name().and_then(|n| n.to_str()).unwrap_or("snapshot"))
        .arg("-")
        .arg(target)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| HostError::internal(format!("cannot run `systemd-creds`: {err}")))?;
    {
        let Some(stdin) = child.stdin.as_mut() else {
            return Err(HostError::internal("cannot write to `systemd-creds`"));
        };
        stdin
            .write_all(&contents)
            .map_err(|err| HostError::internal(format!("cannot feed `systemd-creds`: {err}")))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|err| HostError::internal(format!("`systemd-creds` failed: {err}")))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(HostError::internal(format!(
            "`systemd-creds encrypt` failed: {}",
            stderr.trim()
        )));
    }
    chmod_elevated(target, 0o600)?;
    Ok(())
}

/// Keep the newest `keep` snapshots and remove the rest.
///
/// The old copies are shredded rather than deleted: they hold encrypted
/// configuration snapshots, and the point of the retention rule is that they
/// really disappear.
pub(super) fn prune_snapshots(dir: &str, service: &str, keep: u32) -> Result<(), HostError> {
    let parent = Path::new(dir).parent().unwrap_or_else(|| Path::new("/root"));
    let prefix = format!("{service}-backup-");
    let mut snapshots: Vec<(u64, PathBuf)> = Vec::new();
    // The snapshot directory is root-owned: listing it, and reading the
    // timestamps of what is in it, need elevation. The name carries the
    // timestamp anyway, so the sort does not need the mtime.
    for entry in list_dir_elevated(parent)? {
        let name = entry.file_name().and_then(|n| n.to_str()).unwrap_or_default().to_string();
        if !name.starts_with(&prefix) {
            continue;
        }
        let stamp = name.trim_start_matches(&prefix).parse::<u64>().unwrap_or(0);
        snapshots.push((stamp, entry));
    }
    snapshots.sort_by_key(|(stamp, _)| std::cmp::Reverse(*stamp));
    if snapshots.len() <= keep as usize {
        return Ok(());
    }
    for (_, path) in snapshots.into_iter().skip(keep as usize) {
        shred_and_remove(&path)?;
        crate::ui::report!("==> pruned old snapshot: {}", path.display());
    }
    Ok(())
}

/// Overwrite a file with zeros, then remove it.
///
/// The unelevated path never hands a path to a shell: removal runs as
/// `sudo rm -rf -- <path>` / `sudo find <path> ... -exec shred` with the path
/// as argv, so a directory named `'; rm -rf /'` cannot inject commands. `find`
/// takes no `--` separator (it is not portable; an absolute path cannot be
/// mistaken for an option), while `rm` keeps its `--`.
pub(super) fn shred_and_remove(path: &Path) -> Result<(), HostError> {
    if !nix::unistd::Uid::effective().is_root() {
        // The snapshot belongs to root: shredding it in place needs root.
        // An unelevated pass would fail to write the file and would leave
        // the old credential copies on disk -- the opposite of the point.
        if let Some(parent) = path.parent() {
            validate_absolute_path(parent)?;
        }
        validate_absolute_path(path)?;
        let out = Command::new("sudo")
            .arg("-n")
            .arg("find")
            .arg(path)
            .arg("-type")
            .arg("f")
            .arg("-exec")
            .arg("shred")
            .arg("-u")
            .arg("--")
            .arg("{}")
            .arg("+")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .map_err(|err| {
                HostError::internal(format!("cannot remove `{}`: {err}", path.display()))
            })?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(HostError::failed(format!(
                "cannot remove `{}`: {}",
                path.display(),
                stderr.trim()
            )));
        }
        let out = Command::new("sudo")
            .arg("-n")
            .arg("rm")
            .arg("-rf")
            .arg("--")
            .arg(path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .map_err(|err| {
                HostError::internal(format!("cannot remove `{}`: {err}", path.display()))
            })?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(HostError::failed(format!(
                "cannot remove `{}`: {}",
                path.display(),
                stderr.trim()
            )));
        }
        return Ok(());
    }
    if path.is_dir() {
        for entry in list_dir(path)? {
            shred_and_remove(&entry)?;
        }
        let _ = fs::remove_dir_all(path);
        return Ok(());
    }
    let Ok(meta) = fs::metadata(path) else {
        return Ok(());
    };
    let len = meta.len();
    if len > 0 {
        let chunk = vec![0u8; 4096.min(len as usize)];
        let mut remaining = len;
        if let Ok(mut file) = fs::File::create(path) {
            while remaining > 0 {
                let n = chunk.len().min(remaining as usize);
                if file.write_all(&chunk[..n]).is_err() {
                    break;
                }
                remaining -= n as u64;
            }
            let _ = file.sync_all();
        }
    }
    let _ = fs::remove_file(path);
    Ok(())
}
