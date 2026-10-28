//! Atomic installs and digest assertions.

use super::{
    HostAssertDigestArgs, HostError, HostInstallArgs, Path, PathBuf, fs,
    privileged::{chown_elevated, create_dir_all_elevated, rename_elevated, write_file_elevated},
    sha256_file,
};

/// Install a file on the target, atomically.
///
/// The file is written to a temporary name **in the destination directory**
/// and then renamed into place. `rename` within one filesystem is atomic, so
/// a reader (systemd, `systemctl cat`, a concurrent `daemon-reload`) sees
/// either the old file or the new one — never a truncated one. The shell
/// spelling (`install -m … dst`) truncated the live file in place.
pub(super) fn install(args: &HostInstallArgs) -> Result<(), HostError> {
    let src = Path::new(&args.src);
    let dst = Path::new(&args.dst);
    install_guards(src, dst)?;

    let parent = dst
        .parent()
        .ok_or_else(|| HostError::usage(format!("`{}` has no parent directory", args.dst)))?;
    if parent_must_be_created(parent) {
        let dir_mode = args.dir_mode.unwrap_or(0o755);
        create_dir_all_elevated(parent, dir_mode)?;
    }

    let file_name = dst
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| HostError::usage(format!("`{}` has no file name", args.dst)))?;
    let tmp = staging_path(parent, file_name);
    // A leftover temporary file from an interrupted run must not be mistaken
    // for the destination.
    let _ = fs::remove_file(&tmp);

    let contents = fs::read(src)
        .map_err(|err| HostError::internal(format!("cannot read `{}`: {err}", args.src)))?;
    write_file_elevated(&tmp, &contents, args.mode.unwrap_or(0o644))?;
    if let Some(owner) = &args.owner {
        chown_elevated(&tmp, owner)?;
    }
    rename_elevated(&tmp, dst)?;
    crate::ui::report!("==> installed {} -> {}", src.display(), dst.display());
    Ok(())
}

/// Assert that a file matches a digest.
///
/// The shell spelling printed an `md5sum` that nothing compared; this is a
/// real gate.
pub(super) fn assert_digest(args: &HostAssertDigestArgs) -> Result<(), HostError> {
    let path = Path::new(&args.path);
    if !path.is_absolute() {
        return Err(HostError::usage(format!("the path must be absolute (got `{}`)", args.path)));
    }
    if !path.exists() {
        return Err(HostError::failed(format!("`{}` does not exist", args.path)));
    }
    let actual = sha256_file(path)?;
    let expected = expected_digest(args)?;
    digest_verdict(&args.path, expected.as_deref(), &actual)
}

/// What the operator asked the file to match: `--sha256` wins, then `--local`
/// (the digest of a file the deploy staged), then nothing.
///
/// `--sha256` is lower-cased: a digest copied out of a manifest that spells it
/// in upper case must still match.
fn expected_digest(args: &HostAssertDigestArgs) -> Result<Option<String>, HostError> {
    match (&args.sha256, &args.local) {
        (Some(digest), _) => Ok(Some(digest.to_ascii_lowercase())),
        (None, Some(local)) => {
            let local_path = Path::new(local);
            if !local_path.exists() {
                return Err(HostError::failed(format!("`{local}` does not exist")));
            }
            Ok(Some(sha256_file(local_path)?))
        }
        (None, None) => Ok(None),
    }
}

/// Compare a file's digest with the expectation.
///
/// `None` means no expectation was given: the assertion then **reports** the
/// digest instead of gating on it, which is what makes `@assert_digest` usable
/// as a deployment record as well as a gate.
fn digest_verdict(path: &str, expected: Option<&str>, actual: &str) -> Result<(), HostError> {
    match expected {
        Some(expected) if expected == actual => {
            crate::ui::report!("==> {path} matches sha256 {actual}");
            Ok(())
        }
        Some(expected) => {
            Err(HostError::failed(format!("{path} has sha256 {actual}, expected {expected}")))
        }
        None => {
            crate::ui::report!("==> {path} has sha256 {actual}");
            Ok(())
        }
    }
}

/// Everything an install can reject before it touches the target.
///
/// A relative or missing source is a deploy bug, and it is reported as one
/// rather than as a failed `install(1)`.
fn install_guards(src: &Path, dst: &Path) -> Result<(), HostError> {
    super::validate_absolute_path(src)?;
    super::validate_absolute_path(dst)?;
    if !src.exists() {
        return Err(HostError::failed(format!("the source `{}` does not exist", src.display())));
    }
    Ok(())
}

/// Whether the destination's directory has to be created first.
///
/// A destination under `/etc/systemd/system` exists on any systemd host; a
/// destination under a service's own runtime directory may not, and creating
/// it is the install's business rather than the playbook's.
fn parent_must_be_created(parent: &Path) -> bool {
    !parent.exists()
}

/// The temporary file an install writes before renaming it into place.
///
/// It sits **beside the destination**, so the rename stays within one
/// filesystem and therefore atomic; a shared temp directory would turn it into
/// a copy.
fn staging_path(parent: &Path, file_name: &str) -> PathBuf {
    parent.join(format!(".{file_name}.shellflow-new"))
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use super::{
        assert_digest, digest_verdict, install, install_guards, parent_must_be_created,
        staging_path,
    };
    use crate::cli::{HostAssertDigestArgs, HostInstallArgs};

    fn digest_args(path: &str, sha256: Option<&str>, local: Option<&str>) -> HostAssertDigestArgs {
        HostAssertDigestArgs {
            path: path.to_string(),
            sha256: sha256.map(str::to_string),
            local: local.map(str::to_string),
        }
    }

    #[test]
    fn an_install_rejects_a_relative_or_missing_source() {
        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("f");
        fs::write(&src, b"x").expect("write");
        assert!(install_guards(&src, std::path::Path::new("/srv/app")).is_ok());
        assert!(
            install_guards(std::path::Path::new("f"), std::path::Path::new("/srv/app")).is_err()
        );
        assert!(install_guards(&src, std::path::Path::new("app")).is_err());
        assert!(
            install_guards(&dir.path().join("nope"), std::path::Path::new("/srv/app")).is_err()
        );
    }

    #[test]
    fn the_staging_file_sits_beside_its_destination() {
        assert_eq!(
            staging_path(std::path::Path::new("/etc/systemd/system"), "app.service"),
            PathBuf::from("/etc/systemd/system/.app.service.shellflow-new")
        );
    }

    #[test]
    fn a_matching_digest_passes_and_a_wrong_one_fails() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("f");
        fs::write(&path, b"hello").expect("write");
        let path = path.to_string_lossy().into_owned();
        let digest = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

        assert!(assert_digest(&digest_args(&path, Some(digest), None)).is_ok());
        // An upper-case digest is the same digest.
        assert!(assert_digest(&digest_args(&path, Some(&digest.to_uppercase()), None)).is_ok());
        assert!(assert_digest(&digest_args(&path, Some("deadbeef"), None)).is_err());
        // No expectation: a report, not a gate.
        assert!(assert_digest(&digest_args(&path, None, None)).is_ok());
        assert!(assert_digest(&digest_args("relative/path", None, None)).is_err());
    }

    #[test]
    fn a_digest_verdict_names_both_digests() {
        assert!(digest_verdict("/srv/f", Some("aa"), "aa").is_ok());
        assert!(digest_verdict("/srv/f", None, "aa").is_ok());
        let err = digest_verdict("/srv/f", Some("bb"), "aa").expect_err("a mismatch must fail");
        assert!(err.to_string().contains("has sha256 aa, expected bb"), "{err}");
    }

    #[test]
    fn a_local_reference_digest_must_exist() {
        let dir = tempfile::tempdir().expect("tempdir");
        // The destination must exist; what is being tested is the reference.
        let installed = dir.path().join("f");
        fs::write(&installed, b"hello").expect("write");
        let missing = dir.path().join("nope");
        let args =
            digest_args(&installed.to_string_lossy(), None, Some(&missing.to_string_lossy()));
        let err = assert_digest(&args).expect_err("the reference file is missing");
        assert!(err.to_string().contains(&missing.to_string_lossy().into_owned()), "{err}");
    }

    #[test]
    fn a_local_reference_digest_is_compared_not_just_read() {
        let dir = tempfile::tempdir().expect("tempdir");
        let installed = dir.path().join("installed");
        fs::write(&installed, b"hello").expect("write");
        let same = dir.path().join("same");
        fs::write(&same, b"hello").expect("write");
        let other = dir.path().join("other");
        fs::write(&other, b"goodbye").expect("write");

        let installed = installed.to_string_lossy().into_owned();
        assert!(
            assert_digest(&digest_args(&installed, None, Some(&same.to_string_lossy()))).is_ok()
        );
        assert!(
            assert_digest(&digest_args(&installed, None, Some(&other.to_string_lossy()))).is_err()
        );
    }

    #[test]
    fn a_destination_directory_is_created_only_when_it_is_missing() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(!parent_must_be_created(dir.path()), "it exists");
        assert!(parent_must_be_created(&dir.path().join("missing")));
    }

    #[test]
    fn an_install_reports_a_rejected_source_instead_of_succeeding() {
        // The verb's exit code is the deploy's; an install that swallowed its
        // own validation would report success for a file it never wrote.
        let err = install(&HostInstallArgs {
            src: "relative/source".to_string(),
            dst: "/srv/app".to_string(),
            mode: None,
            owner: None,
            dir_mode: None,
        })
        .expect_err("a relative source must fail");
        assert!(err.to_string().contains("must be absolute"), "{err}");
    }
}
