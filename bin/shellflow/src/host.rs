//! Target-side host helpers: `shellflow host …`.
//!
//! These subcommands run **on the target host** (the binary is installed once
//! per host by a deploy playbook). They own the semantics that a playbook
//! used to spell out in shell — and that the shell spelling got wrong:
//!
//! * an install is **atomic** (write beside the destination, then rename), so a reader never
//!   observes a half-written unit file, config, or binary;
//! * a backup **asserts on the files it wrote itself** rather than re-globbing a directory through
//!   a pipeline that cannot fail;
//! * a restart **never starts a unit that was not running**, unless the operator says so
//!   explicitly;
//! * a leak check compares the **real credential values** instead of a per-service regular
//!   expression, and never puts a plaintext value on a command line.
//!
//! ## Exit codes (the contract the controller depends on)
//!
//! | Code | Meaning |
//! |------|---------|
//! | 0 | the operation succeeded |
//! | 1 | usage / internal error |
//! | 3 | the operation ran but the condition did not hold |
//! | 4 | the budget expired before the condition held |

use std::{
    collections::BTreeSet,
    fmt, fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use sha2::{Digest, Sha256};

use crate::cli::{
    HostAssertCredstoreArgs, HostAssertDigestArgs, HostAssertNoLeakArgs, HostBackupArgs, HostCmd,
    HostCredstoreArgs, HostInstallArgs, HostInventoryArgs, HostServiceArgs,
};
/// The target-side helper protocol (`crate::exit::helper`): these verbs run on
/// the target and report on a file or a unit, so their codes are a wire
/// contract with the payloads that call them — not the CLI's own codes.
pub(crate) use crate::exit::helper::{
    FAILED as EXIT_FAILED, TIMEOUT as EXIT_TIMEOUT, USAGE as EXIT_USAGE,
};

/// The credential store root, as the `cred-env` helper uses it.
pub(crate) const CREDSTORE_ROOT: &str = "/etc/credstore.encrypted";

/// A target-side host error.
///
/// The variants are the *reasons* a verb can fail, not just an exit code, so a
/// caller can tell "the operator asked for something impossible" (a deploy bug,
/// report it) from "the condition did not hold" (a fleet fact, retry or skip).
/// The exit code each one carries is the wire contract with the controller:
/// see `crate::exit::helper`.
#[derive(Debug)]
pub(crate) enum HostError {
    /// The verb, or the payload that called it, was used wrongly: exit 1.
    Usage(String),
    /// An internal invariant broke (a failed fork, an unreadable `/proc`
    /// entry): exit 1, and never the operator's fault.
    Internal(String),
    /// The operation ran and the condition did not hold: exit 3.
    Failed(String),
    /// The budget expired before the condition held: exit 4, which the
    /// controller reads as "a retry may well succeed" rather than a failure.
    TimedOut(String),
    /// A delegated `systemd`/`sudo` operation failed, keeping its own code.
    Delegated { message: String, code: i32 },
}

impl HostError {
    pub(crate) fn usage(message: impl Into<String>) -> Self {
        Self::Usage(message.into())
    }

    pub(crate) fn internal(message: impl Into<String>) -> Self {
        Self::Internal(message.into())
    }

    pub(crate) fn failed(message: impl Into<String>) -> Self {
        Self::Failed(message.into())
    }

    pub(crate) fn timed_out(message: impl Into<String>) -> Self {
        Self::TimedOut(message.into())
    }

    /// The message shown to the operator.
    #[must_use]
    pub(crate) fn message(&self) -> &str {
        match self {
            Self::Usage(message) |
            Self::Internal(message) |
            Self::Failed(message) |
            Self::TimedOut(message) |
            Self::Delegated { message, .. } => message,
        }
    }

    /// The process exit code this error maps to.
    #[must_use]
    pub(crate) const fn exit_code(&self) -> i32 {
        match self {
            Self::Usage(_) | Self::Internal(_) => EXIT_USAGE,
            Self::Failed(_) => EXIT_FAILED,
            Self::TimedOut(_) => EXIT_TIMEOUT,
            Self::Delegated { code, .. } => *code,
        }
    }
}

impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message())
    }
}

impl std::error::Error for HostError {}

impl From<crate::systemd::SystemdError> for HostError {
    fn from(err: crate::systemd::SystemdError) -> Self {
        Self::Delegated { message: err.message, code: err.code }
    }
}

/// Run `shellflow host …`.
///
/// # Errors
///
/// Returns the error of the verb that ran.
pub(crate) fn run(cmd: &HostCmd) -> Result<(), HostError> {
    match cmd {
        HostCmd::Service(args) => lifecycle::service(args),
        HostCmd::Install(args) => install::install(args),
        HostCmd::Backup(args) => backup::backup(args),
        HostCmd::Credstore(args) => credstore::credstore(args),
        HostCmd::AssertNoLeak(args) => credstore::assert_no_leak(args),
        HostCmd::AssertDigest(args) => install::assert_digest(args),
        HostCmd::AssertCredstore(args) => credstore::assert_credstore(args),
        HostCmd::Inventory(args) => probe::inventory(args),
    }
}

// === the systemd lifecycle ===

// === the atomic install ===

// === the backup ===

// === the credential store ===

// === the leak check ===

// === the digest check ===

// === the credential store check ===

// === the unit inventory ===

// === shared helpers ===

/// Validate an absolute path that is handed to a privileged command as argv.
///
/// The path is never passed through a shell, but it is still validated so a
/// programming error (empty path, relative path, NUL byte) fails closed
/// instead of deleting the wrong tree.
fn validate_absolute_path(path: &Path) -> Result<(), HostError> {
    let Some(text) = path.to_str() else {
        return Err(HostError::usage("path is not valid UTF-8"));
    };
    if !path.is_absolute() {
        return Err(HostError::usage(format!("the path must be absolute (got `{text}`)")));
    }
    if text.contains('\0') {
        return Err(HostError::usage("path must not contain NUL"));
    }
    Ok(())
}

/// Validate a unit name with the shared rule (see `shellflow_text`).
fn validate_unit(unit: &str) -> Result<(), HostError> {
    crate::systemctl::validate_unit(unit).map_err(privileged::into_host_error)
}

/// The value of a systemd directive in a unit file line.
///
/// Handles the `Key=value` form and the reset form (`Key=`).
fn strip_directive<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let trimmed = line.trim();
    let rest = trimmed.strip_prefix(key)?;
    Some(rest.trim())
}

/// The sha256 of a file, as lowercase hex.
fn sha256_file(path: &Path) -> Result<String, HostError> {
    let mut file = fs::File::open(path)
        .map_err(|err| HostError::internal(format!("cannot open `{}`: {err}", path.display())))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let read = file.read(&mut buffer).map_err(|err| {
            HostError::internal(format!("cannot read `{}`: {err}", path.display()))
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let mut digest = String::with_capacity(64);
    for byte in hasher.finalize() {
        use std::fmt::Write;
        let _ = write!(digest, "{byte:02x}");
    }
    Ok(digest)
}

/// The seconds since the Unix epoch.
fn unix_timestamp() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use super::{
        HostCmd, SystemTime, UNIX_EPOCH, sha256_file, strip_directive, unix_timestamp,
        validate_absolute_path, validate_unit,
    };
    use crate::cli::HostServiceArgs;

    #[test]
    fn a_unit_name_gets_the_service_suffix() {
        assert_eq!(shellflow_text::normalize_unit("dufs"), "dufs.service");
        assert_eq!(shellflow_text::normalize_unit("dufs.service"), "dufs.service");
        assert_eq!(shellflow_text::normalize_unit(" sshd "), "sshd.service");
    }

    #[test]
    fn unit_files_are_recognized_by_their_suffix() {
        assert!(shellflow_text::is_unit_file("dufs.service"));
        assert!(shellflow_text::is_unit_file("pg-backup.timer"));
        assert!(shellflow_text::is_unit_file("browserless.container"));
        assert!(!shellflow_text::is_unit_file("config.toml"));
        assert!(!shellflow_text::is_unit_file("dufs.service.enc"));
    }

    #[test]
    fn a_directive_is_read_from_a_unit_line() {
        assert_eq!(
            strip_directive(
                "LoadCredentialEncrypted=TOKEN:/etc/x/TOKEN",
                "LoadCredentialEncrypted="
            ),
            Some("TOKEN:/etc/x/TOKEN")
        );
        assert_eq!(strip_directive("ExecStart=/bin/true", "LoadCredentialEncrypted="), None);
    }

    #[test]
    fn a_privileged_path_must_be_absolute_and_free_of_nul() {
        // These paths reach `sudo rm -rf`-shaped argv; relative or NUL-bearing
        // input is a bug, and it must fail here rather than delete the wrong
        // tree.
        assert!(validate_absolute_path(Path::new("/srv/app")).is_ok());
        for bad in ["srv/app", "", "./x", "/srv/\0app"] {
            assert!(validate_absolute_path(Path::new(bad)).is_err(), "{bad} must be rejected");
        }
    }

    #[test]
    fn a_unit_name_is_validated_before_any_verb_runs() {
        assert!(validate_unit("dufs.service").is_ok());
        for bad in ["", "not a unit!", "../etc/passwd", "dufs.service; rm -rf /"] {
            assert!(validate_unit(bad).is_err(), "{bad} must be rejected");
        }
    }

    #[test]
    fn the_dispatch_reports_a_verbs_error() {
        // The CLI's exit code is the verb's; a dispatch that swallowed it would
        // report a successful deploy for a unit it never touched.
        let err = super::run(&HostCmd::Service(HostServiceArgs {
            unit: "not a unit!".to_string(),
            enable: false,
            restart: false,
            reload: false,
            wait: false,
            verify: false,
            force_start: false,
            timeout: 300,
        }))
        .expect_err("a malformed unit must fail");
        assert_eq!(err.exit_code(), super::EXIT_USAGE);
    }

    #[test]
    fn an_error_displays_its_message() {
        assert_eq!(super::HostError::failed("boom").to_string(), "boom");
        assert_eq!(super::HostError::timed_out("slow").exit_code(), super::EXIT_TIMEOUT);
    }

    #[test]
    fn the_epoch_clock_reports_seconds_not_milliseconds() {
        // Snapshot names are `unix_timestamp()` values; a millisecond clock
        // would make every snapshot look like it came from the year 57000.
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
        let stamp = unix_timestamp();
        assert!(stamp > 1_700_000_000, "seconds since the epoch: {stamp}");
        assert!(stamp <= now + 1 && stamp + 1 >= now, "{stamp} is not now ({now})");
    }

    #[test]
    fn the_sha256_of_a_file_is_stable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("f");
        fs::write(&path, b"hello").expect("write");
        let digest = sha256_file(&path).expect("digest");
        assert_eq!(digest, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    }
}

mod backup;
mod credstore;
mod install;
mod lifecycle;
mod privileged;
mod probe;
