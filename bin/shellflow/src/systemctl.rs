//! The one `systemctl` invocation path.
//!
//! `host` and `systemd` both drive the local systemd, and both grew their own
//! copy of "run `systemctl`, elevate when not root, map the failure to an
//! error": identical bodies, different error types. Two copies of a privilege
//! boundary are one edit away from disagreeing, so the command line and the
//! elevation rule live here and each caller maps [`SystemctlError`] into its
//! own error type (the exit-code vocabulary stays per-command).
//!
//! These verbs run **on the target**, as the deploy user or root: the binary
//! ships them to the host (`shellflow systemd …`) and the payloads call them.

use std::{
    fmt,
    process::{Command, Output, Stdio},
};

use shellflow_text::is_valid_unit_name;

/// A failed `systemctl` invocation, before it is mapped to a command's own
/// error type.
#[derive(Debug)]
pub(crate) enum SystemctlError {
    /// The unit name (or another argument) was rejected before running.
    Usage(String),
    /// `systemctl` (or its `sudo` wrapper) could not be spawned.
    Spawn(std::io::Error),
    /// `systemctl` ran and reported a failure.
    Failed {
        /// The argument list, for the message.
        command: String,
        /// The target's stderr, trimmed.
        stderr: String,
    },
}

impl fmt::Display for SystemctlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(message) => formatter.write_str(message),
            Self::Spawn(err) => write!(formatter, "cannot run `systemctl`: {err}"),
            Self::Failed { command, stderr } => {
                write!(formatter, "`systemctl {command}` failed: {stderr}")
            }
        }
    }
}

impl std::error::Error for SystemctlError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Spawn(err) => Some(err),
            Self::Usage(_) | Self::Failed { .. } => None,
        }
    }
}

impl SystemctlError {
    /// Whether this is a usage error (exit 1) rather than an operational one.
    #[must_use]
    pub(crate) const fn is_usage(&self) -> bool {
        matches!(self, Self::Usage(_))
    }
}

/// Run `systemctl`, elevating when the caller is not root.
///
/// The helper is installed for the deploy user, but `systemctl reload`,
/// `systemctl kill`, and every write are privileged. Passwordless sudo is the
/// same assumption the `cred-env` helper already makes; a host without it gets
/// a clear error instead of a silent no-op.
pub(crate) fn output(args: &[&str]) -> Result<Output, SystemctlError> {
    let mut cmd = if nix::unistd::Uid::effective().is_root() {
        let mut cmd = Command::new("systemctl");
        cmd.args(args);
        cmd
    } else {
        let mut cmd = Command::new("sudo");
        cmd.arg("-n").arg("systemctl").args(args);
        cmd
    };
    cmd.stdin(Stdio::null())
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .output()
        .map_err(SystemctlError::Spawn)
}

/// Run `systemctl` and fail unless it exits zero.
pub(crate) fn run(args: &[&str]) -> Result<(), SystemctlError> {
    let out = output(args)?;
    if out.status.success() {
        return Ok(());
    }
    Err(SystemctlError::Failed {
        command: args.join(" "),
        stderr: String::from_utf8_lossy(&out.stderr).trim().to_string(),
    })
}

/// Whether the unit declares a given property (`systemctl show -p X`).
///
/// An unreadable property is reported as "absent": callers use this to decide
/// between a graceful reload and a refusal, and a host that cannot answer must
/// not be assumed to support the reload.
pub(crate) fn has_property(unit: &str, property: &str) -> bool {
    let Ok(out) = output(&["show", unit, "-p", property]) else {
        return false;
    };
    if !out.status.success() {
        return false;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines().any(|line| !line.ends_with('=') && !line.is_empty())
}

/// Reject a unit name that is unsafe to interpolate into a command.
pub(crate) fn validate_unit(unit: &str) -> Result<(), SystemctlError> {
    if unit.is_empty() {
        return Err(SystemctlError::Usage("empty unit name".to_string()));
    }
    if !is_valid_unit_name(unit) {
        return Err(SystemctlError::Usage(format!("invalid unit name `{unit}`")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shared_unit_rules_reject_metacharacters() {
        assert!(validate_unit("dufs").is_ok());
        assert!(validate_unit("app@blue.service").is_ok());
        assert!(validate_unit("").expect_err("empty").is_usage());
        assert!(validate_unit("a;rm -rf /").expect_err("shell").is_usage());
    }

    #[test]
    fn a_spawn_failure_says_which_tool_was_missing() {
        // The message is what an operator sees on a host without systemd;
        // losing the tool name would make it unactionable.
        let rendered = SystemctlError::Spawn(std::io::Error::from(std::io::ErrorKind::NotFound));
        assert!(rendered.to_string().contains("systemctl"), "{rendered}");
    }
}
