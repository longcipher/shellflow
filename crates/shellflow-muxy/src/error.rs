//! Muxy transport errors: concrete types through `?`, never strings.

use thiserror::Error;

/// Every failure of the Muxy transport, classified so the executor can map it
/// to the right exit code without string matching.
#[derive(Debug, Error)]
pub enum MuxyError {
    /// The `ssh` that carries the bridge failed before the ready line.
    #[error("ssh to {destination} failed: {detail}")]
    Ssh {
        /// The host as the user named it.
        destination: String,
        /// The tail of ssh's stderr.
        detail: String,
    },

    /// `muxy` is not installed on the target.
    #[error("muxy is not installed on {destination}")]
    NotInstalled {
        /// The host as the user named it.
        destination: String,
    },

    /// The host cannot be resolved or reached.
    #[error("cannot reach {destination}: {detail}")]
    Unreachable {
        /// The host as the user named it.
        destination: String,
        /// What the transport reported.
        detail: String,
    },

    /// The bridge answered with a version this build cannot speak, or the
    /// server speaks a protocol this build cannot speak.
    #[error("incompatible muxy on {destination}: {detail}")]
    Incompatible {
        /// The host as the user named it.
        destination: String,
        /// Both sides, never a silent fallback under `--transport muxy`.
        detail: String,
    },

    /// The bridge did not answer in time.
    #[error("timed out connecting to {destination}: {detail}")]
    Timeout {
        /// The host as the user named it.
        destination: String,
        /// The last line of the transport's output.
        detail: String,
    },

    /// The remote shell printed output instead of starting the bridge.
    #[error("unexpected output from {destination}: {detail}")]
    UnexpectedOutput {
        /// The host as the user named it.
        destination: String,
        /// The last line of what the shell printed.
        detail: String,
    },

    /// The bridge reported an error.
    #[error("muxy bridge on {destination} failed: {detail}")]
    BridgeFailed {
        /// The host as the user named it.
        destination: String,
        /// What the bridge reported.
        detail: String,
    },

    /// A request to a connected server failed.
    #[error("muxy request failed: {detail}")]
    Request {
        /// What failed, for the operator.
        detail: String,
    },

    /// The server rejected the payload path or the session parameters.
    #[error("muxy plan error: {detail}")]
    Plan {
        /// What was wrong, for the operator.
        detail: String,
    },

    /// The connection dropped mid-step and the reconnect failed.
    #[error("lost the muxy connection to {destination}")]
    Disconnected {
        /// The host as the user named it.
        destination: String,
    },

    /// The step redrew the screen instead of scrolling (a full-screen TUI).
    #[error("{host}: the block redrew the screen; not supported over muxy (use --transport ssh)")]
    Tui {
        /// The host alias, for the operator.
        host: String,
    },

    /// The step produced more than the session's scrollback budget; the head
    /// is gone.
    #[error("{host}: the step produced more than the session budget; its head is gone")]
    BudgetExceeded {
        /// The host alias, for the operator.
        host: String,
    },

    /// The event-pump thread could not be spawned. A connection without a
    /// pump streams nothing, so the failure is reported instead of a run that
    /// silently "succeeds" with no output until its deadline.
    #[error("cannot spawn the event pump for {destination}")]
    PumpSpawn {
        /// The host as the user named it.
        destination: String,
    },
}

impl MuxyError {
    /// Whether connecting again may work without the user's help.
    #[must_use]
    pub const fn recoverable(&self) -> bool {
        match self {
            Self::Unreachable { .. } | Self::Timeout { .. } | Self::BridgeFailed { .. } => true,
            Self::Ssh { .. } |
            Self::NotInstalled { .. } |
            Self::Incompatible { .. } |
            Self::UnexpectedOutput { .. } |
            Self::Request { .. } |
            Self::Plan { .. } |
            Self::Disconnected { .. } |
            Self::Tui { .. } |
            Self::BudgetExceeded { .. } |
            Self::PumpSpawn { .. } => false,
        }
    }
}

/// Classify a `muxy-client` error without string matching the message.
#[must_use]
pub fn classify_client_error(destination: &str, err: &muxy_client::ClientError) -> MuxyError {
    use muxy_client::{ClientError, RemoteReason};
    match err {
        ClientError::Remote { reason, destination: _, detail } => {
            let destination = destination.to_string();
            let detail = detail.clone();
            match reason {
                RemoteReason::NotInstalled => MuxyError::NotInstalled { destination },
                RemoteReason::Unreachable => MuxyError::Unreachable { destination, detail },
                RemoteReason::Incompatible => MuxyError::Incompatible { destination, detail },
                RemoteReason::Timeout => MuxyError::Timeout { destination, detail },
                RemoteReason::UnexpectedOutput => {
                    MuxyError::UnexpectedOutput { destination, detail }
                }
                RemoteReason::BridgeFailed => MuxyError::BridgeFailed { destination, detail },
                RemoteReason::NotRunning |
                RemoteReason::HostKeyUnknown |
                RemoteReason::HostKeyChanged |
                RemoteReason::AuthenticationFailed |
                RemoteReason::SshMissing => MuxyError::Ssh { destination, detail },
            }
        }
        ClientError::VersionUnsupported => MuxyError::Incompatible {
            destination: destination.to_string(),
            detail: "the running server speaks a protocol this build cannot speak".to_string(),
        },
        ClientError::Timeout => MuxyError::Timeout {
            destination: destination.to_string(),
            detail: "request timed out".to_string(),
        },
        ClientError::Disconnected => {
            MuxyError::Disconnected { destination: destination.to_string() }
        }
        other => MuxyError::Request { detail: other.to_string() },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unreachable_and_timeout_are_recoverable() {
        assert!(
            MuxyError::Unreachable { destination: "api".into(), detail: "x".into() }.recoverable()
        );
        assert!(MuxyError::Timeout { destination: "api".into(), detail: "x".into() }.recoverable());
        assert!(
            MuxyError::BridgeFailed { destination: "api".into(), detail: "x".into() }.recoverable()
        );
    }

    #[test]
    fn auth_and_missing_muxy_are_not_recoverable() {
        assert!(!MuxyError::NotInstalled { destination: "api".into() }.recoverable());
        assert!(!MuxyError::Ssh { destination: "api".into(), detail: "x".into() }.recoverable());
    }
}
