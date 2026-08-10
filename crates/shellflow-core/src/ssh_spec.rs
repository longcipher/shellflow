//! Parsing and rendering of `[user@]host[:port]` SSH destinations.

use crate::error::ParseError;

/// A parsed `[user@]host[:port]` SSH destination.
///
/// The destination is rendered back into `ssh`/`rsync` argv fragments by
/// [`to_ssh_args`](Self::to_ssh_args) and
/// [`to_rsync_args`](Self::to_rsync_args).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SshSpec {
    /// Optional login user (as in `deploy@host`).
    pub user: Option<String>,
    /// Host name or IP address.
    pub host: String,
    /// Optional non-default port.
    pub port: Option<u16>,
}

impl SshSpec {
    /// Parse a destination string of the form `[user@]host[:port]`.
    ///
    /// IPv6 addresses are not supported in v1; use `~/.ssh/config` for exotic
    /// destinations.
    ///
    /// # Errors
    ///
    /// Returns a [`ParseError`] when the spec has no host, an empty user, or a
    /// non-numeric / out-of-range port.
    pub fn parse(spec: &str) -> Result<Self, ParseError> {
        let (user, rest) = match spec.split_once('@') {
            Some((user, rest)) => {
                if user.is_empty() {
                    return Err(ParseError::InvalidSshSpec {
                        line: 0,
                        spec: spec.to_string(),
                        reason: "empty user before `@`".to_string(),
                    });
                }
                (Some(user.to_string()), rest)
            }
            None => (None, spec),
        };

        let (host, port) = match rest.rsplit_once(':') {
            Some((host, port)) => {
                let port = port.parse::<u16>().map_err(|_| ParseError::InvalidSshSpec {
                    line: 0,
                    spec: spec.to_string(),
                    reason: format!("invalid port `{port}`"),
                })?;
                (host.to_string(), Some(port))
            }
            None => (rest.to_string(), None),
        };

        if host.is_empty() {
            return Err(ParseError::InvalidSshSpec {
                line: 0,
                spec: spec.to_string(),
                reason: "empty host".to_string(),
            });
        }

        Ok(Self { user, host, port })
    }

    /// The `user@host` destination as passed to `rsync`.
    #[must_use]
    pub fn dest(&self) -> String {
        match &self.user {
            Some(user) => format!("{user}@{}", self.host),
            None => self.host.clone(),
        }
    }

    /// The `-e 'ssh -p N'` transport argument for `rsync`, when a custom port
    /// is set.
    #[must_use]
    pub fn rsync_remote_shell(&self) -> Option<String> {
        self.port.map(|port| format!("ssh -p {port}"))
    }

    /// Arguments for `ssh`: `-p <port>` when set, then `user@host`.
    #[must_use]
    pub fn to_ssh_args(&self) -> Vec<String> {
        let mut args = Vec::with_capacity(3);
        if let Some(port) = self.port {
            args.push("-p".to_string());
            args.push(port.to_string());
        }
        args.push(self.dest());
        args
    }
}

#[cfg(test)]
mod tests {
    use super::SshSpec;

    fn parse(spec: &str) -> Result<SshSpec, String> {
        SshSpec::parse(spec).map_err(|e| e.to_string())
    }

    #[test]
    fn parses_plain_host() -> Result<(), String> {
        let spec = parse("10.0.0.1")?;
        assert_eq!(spec.user, None);
        assert_eq!(spec.host, "10.0.0.1");
        assert_eq!(spec.port, None);
        Ok(())
    }

    #[test]
    fn parses_user_host() -> Result<(), String> {
        let spec = parse("deploy@10.0.0.1")?;
        assert_eq!(spec.user.as_deref(), Some("deploy"));
        assert_eq!(spec.host, "10.0.0.1");
        assert_eq!(spec.port, None);
        Ok(())
    }

    #[test]
    fn parses_user_host_port() -> Result<(), String> {
        let spec = parse("deploy@10.0.0.1:2222")?;
        assert_eq!(spec.user.as_deref(), Some("deploy"));
        assert_eq!(spec.host, "10.0.0.1");
        assert_eq!(spec.port, Some(2222));
        Ok(())
    }

    #[test]
    fn rejects_empty_user() {
        assert!(SshSpec::parse("@host").is_err());
    }

    #[test]
    fn rejects_empty_host() {
        assert!(SshSpec::parse("user@").is_err());
        assert!(SshSpec::parse(":22").is_err());
    }

    #[test]
    fn rejects_bad_port() {
        assert!(SshSpec::parse("host:not-a-port").is_err());
        assert!(SshSpec::parse("host:99999").is_err());
    }

    #[test]
    fn renders_ssh_args_with_port() -> Result<(), String> {
        let spec = parse("deploy@10.0.0.1:2222")?;
        assert_eq!(spec.to_ssh_args(), vec!["-p", "2222", "deploy@10.0.0.1"]);
        Ok(())
    }

    #[test]
    fn renders_ssh_args_without_port() -> Result<(), String> {
        let spec = parse("10.0.0.1")?;
        assert_eq!(spec.to_ssh_args(), vec!["10.0.0.1"]);
        Ok(())
    }

    #[test]
    fn renders_rsync_dest_and_remote_shell() -> Result<(), String> {
        let spec = parse("deploy@10.0.0.1:2222")?;
        assert_eq!(spec.dest(), "deploy@10.0.0.1");
        assert_eq!(spec.rsync_remote_shell().as_deref(), Some("ssh -p 2222"));
        Ok(())
    }
}
