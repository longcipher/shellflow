//! Parsing and rendering of `[user@]host[:port]` SSH destinations.

use crate::error::ParseError;

/// A parsed `[user@]host[:port]` SSH destination.
///
/// The destination is rendered back into `ssh`/`rsync` argv fragments by
/// [`to_ssh_args`](Self::to_ssh_args) and
/// [`dest`](Self::dest) / [`rsync_remote_shell`](Self::rsync_remote_shell).
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
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
    /// An IPv6 literal is written in brackets, as `ssh` accepts it:
    /// `deploy@[2001:db8::1]:2222`. A bare IPv6 address without brackets is
    /// ambiguous (`::1` has no port to split off), so it is rejected rather
    /// than guessed at.
    ///
    /// # Errors
    ///
    /// Returns a [`ParseError`] when the spec has no host, an empty user, an
    /// unclosed `[`, a non-numeric / out-of-range port, or a user or host that
    /// contains characters outside `[A-Za-z0-9._-]` (`[0-9A-Fa-f:.]` inside
    /// brackets).
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
                if !is_valid_spec_component(user) {
                    return Err(ParseError::InvalidSshSpec {
                        line: 0,
                        spec: spec.to_string(),
                        reason: format!(
                            "invalid user `{user}` (allowed: letters, digits, `.`, `_`, `-`)"
                        ),
                    });
                }
                (Some(user.to_string()), rest)
            }
            None => (None, spec),
        };

        let (host, port) = match rest.strip_prefix('[') {
            Some(bracketed) => {
                let Some((host, tail)) = bracketed.split_once(']') else {
                    return Err(ParseError::InvalidSshSpec {
                        line: 0,
                        spec: spec.to_string(),
                        reason: "unclosed `[` in an IPv6 destination".to_string(),
                    });
                };
                if host.is_empty() || !is_ipv6_literal(host) {
                    return Err(ParseError::InvalidSshSpec {
                        line: 0,
                        spec: spec.to_string(),
                        reason: format!(
                            "invalid IPv6 address `{host}` (allowed: hex digits, `:`, `.`)"
                        ),
                    });
                }
                let port = if tail.is_empty() {
                    None
                } else {
                    let Some(raw) = tail.strip_prefix(':') else {
                        return Err(ParseError::InvalidSshSpec {
                            line: 0,
                            spec: spec.to_string(),
                            reason: format!("unexpected `{tail}` after `]`"),
                        });
                    };
                    Some(parse_port(raw, spec)?)
                };
                (host.to_string(), port)
            }
            None => match rest.rsplit_once(':') {
                Some((host, port)) => {
                    if host.contains(':') {
                        return Err(ParseError::InvalidSshSpec {
                            line: 0,
                            spec: spec.to_string(),
                            reason: format!(
                                "bare IPv6 address `{rest}` is ambiguous (use `[{rest}]` or `[addr]:port`)"
                            ),
                        });
                    }
                    (host.to_string(), Some(parse_port(port, spec)?))
                }
                None => (rest.to_string(), None),
            },
        };

        if host.is_empty() {
            return Err(ParseError::InvalidSshSpec {
                line: 0,
                spec: spec.to_string(),
                reason: "empty host".to_string(),
            });
        }
        if !self::host_is_well_formed(&host) {
            return Err(ParseError::InvalidSshSpec {
                line: 0,
                spec: spec.to_string(),
                reason: format!("invalid host `{host}` (allowed: letters, digits, `.`, `_`, `-`)"),
            });
        }

        Ok(Self { user, host, port })
    }

    /// The `user@host` destination as passed to `rsync`.
    ///
    /// An IPv6 host is rendered back in brackets, which is the only form
    /// `rsync` and `ssh` accept for a literal address.
    #[must_use]
    pub fn dest(&self) -> String {
        let host =
            if self.host.contains(':') { format!("[{}]", self.host) } else { self.host.clone() };
        match &self.user {
            Some(user) => format!("{user}@{host}"),
            None => host,
        }
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

/// Parse a port and reject `0`, which `ssh` treats as "default" but which a
/// playbook almost certainly did not mean.
fn parse_port(raw: &str, spec: &str) -> Result<u16, ParseError> {
    let port = raw.parse::<u16>().map_err(|_| ParseError::InvalidSshSpec {
        line: 0,
        spec: spec.to_string(),
        reason: format!("invalid port `{raw}`"),
    })?;
    if port == 0 {
        return Err(ParseError::InvalidSshSpec {
            line: 0,
            spec: spec.to_string(),
            reason: "invalid port `0` (must be 1-65535)".to_string(),
        });
    }
    Ok(port)
}

/// Whether a bracketed host is a plausible IPv6 literal.
///
/// Hex digits, `:` separators and `.` (for an embedded IPv4 tail) only: a
/// zone index (`%eth0`) and every shell metacharacter stay out, and the
/// address never reaches a shell unquoted in the first place.
fn is_ipv6_literal(host: &str) -> bool {
    host.contains(':') &&
        host.chars().all(|c| c.is_ascii_hexdigit() || matches!(c, ':' | '.')) &&
        host.chars().any(|c| c.is_ascii_hexdigit())
}

/// A host is a DNS name, an IPv4 literal, or a bracketed IPv6 literal.
fn host_is_well_formed(host: &str) -> bool {
    if host.contains(':') { is_ipv6_literal(host) } else { is_valid_spec_component(host) }
}

/// Whether a user or host component contains only characters that are valid in
/// a POSIX login name or a DNS host name.
///
/// The spec is never handed to a shell (it becomes one `ssh`/`rsync` argv
/// element), so this is not an injection guard — it is a correctness guard: a
/// host containing whitespace or a quote cannot be a real destination, and
/// accepting it produces an opaque `ssh` failure instead of a parse-time
/// diagnostic.
///
/// The rejected single- and double-dot names (`-`, `.`, `..`) need no
/// special case: a leading dot or dash is rejected outright, which subsumes
/// them.
fn is_valid_spec_component(component: &str) -> bool {
    if component.is_empty() {
        return false;
    }
    if component.starts_with('.') || component.starts_with('-') {
        return false;
    }
    component.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

#[cfg(test)]
mod tests {
    use super::{SshSpec, is_valid_spec_component};

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
    fn parses_a_bracketed_ipv6_literal() -> Result<(), String> {
        // `[addr]:port` is the only unambiguous IPv6 spelling: `::1:2222`
        // could be an address or an address plus a port.
        let spec = parse("deploy@[2001:db8::1]:2222")?;
        assert_eq!(spec.user.as_deref(), Some("deploy"));
        assert_eq!(spec.host, "2001:db8::1");
        assert_eq!(spec.port, Some(2222));
        assert_eq!(spec.dest(), "deploy@[2001:db8::1]");
        assert_eq!(spec.to_ssh_args(), vec!["-p", "2222", "deploy@[2001:db8::1]"]);

        let no_port = parse("[::1]")?;
        assert_eq!(no_port.host, "::1");
        assert_eq!(no_port.port, None);
        assert_eq!(no_port.dest(), "[::1]");
        Ok(())
    }

    #[test]
    fn a_malformed_bracket_form_is_rejected() {
        // `[zz]` matters: without the "must contain a colon" half of
        // `is_ipv6_literal` it falls through to the DNS-name rule and is
        // accepted as a host called `zz`.
        for bad in ["[::1", "[::1]x", "[::1]:", "[not:hex]:22", "[]:22", "[zz]:22"] {
            assert!(SshSpec::parse(bad).is_err(), "{bad} must be rejected");
        }
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
    fn rejects_a_host_or_user_that_is_not_a_valid_name() {
        // A whitespace- or quote-bearing component can never be a real
        // destination: accepting it produces an opaque `ssh` failure instead
        // of a parse-time diagnostic.
        for spec in ["web1 web2", "deploy user@host", "host;id", "host'", "ho st"] {
            assert!(SshSpec::parse(spec).is_err(), "`{spec}` must be rejected");
        }
    }

    #[test]
    fn rejects_empty_dotted_and_dashed_components() {
        for component in ["", "-", ".", "..", ".foo", "-foo"] {
            assert!(!is_valid_spec_component(component), "`{component}` must be rejected");
        }
        assert!(is_valid_spec_component("web1"));
        assert!(is_valid_spec_component("a-b_c.d9"));
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
    fn renders_the_rsync_destination() -> Result<(), String> {
        let spec = parse("deploy@10.0.0.1:2222")?;
        assert_eq!(spec.dest(), "deploy@10.0.0.1");
        assert_eq!(
            spec.to_ssh_args(),
            vec!["-p".to_string(), "2222".to_string(), "deploy@10.0.0.1".to_string()]
        );
        let plain = parse("deploy@10.0.0.1")?;
        assert_eq!(plain.to_ssh_args(), vec!["deploy@10.0.0.1".to_string()]);
        Ok(())
    }

    proptest::proptest! {
        /// A rendered spec parses back to exactly the same fields, so a
        /// `~/.ssh/config`-free destination survives the plan -> argv path
        /// unchanged.
        #[test]
        fn spec_round_trips_through_parse_and_render(
            user in "[a-z][a-z0-9_-]{0,12}",
            host in "[a-z0-9]([a-z0-9.-]{0,28}[a-z0-9])?",
            port in 1_u16..65535,
        ) {
            let rendered = format!("{user}@{host}:{port}");
            let spec = SshSpec::parse(&rendered).map_err(|e| TestCaseError::fail(e.to_string()))?;
            prop_assert_eq!(spec.user.as_deref(), Some(user.as_str()));
            prop_assert_eq!(&spec.host, &host);
            prop_assert_eq!(spec.port, Some(port));
            let dest = spec.dest();
            let want_dest = format!("{user}@{host}");
            prop_assert_eq!(&dest, &want_dest);
        }

        /// `to_ssh_args` is always 1 or 3 elements and ends with the
        /// destination: a host string can never grow the argv, which is what
        /// keeps `ssh` injection impossible even for exotic specs.
        #[test]
        fn ssh_argv_shape_is_fixed(
            spec in prop_oneof![
                "[a-z0-9]([a-z0-9.-]{0,28}[a-z0-9])?".prop_map(|host| host.to_owned()),
                ("[a-z][a-z0-9.-]{0,19}", 1_u16..65535)
                    .prop_map(|(host, port)| format!("{host}:{port}")),
            ],
        ) {
            let parsed = SshSpec::parse(&spec).map_err(|e| TestCaseError::fail(e.to_string()))?;
            let dest = parsed.dest();
            let args = parsed.to_ssh_args();
            let expected_len = if parsed.port.is_some() { 3 } else { 1 };
            prop_assert_eq!(args.len(), expected_len);
            prop_assert_eq!(args.last().map(String::as_str), Some(dest.as_str()));
            for arg in &args {
                prop_assert!(!arg.is_empty(), "empty ssh argument");
                prop_assert!(
                    !arg.contains(char::is_whitespace),
                    "argv element contains whitespace: {}",
                    arg
                );
            }
        }
    }

    use proptest::{
        prelude::{Strategy, TestCaseError, prop_assert, prop_assert_eq},
        prop_oneof,
    };
}
