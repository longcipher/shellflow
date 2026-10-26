//! Policy: which steps may use the muxy transport.
//!
//! The seam covers every command step, but **eligibility is by step class**,
//! so a playbook does not spawn twenty short-lived terminals for its asserts.

/// The `--transport` policy.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum TransportPolicy {
    /// Muxy where it works, ssh everywhere else (default).
    #[default]
    Auto,
    /// Every command step through muxy; fail fast when it is unavailable.
    Muxy,
    /// Never attempt muxy.
    Ssh,
}

/// The class of a command step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StepClass {
    /// A remote block (`@remote`): the long ones, the whole point.
    Remote,
    /// A service lifecycle step (`@service`).
    Service,
    /// A readiness wait (`@wait_active`) or reload.
    Wait,
    /// Reload of a unit.
    Reload,
    /// Builds and dumps that run for minutes (`@backup`, `@helper`,
    /// `@release`, `@build`, `@toolchain`, `@image`).
    LongHelper,
    /// Seconds-long probes (`@assert`, `@install`, `@credstore`,
    /// `@unit_inventory`).
    ShortHelper,
    /// Syntax check (`--check`): byte-exact stdin, no PTY, no session.
    Check,
}

impl StepClass {
    /// Whether this class may use muxy under `auto`.
    ///
    /// Short helpers stay on ssh: a session each would flood the operator's
    /// terminal list for no gain. `--transport muxy` overrides the filter.
    #[must_use]
    pub const fn eligible_auto(self) -> bool {
        match self {
            Self::Remote |
            Self::Service |
            Self::Wait |
            Self::Reload |
            Self::LongHelper |
            Self::Check => true,
            Self::ShortHelper => false,
        }
    }
}

/// Whether a step of `class` should run through muxy under `policy`.
#[must_use]
pub const fn should_use_muxy(policy: TransportPolicy, class: StepClass) -> bool {
    match policy {
        TransportPolicy::Ssh => false,
        TransportPolicy::Muxy => true,
        TransportPolicy::Auto => class.eligible_auto(),
    }
}

/// Parse `--transport` / `$SHELLFLOW_TRANSPORT`.
#[must_use]
pub fn parse_policy(flag: Option<&str>, env: Option<&str>) -> TransportPolicy {
    if let Some(flag) = flag {
        return match flag {
            "muxy" => TransportPolicy::Muxy,
            "ssh" => TransportPolicy::Ssh,
            _ => TransportPolicy::Auto,
        };
    }
    match env {
        Some("muxy") => TransportPolicy::Muxy,
        Some("ssh") => TransportPolicy::Ssh,
        _ => TransportPolicy::Auto,
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn auto_routes_long_steps_to_muxy_and_keeps_asserts_on_ssh() {
        assert!(should_use_muxy(TransportPolicy::Auto, StepClass::Remote));
        assert!(should_use_muxy(TransportPolicy::Auto, StepClass::Service));
        assert!(should_use_muxy(TransportPolicy::Auto, StepClass::Wait));
        assert!(should_use_muxy(TransportPolicy::Auto, StepClass::Reload));
        assert!(should_use_muxy(TransportPolicy::Auto, StepClass::LongHelper));
        assert!(!should_use_muxy(TransportPolicy::Auto, StepClass::ShortHelper));
    }

    #[test]
    fn forced_muxy_covers_every_class() {
        assert!(should_use_muxy(TransportPolicy::Muxy, StepClass::ShortHelper));
        assert!(!should_use_muxy(TransportPolicy::Ssh, StepClass::Remote));
    }

    #[test]
    fn the_flag_wins_over_the_environment() {
        assert_eq!(parse_policy(Some("ssh"), Some("muxy")), TransportPolicy::Ssh);
        assert_eq!(parse_policy(None, Some("muxy")), TransportPolicy::Muxy);
        assert_eq!(parse_policy(None, None), TransportPolicy::Auto);
    }

    #[test]
    fn every_spelling_of_every_policy_is_recognized() {
        // An explicit value must be honored in both channels: a typo'd value
        // degrades to `auto`, never to the other transport.
        assert_eq!(parse_policy(Some("muxy"), None), TransportPolicy::Muxy);
        assert_eq!(parse_policy(Some("ssh"), None), TransportPolicy::Ssh);
        assert_eq!(parse_policy(None, Some("ssh")), TransportPolicy::Ssh);
        assert_eq!(parse_policy(Some("MUXY"), None), TransportPolicy::Auto);
        assert_eq!(parse_policy(None, Some("")), TransportPolicy::Auto);
    }
}
