//! Event-driven systemd unit state over D-Bus.
//!
//! With the `dbus` feature the `systemd watch` helper subscribes to systemd's
//! `PropertiesChanged` signal instead of polling, so a state change is picked
//! up the moment it happens rather than up to one poll interval later.
//!
//! The feature is **off by default** on purpose: the standard build stays a
//! single static binary with no D-Bus dependency, and the CLI path produces
//! exactly the same output by polling. The D-Bus path is an optimisation for
//! hosts where a D-Bus connection is available and the latency matters.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use futures_util::StreamExt;
use zbus::{
    Connection, OwnedObjectPath, OwnedVariant, Variant,
    fdo::PropertiesProxy,
    names::{BusName, InterfaceName},
};

use crate::systemd::{EXIT_TIMEOUT, SystemdError, UnitState, Verdict, state_line, verdict};

const MANAGER_SERVICE: &str = "org.freedesktop.systemd1";
const UNIT_INTERFACE: &str = "org.freedesktop.systemd1.Unit";

/// The systemd manager object.
#[zbus::proxy(
    interface = "org.freedesktop.systemd1.Manager",
    default_service = "org.freedesktop.systemd1",
    default_path = "/org/freedesktop/systemd1"
)]
trait Manager {
    /// Look up a unit by name, returning its D-Bus object path.
    fn get_unit(&self, name: &str) -> zbus::Result<OwnedObjectPath>;
}

/// Watch a unit over D-Bus until it is ready or the budget expires.
///
/// The output is the same machine-readable state line the polling path
/// prints, so a caller cannot tell the two apart.
pub(crate) async fn watch(
    unit: &str,
    deadline: Instant,
    poll_interval: Duration,
) -> Result<(), SystemdError> {
    let conn = Connection::system()
        .await
        .map_err(|err| SystemdError::internal(format!("cannot reach the system bus: {err}")))?;

    let manager = ManagerProxy::builder(&conn).build().await.map_err(|err| {
        SystemdError::internal(format!("cannot reach the systemd manager: {err}"))
    })?;
    let path = manager
        .get_unit(unit)
        .await
        .map_err(|err| SystemdError::internal(format!("unit `{unit}` is unknown: {err}")))?;

    let destination = BusName::try_from(MANAGER_SERVICE)
        .map_err(|err| SystemdError::internal(format!("invalid bus name: {err}")))?;
    let props = PropertiesProxy::builder(&conn)
        .destination(destination)
        .path(path.as_ref())
        .build()
        .await
        .map_err(|err| SystemdError::internal(format!("cannot build a properties proxy: {err}")))?;

    let mut changes = props.receive_properties_changed().await.map_err(|err| {
        SystemdError::internal(format!("cannot subscribe to state changes: {err}"))
    })?;

    let mut last = String::new();
    loop {
        let interface = InterfaceName::try_from(UNIT_INTERFACE)
            .map_err(|err| SystemdError::internal(format!("invalid interface name: {err}")))?;
        let all = props.get_all(interface).await.map_err(|err| {
            SystemdError::internal(format!("cannot read the unit properties: {err}"))
        })?;
        let state = state_from_properties(&all);
        let line = state_line(&state);
        if line != last {
            println!("{line}");
            last = line;
        }
        if verdict(&state) == Verdict::Ready {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(SystemdError {
                message: format!("`{unit}` did not become ready before the deadline"),
                code: EXIT_TIMEOUT,
            });
        }
        // Wait for the next change, but never longer than the poll interval:
        // D-Bus signals can be missed (a reconnect, a dropped bus), and the
        // polling path is the guaranteed fallback.
        let remaining = deadline.saturating_duration_since(Instant::now());
        let wait = poll_interval.min(remaining.max(Duration::from_millis(1)));
        tokio::select! {
            msg = changes.next() => {
                if msg.is_none() {
                    // The stream ended (the bus closed): fall back to polling.
                    return poll_until_ready(unit, deadline, poll_interval, last).await;
                }
            }
            () = tokio::time::sleep(wait) => {}
        }
    }
}

/// The polling fallback, used when the D-Bus stream ends early.
async fn poll_until_ready(
    unit: &str,
    deadline: Instant,
    poll_interval: Duration,
    mut last: String,
) -> Result<(), SystemdError> {
    loop {
        let state = crate::systemd::show_state(unit)?;
        let line = state_line(&state);
        if line != last {
            println!("{line}");
            last = line;
        }
        if verdict(&state) == Verdict::Ready {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(SystemdError {
                message: format!("`{unit}` did not become ready before the deadline"),
                code: EXIT_TIMEOUT,
            });
        }
        tokio::time::sleep(poll_interval).await;
    }
}

/// The text of a D-Bus string property (empty for any other type).
fn value_text(value: &OwnedVariant) -> String {
    // `OwnedVariant` derefs to `Variant`; bind the inner value once so the match
    // does not need a double dereference.
    let inner: &Variant<'_> = value;
    match inner {
        Variant::Str(text) => text.as_str().to_string(),
        _ => String::new(),
    }
}

/// Build a [`UnitState`] from a D-Bus property map.
fn state_from_properties(props: &HashMap<String, OwnedVariant>) -> UnitState {
    let text = |key: &str| -> String { props.get(key).map_or_else(String::new, value_text) };
    UnitState {
        unit_type: text("Type"),
        active: text("ActiveState"),
        sub: text("SubState"),
        result: text("Result"),
        status: text("StatusText"),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use zbus::{OwnedVariant, Variant};

    use super::state_from_properties;

    /// An owned D-Bus string value.
    fn owned(text: &str) -> OwnedVariant {
        Variant::from(text).try_into_owned().expect("owned value")
    }

    #[test]
    fn reads_the_unit_state_from_a_property_map() {
        let mut props: HashMap<String, OwnedVariant> = HashMap::new();
        props.insert("Type".to_string(), owned("notify"));
        props.insert("ActiveState".to_string(), owned("active"));
        props.insert("SubState".to_string(), owned("running"));
        props.insert("Result".to_string(), owned("success"));
        props.insert("StatusText".to_string(), owned("syncing 42%"));
        let state = state_from_properties(&props);
        assert_eq!(state.unit_type, "notify");
        assert_eq!(state.active, "active");
        assert_eq!(state.sub, "running");
        assert_eq!(state.result, "success");
        assert_eq!(state.status, "syncing 42%");
    }

    #[test]
    fn a_missing_property_is_empty_not_a_panic() {
        let props: HashMap<String, OwnedVariant> = HashMap::new();
        let state = state_from_properties(&props);
        assert!(state.active.is_empty());
        assert!(state.status.is_empty());
    }
}
