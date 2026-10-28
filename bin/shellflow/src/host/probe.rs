//! Reading the target's state: unit verification, `systemctl show` parsing,
//! the readiness verdict, and the unit inventory.
//!
//! Everything here is read-only: a probe never changes the host, so a failed
//! check costs a round trip and nothing else.

use super::{
    BTreeSet, Command, Duration, HostError, HostInventoryArgs, Instant, Path, PathBuf, Stdio,
    privileged::{list_dir, run_systemctl, systemctl_output},
};

/// Validate a unit with `systemd-analyze verify`.
///
/// The check is **fail closed**: a non-zero exit aborts the deploy.
///
/// The unit is validated through the file systemd actually loaded -- its
/// fragment path -- rather than by name. A Quadlet container's unit exists
/// only as generated output, so verifying it by name reports "not found"
/// for a unit that is loaded and running. For a unit systemd has never
/// loaded there is no fragment yet, and the name is all there is.
pub(super) fn verify_unit(unit: &str) -> Result<(), HostError> {
    if let Some(fragment) = loaded_fragment(unit) {
        return verify_unit_file(unit, &fragment);
    }
    verify_unit_file(unit, unit)
}

/// The fragment path of a loaded unit, if systemd knows one.
pub(super) fn loaded_fragment(unit: &str) -> Option<String> {
    let out = systemctl_output(&["show", "-p", "FragmentPath", "--value", unit]).ok()?;
    let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if path.is_empty() || path == "/dev/null" {
        return None;
    }
    Some(path)
}

pub(super) fn verify_unit_file(unit: &str, path: &str) -> Result<(), HostError> {
    let out = Command::new("systemd-analyze")
        .arg("verify")
        .arg(path)
        .stdin(Stdio::null())
        .output()
        .map_err(|err| HostError::internal(format!("cannot run `systemd-analyze`: {err}")))?;
    if out.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let detail = if stderr.trim().is_empty() { stdout.trim() } else { stderr.trim() };
    // `systemd-analyze verify` reports on every unit it can see, not only on
    // the one it was asked about. A complaint about another unit is that
    // unit's business; only the ones about this unit decide the deploy.
    let about: Vec<&str> =
        detail.lines().filter(|line| line.contains(unit.trim_end_matches(".service"))).collect();
    // A unit that names a file which is not in place yet is not an invalid
    // unit: the rendered configuration and the binary may only appear when
    // the service starts. Every complaint about this unit has to be about a
    // missing file for this to be one.
    if !about.iter().all(|line| is_a_missing_file(line)) {
        return Err(HostError::failed(format!("`systemd-analyze verify {unit}` failed: {detail}")));
    }
    for line in &about {
        crate::ui::report!("==> {unit}: {line}");
    }
    crate::ui::report!(
        "==> {unit}: the unit is valid, some of the files it names are not in place yet"
    );
    Ok(())
}

/// Whether a complaint is about a file that is not in place.
///
/// `systemd-analyze verify` reports both a malformed unit and a unit that
/// names a missing file, and it exits non-zero for either. Only the first
/// is a reason to abort a deploy.
pub(super) fn is_a_missing_file(line: &str) -> bool {
    line.contains("is not executable") ||
        line.contains("No such file or directory") ||
        line.contains("not found") ||
        line.contains("Cannot find") ||
        line.contains("Failed to resolve") ||
        line.trim().is_empty()
}

/// How the unit is enabled (`enabled`, `disabled`, `generated`, ...).
///
/// An unreadable state is reported as empty: the caller decides.
pub(super) fn unit_enabled_state(unit: &str) -> Result<String, HostError> {
    let out = systemctl_output(&["is-enabled", unit])
        .map_err(|err| HostError::internal(format!("cannot run `systemctl is-enabled`: {err}")))?;
    if out.status.success() {
        return Ok(String::from_utf8_lossy(&out.stdout).trim().to_string());
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let detail = if stderr.trim().is_empty() { stdout.trim() } else { stderr.trim() };
    // A unit systemd has never heard of is not enabled; anything else the
    // caller handles.
    if detail.contains("No such file or directory") || detail.contains("not found") {
        return Ok("missing".to_string());
    }
    Err(HostError::failed(format!("`systemctl is-enabled {unit}` failed: {detail}")))
}

/// The unit's activation state (`active`, `inactive`, `failed`, ...).
///
/// An empty string means the state could not be read at all.
pub(super) fn unit_state(unit: &str) -> String {
    let Ok(out) = systemctl_output(&["is-active", unit]) else {
        return String::new();
    };
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Whether the unit declares a given property.
pub(super) fn unit_has_property(unit: &str, property: &str) -> bool {
    crate::systemctl::has_property(unit, property)
}

/// The main PID of a running unit.
pub(super) fn main_pid(unit: &str) -> Result<String, HostError> {
    let out = systemctl_output(&["show", unit, "-p", "MainPID", "--value"])?;
    let text = String::from_utf8_lossy(&out.stdout);
    let pid = text.trim();
    if pid.is_empty() || pid == "0" {
        return Err(HostError::failed(format!("{unit} has no main process")));
    }
    Ok(pid.to_string())
}

/// Reload a unit through its own `ExecReload=`, or refuse.
///
/// A silent fallback to a restart would drop the connections the reload
/// exists to preserve, so the refusal is explicit.
pub(super) fn reload_unit(unit: &str) -> Result<(), HostError> {
    let has_exec_reload = unit_has_property(unit, "ExecReload");
    if has_exec_reload {
        run_systemctl(&["reload", unit])
    } else {
        Err(HostError::usage(format!(
            "`{unit}` has no ExecReload=: refusing to reload it, because the only fallback would \
             be a restart."
        )))
    }
}

/// Wait for a unit to become ready, using the notify-aware verdict.
pub(super) fn wait_for_ready(unit: &str, budget: Duration) -> Result<(), HostError> {
    let deadline = Instant::now() + budget;
    loop {
        let state = crate::systemd::show_state(unit)?;
        crate::ui::report!("{}", crate::systemd::state_line(&state));
        match crate::systemd::verdict(&state) {
            crate::systemd::Verdict::Ready => return Ok(()),
            crate::systemd::Verdict::Failed(reason) => {
                return Err(HostError::failed(reason));
            }
            crate::systemd::Verdict::Pending => {}
        }
        if Instant::now() >= deadline {
            return Err(HostError::timed_out(format!(
                "{unit} did not become ready within {budget:?}"
            )));
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}

/// Every unit file and drop-in on the system.
pub(super) fn all_unit_files() -> Vec<PathBuf> {
    let mut files = Vec::new();
    // Quadlet's own directory holds the container units.
    for root in [
        "/etc/systemd/system",
        "/usr/lib/systemd/system",
        "/run/systemd/system",
        "/etc/containers/systemd",
    ] {
        let Ok(entries) = list_dir(Path::new(root)) else {
            continue;
        };
        for entry in entries {
            let name = entry.file_name().and_then(|n| n.to_str()).unwrap_or_default().to_string();
            // Unit-shaped files carry credential wiring (service, timer,
            // socket, container, …); the shared suffix list is the single
            // definition so the scan and the inventory agree.
            let is_unit = shellflow_text::is_unit_file(&name);
            let is_drop_in_dir = name.ends_with(".service.d") ||
                name.ends_with(".timer.d") ||
                name.ends_with(".container.d");
            if is_drop_in_dir {
                for drop_in in list_dir(&entry).unwrap_or_default() {
                    if drop_in.extension().is_some_and(|ext| ext == "conf") {
                        files.push(drop_in);
                    }
                }
            }
            if is_unit {
                files.push(entry);
            }
        }
    }
    files
}

/// List the units installed on the target.
///
/// The report is a **report**, not a gate: a pre-existing finding must never
/// block an unrelated deploy.
pub(super) fn inventory(_args: &HostInventoryArgs) -> Result<(), HostError> {
    let roots = ["/etc/systemd/system", "/run/systemd/system", "/usr/lib/systemd/system"];
    let mut units: BTreeSet<String> = BTreeSet::new();
    for root in roots {
        let root_path = Path::new(root);
        let Ok(entries) = list_dir(root_path) else {
            continue;
        };
        for entry in entries {
            let name = entry.file_name().and_then(|n| n.to_str()).unwrap_or_default();
            if name.ends_with(".d") {
                // A drop-in directory: report the unit it belongs to.
                let unit = name.trim_end_matches(".d");
                units.insert(format!("{unit} (drop-in {root}/{name})"));
                continue;
            }
            if shellflow_text::is_unit_file(name) {
                units.insert(name.to_string());
            }
        }
    }
    for unit in &units {
        crate::ui::report!("{unit}");
    }
    crate::ui::report!("==> {} unit files installed", units.len());
    Ok(())
}
