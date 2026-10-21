//! `shellflow service status --all` — the fleet view.
//!
//! Answering "is the fleet healthy?" meant running `systemctl status` on
//! every host by hand, or reading the last line of every deploy log. Both
//! are per-host and per-service, and neither says anything about the fleet.
//!
//! This subcommand reads the **repository** as the fleet's description: the
//! playbooks declare the hosts (`@server`), and `services/<svc>/` declares
//! the services. One SSH round trip per host then answers for every service
//! at once, and the result is one table.
//!
//! Nothing here is specific to this repository's layout: `--host` and
//! `--service` name the fleet explicitly when the repository is not the
//! description to use.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

use crate::{
    cli::ServiceStatusArgs,
    rbatch::{Batch, SshDest},
    service::ServiceError,
    service::ServiceError::Other,
};
use shellflow_core::SshSpec;

/// The state of one unit on one host.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct UnitState {
    /// The systemd unit name.
    unit: String,
    /// `ActiveState` (`active`, `inactive`, `failed`).
    active: String,
    /// `SubState` (`running`, `dead`).
    sub: String,
    /// `LoadState` (`loaded`, `not-found`).
    load: String,
}

/// Run `service status`.
///
/// # Errors
///
/// Returns [`ServiceError::Transport`] when a host is unreachable and
/// [`ServiceError::Other`] when the request is malformed.
pub(crate) fn status(args: &ServiceStatusArgs) -> Result<(), ServiceError> {
    let hosts = resolve_hosts(args)?;
    if hosts.is_empty() {
        return Err(Other(eyre::eyre!(
            "service status: name a host with --host, or pass --all to use the hosts the \
             repository declares"
        )));
    }
    let mut rows: Vec<(String, String, UnitState)> = Vec::new();
    for (alias, dest) in &hosts {
        let units = units_for_host(args, alias)?;
        if units.is_empty() {
            // Nothing to ask about: report that the host answered at all.
            let mut batch = Batch::new();
            batch.section("ping", "systemctl --version | head -1");
            match batch.run_dest(dest) {
                Ok(sections) => {
                    let body = sections.get("ping").map_or("", |s| s.body.as_str());
                    rows.push((
                        alias.clone(),
                        String::new(),
                        UnitState {
                            unit: "-".to_string(),
                            active: "reachable".to_string(),
                            sub: body.to_string(),
                            load: "-".to_string(),
                        },
                    ));
                }
                Err(err) => {
                    println!("[FAIL] {alias}: {err}");
                }
            }
            continue;
        }

        let mut batch = Batch::new();
        batch.section(
            "units",
            &format!(
                "systemctl show {} -p Id,ActiveState,SubState,LoadState",
                units
                    .iter()
                    .map(|u| shellflow_core::env::shell_quote_single(u))
                    .collect::<Vec<_>>()
                    .join(" ")
            ),
        );
        match batch.run_dest(dest) {
            Ok(sections) => {
                for state in parse_units(sections.get("units").map_or("", |s| s.body.as_str())) {
                    rows.push((alias.clone(), state.unit.clone(), state));
                }
            }
            Err(err) => {
                println!("[FAIL] {alias}: {err}");
            }
        }
    }

    print_table(&rows);
    Ok(())
}

/// Print the table of unit states.
fn print_table(rows: &[(String, String, UnitState)]) {
    if rows.is_empty() {
        println!("(no units to report)");
        return;
    }
    let header = vec!["HOST".to_string(), "UNIT".to_string(), "ACTIVE".to_string(), "SUB".to_string(), "LOAD".to_string()];
    let mut widths = header.iter().map(|h| h.len()).collect::<Vec<_>>();
    let mut body: Vec<Vec<String>> = Vec::new();
    for (host, _service, state) in rows {
        let cells = vec![
            host.clone(),
            state.unit.clone(),
            state.active.clone(),
            state.sub.clone(),
            state.load.clone(),
        ];
        for (idx, cell) in cells.iter().enumerate() {
            widths[idx] = widths[idx].max(cell.len());
        }
        body.push(cells);
    }
    let render = |cells: &[String]| {
        cells
            .iter()
            .enumerate()
            .map(|(idx, cell)| {
                if idx + 1 == cells.len() {
                    cell.clone()
                } else {
                    format!("{cell:<width$}", width = widths[idx])
                }
            })
            .collect::<Vec<_>>()
            .join("  ")
    };
    println!("{}", render(&header));
    for cells in &body {
        println!("{}", render(cells));
    }
}

/// Parse the `systemctl show` output for several units.
///
/// `systemctl show` prints one `Key=Value` block per unit, separated by a
/// blank line, each carrying its own `Id=`.
fn parse_units(show: &str) -> Vec<UnitState> {
    let mut out: Vec<UnitState> = Vec::new();
    let mut current = UnitState::default();
    for line in show.lines() {
        if line.trim().is_empty() {
            if !current.unit.is_empty() {
                out.push(std::mem::take(&mut current));
            }
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key.trim() {
            "Id" => current.unit = value.to_string(),
            "ActiveState" => current.active = value.to_string(),
            "SubState" => current.sub = value.to_string(),
            "LoadState" => current.load = value.to_string(),
            _ => {}
        }
    }
    if !current.unit.is_empty() {
        out.push(current);
    }
    out
}

/// The hosts to report on: the explicit ones plus, with `--all`, the hosts
/// the repository's playbooks declare.
fn resolve_hosts(args: &ServiceStatusArgs) -> Result<Vec<(String, SshDest)>, ServiceError> {
    let mut hosts: BTreeMap<String, SshDest> = BTreeMap::new();
    for host in &args.hosts {
        let dest = SshDest::Host(host.clone());
        hosts.insert(host.clone(), dest);
    }
    if args.all {
        for (alias, spec) in repo_hosts(&args.repo)? {
            hosts.entry(alias).or_insert_with(|| match SshSpec::parse(&spec) {
                Ok(spec) => SshDest::Spec(spec),
                Err(_) => SshDest::Host(spec),
            });
        }
    }
    Ok(hosts.into_iter().collect())
}

/// The units to report on for one host.
///
/// The repository knows which service belongs to which host: the playbook
/// that deploys a service names both the service (`SVC=`) and the host
/// (`@server`/`@remote`). Reporting only the services a host is supposed
/// to run is what makes a missing unit visible; a unit that is not
/// installed on a host that never wanted it is noise.
fn units_for_host(args: &ServiceStatusArgs, host: &str) -> Result<Vec<String>, ServiceError> {
    if !args.services.is_empty() {
        return Ok(args.services.iter().map(|s| format!("{s}.service")).collect());
    }
    let mapping = repo_fleet(&args.repo)?;
    if let Some(services) = mapping.get(host) {
        let units: Vec<String> = services.iter().map(|s| format!("{s}.service")).collect();
        if !units.is_empty() {
            return Ok(units);
        }
    }
    repo_units(&args.repo)
}

/// The hosts the repository's playbooks declare.
fn repo_hosts(repo: &Path) -> Result<Vec<(String, String)>, ServiceError> {
    let dir = repo.join("playbooks");
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    for script in playbook_scripts(&dir)? {
        let Ok(text) = std::fs::read_to_string(&script) else {
            continue;
        };
        for (alias, spec) in declared_servers(&text) {
            out.insert(alias, spec);
        }
    }
    Ok(out.into_iter().collect())
}

/// Which service each host is supposed to run.
///
/// The mapping comes from the playbooks: the service a playbook installs
/// (`SVC=`) and the hosts it targets (`@server`/`@remote`).
fn repo_fleet(repo: &Path) -> Result<BTreeMap<String, Vec<String>>, ServiceError> {
    let dir = repo.join("playbooks");
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for script in playbook_scripts(&dir)? {
        let Ok(text) = std::fs::read_to_string(&script) else {
            continue;
        };
        let Some(service) = extract_service(&text) else {
            continue;
        };
        let mut targets: BTreeSet<String> = BTreeSet::new();
        for (alias, _) in declared_servers(&text) {
            targets.insert(alias);
        }
        for target in remote_targets(&text) {
            targets.insert(target);
        }
        for target in targets {
            out.entry(target).or_default().insert(service.clone());
        }
    }
    Ok(out.into_iter().map(|(host, services)| (host, services.into_iter().collect())).collect())
}

/// The playbook scripts of a repository, in a stable order.
fn playbook_scripts(dir: &Path) -> Result<Vec<PathBuf>, ServiceError> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(Vec::new());
    };
    let mut scripts: Vec<PathBuf> = entries
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "sh"))
        .collect();
    scripts.sort();
    Ok(scripts)
}

/// The `@server` declarations of a playbook: alias to ssh spec.
fn declared_servers(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim_start();
        let Some(payload) = trimmed.strip_prefix("# @server") else {
            continue;
        };
        let mut tokens = payload.split_whitespace();
        let (Some(alias), Some(spec)) = (tokens.next(), tokens.next()) else {
            continue;
        };
        out.push((alias.to_string(), spec.to_string()));
    }
    out
}

/// The targets the `@remote` steps of a playbook use.
fn remote_targets(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim_start();
        let Some(payload) = trimmed.strip_prefix("# @remote") else {
            continue;
        };
        let target = payload.trim().trim_start_matches('@').trim();
        if !target.is_empty() {
            out.push(target.to_string());
        }
    }
    out
}

/// The service a playbook installs.
///
/// The playbooks name it in `SVC=`, either directly (`SVC=dufs`) or as the
/// default of a re-assignment (`SVC="${SVC:-dufs}"`).
fn extract_service(text: &str) -> Option<String> {
    for line in text.lines() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with("SVC=") {
            continue;
        }
        let value = trimmed.trim_start_matches("SVC=").trim();
        if let Some(rest) = value.strip_prefix("\"${SVC:-") {
            let name = rest.split('}').next().unwrap_or_default().trim();
            if !name.is_empty() {
                return Some(name.to_string());
            }
            continue;
        }
        let name: String = value
            .trim_matches(|c| c == '"' || c == '\'')
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
            .collect();
        if !name.is_empty() {
            return Some(name);
        }
    }
    None
}

/// The units of the services the repository holds.
fn repo_units(repo: &Path) -> Result<Vec<String>, ServiceError> {
    let dir = repo.join("services");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Ok(Vec::new());
    };
    let mut dirs: Vec<PathBuf> = entries
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    dirs.sort();
    let mut out = Vec::new();
    for service_dir in dirs {
        let Some(name) = service_dir.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        // The convention is `<svc>.service`; a service whose unit carries
        // another name falls back to the single `*.service` in the folder.
        let preferred = service_dir.join(format!("{name}.service"));
        if preferred.is_file() {
            out.push(format!("{name}.service"));
            continue;
        }
        let Ok(files) = std::fs::read_dir(&service_dir) else {
            continue;
        };
        let mut candidates: Vec<String> = files
            .filter_map(std::result::Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "service"))
            .filter_map(|path| {
                path.file_name().and_then(|n| n.to_str()).map(ToString::to_string)
            })
            .collect();
        candidates.sort();
        if let Some(unit) = candidates.first() {
            out.push(unit.clone());
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{extract_service, parse_units, repo_fleet, repo_hosts, repo_units};

    #[test]
    fn a_playbook_names_its_service() {
        assert_eq!(extract_service("# @server api api\nSVC=dufs\n"), Some("dufs".to_string()));
        assert_eq!(
            extract_service("SVC=\"${SVC:-dufs}\"\n"),
            Some("dufs".to_string())
        );
        assert_eq!(extract_service("# no service here\n"), None);
    }

    #[test]
    fn the_fleet_mapping_comes_from_the_playbooks() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("playbooks")).expect("dirs");
        std::fs::write(
            dir.path().join("playbooks/deploy-dufs.sh"),
            "# @server api api\nSVC=dufs\n# @remote api\n",
        )
        .expect("write");
        std::fs::write(
            dir.path().join("playbooks/deploy-rss.sh"),
            "# @server trade trade\nSVC=longfeeds\n# @remote trade\n",
        )
        .expect("write");
        let fleet = repo_fleet(dir.path()).expect("fleet");
        assert_eq!(fleet.get("api"), Some(&vec!["dufs".to_string()]));
        assert_eq!(fleet.get("trade"), Some(&vec!["longfeeds".to_string()]));
    }

    #[test]
    fn unit_states_are_parsed() {
        let show = "Id=dufs.service\nActiveState=active\nSubState=running\nLoadState=loaded\n\
                    \nId=nginx.service\nActiveState=inactive\nSubState=dead\nLoadState=not-found\n";
        let units = parse_units(show);
        assert_eq!(units.len(), 2);
        assert_eq!(units[0].unit, "dufs.service");
        assert_eq!(units[0].active, "active");
        assert_eq!(units[1].load, "not-found");
    }

    #[test]
    fn a_unit_block_without_a_trailing_blank_line_is_kept() {
        let show = "Id=a.service\nActiveState=active\n";
        let units = parse_units(show);
        assert_eq!(units.len(), 1);
        assert_eq!(units[0].unit, "a.service");
    }

    #[test]
    fn the_hosts_come_from_the_playbooks() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("playbooks")).expect("dirs");
        std::fs::write(
            dir.path().join("playbooks/deploy-a.sh"),
            "# @server api api\n# @server trade trade\n",
        )
        .expect("write");
        let hosts = repo_hosts(dir.path()).expect("hosts");
        assert_eq!(hosts.len(), 2);
        assert!(hosts.iter().any(|(a, s)| a == "api" && s == "api"));
    }

    #[test]
    fn the_units_come_from_the_service_folders() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("services/dufs")).expect("dirs");
        std::fs::create_dir_all(dir.path().join("services/rpxy")).expect("dirs");
        std::fs::write(dir.path().join("services/dufs/dufs.service"), "[Unit]\n").expect("write");
        std::fs::write(dir.path().join("services/rpxy/rpxy.service"), "[Unit]\n").expect("write");
        let units = repo_units(dir.path()).expect("units");
        assert_eq!(units, vec!["dufs.service".to_string(), "rpxy.service".to_string()]);
    }
}
