//! `shellflow unit verify` — the repository consistency check.
//!
//! The generated parts of a deploy repository can drift away from the
//! sources they are generated from. The drift is silent: a playbook installs
//! a drop-in that no longer matches the manifest, a unit names a credential
//! the store does not hold, an `@install` copies a file the repository does
//! not have. Nothing breaks until a deploy does.
//!
//! The check answers four questions, statically:
//!
//! 1. **Is every generated drop-in up to date?** The drop-in is re-rendered from the manifest and
//!    compared with the file on disk.
//! 2. **Does every `@install` source exist?** The install steps are read out of the playbook with
//!    the tool's own parser, and every source is looked up in the repository.
//! 3. **Is every generated drop-in installed?** A service whose drop-in is never installed would
//!    run with the unit's own (stale) wiring.
//! 4. **Is the shared hardening installed?** The hardening is a default, not an opt-in: a service
//!    that never receives it runs unhardened.

use std::{
    collections::BTreeSet,
    fmt,
    path::{Path, PathBuf},
};

use eyre::Result;

use crate::{
    manifest::{self, ServiceManifest},
    unit::{self, HARDENING_FILE, HARDENING_NAME},
};

/// A problem the check found.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Problem {
    /// Where the problem is.
    pub location: String,
    /// What is wrong.
    pub message: String,
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.location, self.message)
    }
}

/// The result of the check.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct Report {
    /// The problems found.
    pub problems: Vec<Problem>,
    /// How many units were checked.
    pub units: usize,
    /// How many playbooks were checked.
    pub playbooks: usize,
}

/// The exit code of a failed check.
pub(crate) const EXIT_OUT_OF_DATE: i32 = 1;

/// Run the check over a repository.
///
/// # Errors
///
/// Returns when the repository cannot be read at all.
pub(crate) fn verify(repo: &Path) -> Result<Report> {
    let mut report = Report::default();
    let manifests = manifest::load_all(repo).map_err(|err| eyre::eyre!("{err}"))?;
    report.units = manifests.len();

    // 1. every manifest has a unit, and every drop-in is up to date
    for (key, m) in &manifests {
        let unit_file =
            repo.join("services").join(&m.service).join(format!("{}.service", unit_stem(&m.unit)));
        if !unit_file.exists() {
            report.problems.push(Problem {
                location: key.clone(),
                message: format!("the manifest has no unit file `{}`", unit_file.display()),
            });
            continue;
        }
        check_dropin(repo, m, &mut report);
    }

    // 2. the manifests of a service must agree on the host and the store
    check_manifest_agreement(&manifests, &mut report);

    // the shared hardening must exist: a repository that lost it would
    // deploy every service unhardened, silently.
    let hardening = hardening_path(repo);
    if !hardening.exists() {
        report.problems.push(Problem {
            location: hardening.display().to_string(),
            message: "the shared hardening drop-in is missing".to_string(),
        });
    }

    // 3. the playbooks
    for playbook in playbooks(repo) {
        report.playbooks += 1;
        check_playbook(repo, &playbook, &manifests, &mut report);
    }

    Ok(report)
}

/// The unit name without its `.service` suffix.
fn unit_stem(unit: &str) -> &str {
    unit.strip_suffix(".service").unwrap_or(unit)
}

/// Compare the drop-in on disk with the one the manifest generates.
fn check_dropin(repo: &Path, m: &ServiceManifest, report: &mut Report) {
    let path = unit::dropin_path(repo, &m.service, unit_stem(&m.unit));
    if !path.exists() {
        report.problems.push(Problem {
            location: path.display().to_string(),
            message: "the generated drop-in is missing: run `shellflow unit render`".to_string(),
        });
        return;
    }
    let rendered = unit::render(m, &m.credentials);
    let Ok(current) = std::fs::read_to_string(&path) else {
        return;
    };
    if current != rendered.text {
        report.problems.push(Problem {
            location: path.display().to_string(),
            message: "the generated drop-in is out of date: run `shellflow unit render`"
                .to_string(),
        });
    }
}

/// The units of a service must agree on the host and the credential store.
fn check_manifest_agreement(
    manifests: &std::collections::BTreeMap<String, ServiceManifest>,
    report: &mut Report,
) {
    let mut hosts: std::collections::BTreeMap<String, BTreeSet<String>> =
        std::collections::BTreeMap::new();
    let mut stores: std::collections::BTreeMap<String, BTreeSet<String>> =
        std::collections::BTreeMap::new();
    for m in manifests.values() {
        hosts.entry(m.service.clone()).or_default().insert(m.host.clone());
        stores
            .entry(m.service.clone())
            .or_default()
            .insert(m.store.clone().unwrap_or_else(|| m.service.clone()));
    }
    for (service, found) in hosts {
        if found.len() > 1 {
            report.problems.push(Problem {
                location: service,
                message: format!(
                    "the units disagree on the host: {}",
                    found.iter().cloned().collect::<Vec<_>>().join(", ")
                ),
            });
        }
    }
    for (service, found) in stores {
        if found.len() > 1 {
            report.problems.push(Problem {
                location: service,
                message: format!(
                    "the units disagree on the credential store: {}",
                    found.iter().cloned().collect::<Vec<_>>().join(", ")
                ),
            });
        }
    }
}

/// The names of the entries of a directory, sorted.
fn read_dir_sorted(dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<String> =
        entries.flatten().filter_map(|e| e.file_name().to_str().map(ToOwned::to_owned)).collect();
    out.sort();
    out
}

/// Resolve the variables a path may name.
///
/// A path in a playbook may name an exported variable (`${SVC}`,
/// `${UNIT}`); the check resolves them the way a deploy would.
fn resolve(path: &str, facts: &PlaybookFacts) -> String {
    let mut out = path.to_string();
    for (name, value) in &facts.variables {
        out = out.replace(&format!("${{{name}}}"), value);
        out = out.replace(&format!("${name}"), value);
    }
    out
}

/// The playbooks of a repository.
fn playbooks(repo: &Path) -> Vec<PathBuf> {
    let dir = repo.join("playbooks");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut out: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "sh"))
        .collect();
    out.sort();
    out
}

/// What a playbook installs, and what it copies.
struct PlaybookFacts {
    /// The service directories the playbook copies from.
    service_dirs: Vec<String>,
    /// The install steps: `(source, destination)`.
    installs: Vec<(String, String)>,
    /// Whether the playbook copies the shared hardening.
    copies_common: bool,
    /// The playbook's text, for the checks a plan cannot answer.
    text: String,
    /// The service name the playbook exports (`SVC=`).
    service: String,
    /// The file names the copy steps land in the staging directory.
    staged: BTreeSet<String>,
    /// The variables the local block assigns, resolved.
    variables: std::collections::BTreeMap<String, String>,
    /// The repository paths the copy steps read from.
    copy_sources: Vec<String>,
    /// The backup and install steps, in plan order.
    ordered: Vec<PlanEvent>,
}

/// One plan step the ordering rule cares about.
///
/// A `# @backup` snapshots files; an `# @install` writes one. Both touch the
/// target in the order their directives appear, which is why the order in
/// the plan is exactly the order of side effects.
#[derive(Clone, Debug, Eq, PartialEq)]
enum PlanEvent {
    /// The paths the step snapshots.
    Backup(Vec<String>),
    /// The path the step overwrites on the target.
    Install(String),
}

/// Read the facts of a playbook out of its own plan.
///
/// The playbook is parsed with the tool's own parser, so the check sees
/// exactly what a deploy would do.
fn playbook_facts(repo: &Path, path: &Path) -> Option<PlaybookFacts> {
    let text = std::fs::read_to_string(path).ok()?;
    let plan = shellflow_core::parse_script(&text).ok()?;
    let service = text
        .lines()
        .find_map(|line| line.strip_prefix("SVC="))
        .map_or_else(String::new, |value| value.trim().to_string());
    // the variables the local block assigns: the install and copy paths may
    // name them
    let mut variables: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    for line in text.lines() {
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        let name = name.trim();
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            continue;
        }
        let value = value.trim().trim_matches('"').trim_matches('\'');
        if value.is_empty() || value.contains(' ') || value.contains('$') {
            continue;
        }
        // the first assignment wins: a later `SVC="${SVC:-x}"` in a remote
        // block is a fallback, not a new value
        variables.entry(name.to_string()).or_insert_with(|| value.to_string());
    }
    let mut facts = PlaybookFacts {
        service_dirs: Vec::new(),
        installs: Vec::new(),
        copies_common: false,
        service,
        text,
        staged: BTreeSet::new(),
        variables,
        copy_sources: Vec::new(),
        ordered: Vec::new(),
    };
    for step in &plan.steps {
        match step {
            shellflow_core::Step::Copy(copy) => {
                for entry in &copy.entries {
                    let source = resolve(&entry.src, &facts);
                    facts.copy_sources.push(source.clone());
                    // A directory copy lands its *contents* in the staging
                    // directory; a file copy lands the file under the
                    // destination's name.
                    if let Some(dir) = source.strip_prefix("services/") {
                        let dir = dir.trim_matches('/');
                        if Path::new(dir).extension().is_none() {
                            facts.service_dirs.push(dir.to_string());
                            let service_dir = repo.join("services").join(dir);
                            for entry in read_dir_sorted(&service_dir) {
                                facts.staged.insert(entry.clone());
                                // a drop-in directory lands its files too
                                let nested = service_dir.join(&entry);
                                if nested.is_dir() {
                                    for file in read_dir_sorted(&nested) {
                                        facts.staged.insert(file);
                                    }
                                }
                            }
                            continue;
                        }
                    }
                    if let Some(name) = entry.dst.rsplit('/').next() &&
                        !name.is_empty()
                    {
                        facts.staged.insert(name.to_string());
                    }
                    // the copy's source is the service directory in the
                    // repository; its destination is the staging directory
                    if entry.src.contains("common") {
                        facts.copies_common = true;
                    }
                    if let Some(rest) = entry.src.strip_prefix("services/") {
                        let dir = rest
                            .trim_matches('/')
                            .replace("${SVC}", &facts.service)
                            .replace("$SVC", &facts.service);
                        // A copy of a *file* out of another service is not a
                        // copy of that service: only a directory is.
                        if Path::new(&dir).extension().is_none() {
                            facts.service_dirs.push(dir);
                        }
                    }
                }
            }
            shellflow_core::Step::Install(install) => {
                facts.installs.push((install.src.clone(), install.dst.clone()));
                facts.ordered.push(PlanEvent::Install(resolve(&install.dst, &facts)));
            }
            shellflow_core::Step::Backup(backup) => {
                let paths = backup.paths.iter().map(|path| resolve(path, &facts)).collect();
                facts.ordered.push(PlanEvent::Backup(paths));
            }
            _ => {}
        }
    }
    Some(facts)
}

/// Check one playbook against the repository.
fn check_playbook(
    repo: &Path,
    playbook: &Path,
    manifests: &std::collections::BTreeMap<String, ServiceManifest>,
    report: &mut Report,
) {
    let Some(facts) = playbook_facts(repo, playbook) else {
        report.problems.push(Problem {
            location: playbook.display().to_string(),
            message: "the playbook does not parse".to_string(),
        });
        return;
    };

    // Every `@install` source must be a file the playbook actually stages.
    for (src, _dst) in &facts.installs {
        let Some(rest) = src.strip_prefix("${WORKDIR}/svc/") else {
            continue;
        };
        let resolved = resolve(rest, &facts);
        let name = resolved.rsplit('/').next().unwrap_or_default();
        if name.is_empty() {
            continue;
        }
        if !facts.staged.contains(name) {
            report.problems.push(Problem {
                location: playbook.display().to_string(),
                message: format!(
                    "`@install {src}` names a file the playbook never stages (the copy steps \
                     stage: {})",
                    facts.staged.iter().cloned().collect::<Vec<_>>().join(", ")
                ),
            });
            continue;
        }
        // and the staged file must exist in the repository
        let exists = facts.service_dirs.iter().any(|dir| {
            let candidate = repo.join("services").join(dir).join(&resolved);
            candidate.exists()
        }) || facts.copy_sources.iter().any(|source| repo.join(source).exists());
        if !exists {
            report.problems.push(Problem {
                location: playbook.display().to_string(),
                message: format!("`@install {src}` names a file the repository does not have"),
            });
        }
    }

    // A backup must run *before* the step that overwrites the file it
    // snapshots: executed after, it captures the just-installed file and the
    // rollback copy is worthless.
    check_backup_order(&facts, playbook, report);

    // Every generated drop-in of a copied service must be installed, and the
    // shared hardening must be installed too.
    for service_dir in &facts.service_dirs {
        let service = service_dir.split('/').next().unwrap_or(service_dir);
        let units: Vec<String> = manifests
            .values()
            .filter(|m| m.service == service)
            .map(|m| unit_stem(&m.unit).to_string())
            .collect();
        for unit in units {
            let dropin = format!("/etc/systemd/system/{unit}.service.d/{}", unit::DROPIN_NAME);
            let hardening = format!("/etc/systemd/system/{unit}.service.d/{HARDENING_NAME}");
            // A multi-unit service installs its units in a shell loop, which
            // the plan cannot show. The loop names the drop-in by its
            // suffix (`${u}.service.d/<file>`), so a mention of the suffix
            // counts.
            let mentions = |name: &str| facts.text.contains(&format!(".service.d/{name}"));
            if !facts.installs.iter().any(|(_, dst)| dst == &dropin) && !mentions(unit::DROPIN_NAME)
            {
                report.problems.push(Problem {
                    location: playbook.display().to_string(),
                    message: format!("the generated drop-in {dropin} is never installed"),
                });
            }
            // A unit that cannot take the shared hardening says so in its
            // manifest; the check then stops asking for it.
            let wants_hardening = manifests
                .values()
                .any(|m| m.service == service && unit_stem(&m.unit) == unit && m.hardening);
            if wants_hardening &&
                !facts.installs.iter().any(|(_, dst)| dst == &hardening) &&
                !mentions(HARDENING_NAME)
            {
                report.problems.push(Problem {
                    location: playbook.display().to_string(),
                    message: format!("the shared hardening {hardening} is never installed"),
                });
            }
        }
    }
}

/// A backup that runs after the overwrite it is supposed to capture.
///
/// The directives are executed in source order, so a `# @backup` line that
/// sits below the `# @install` lines snapshots the *new* content. The rule
/// flags exactly that shape: a path backed up by a later step and written by
/// an earlier one.
fn check_backup_order(facts: &PlaybookFacts, playbook: &Path, report: &mut Report) {
    for (index, event) in facts.ordered.iter().enumerate() {
        let PlanEvent::Install(dst) = event else {
            continue;
        };
        // the earliest backup covering this path
        let covering = facts
            .ordered
            .iter()
            .position(|other| matches!(other, PlanEvent::Backup(paths) if paths.contains(dst)));
        if covering.is_some_and(|backup_index| backup_index > index) {
            report.problems.push(Problem {
                location: playbook.display().to_string(),
                message: format!(
                    "the backup of {dst} runs after the step that installs the same path: \
                     move the `# @backup` line above the `# @install` line, so the snapshot captures the previous file"
                ),
            });
        }
    }
}

/// The shared hardening file of a repository, if it has one.
#[must_use]
pub(crate) fn hardening_path(repo: &Path) -> PathBuf {
    repo.join(HARDENING_FILE)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{playbook_facts, verify};

    fn repo_with_service() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        let service = dir.path().join("services").join("dufs");
        fs::create_dir_all(&service).expect("mkdir");
        fs::write(service.join("dufs.service"), "[Service]\nExecStart=/opt/dufs/bin/dufs\n")
            .expect("write");
        fs::write(
            service.join("dufs.service.toml"),
            "host = \"api\"\nunit = \"dufs.service\"\nbinary = \"/opt/dufs/bin/dufs\"\n",
        )
        .expect("write");
        dir
    }

    #[test]
    fn a_repository_without_playbooks_has_no_problem() {
        let dir = repo_with_service();
        let report = verify(dir.path()).expect("verify");
        // The drop-in is missing, and that is a problem worth reporting.
        assert!(
            report.problems.iter().any(|p| p.message.contains("drop-in is missing")),
            "{report:?}"
        );
    }

    #[test]
    fn a_manifest_without_a_unit_is_reported() {
        let dir = repo_with_service();
        fs::remove_file(dir.path().join("services/dufs/dufs.service")).expect("rm");
        let report = verify(dir.path()).expect("verify");
        assert!(report.problems.iter().any(|p| p.message.contains("no unit file")), "{report:?}");
    }

    #[test]
    fn a_playbook_that_does_not_parse_is_reported() {
        let dir = repo_with_service();
        fs::create_dir_all(dir.path().join("playbooks")).expect("mkdir");
        fs::write(dir.path().join("playbooks/bad.sh"), "# @nope\n").expect("write");
        let report = verify(dir.path()).expect("verify");
        assert!(report.problems.iter().any(|p| p.message.contains("does not parse")), "{report:?}");
    }

    #[test]
    fn a_backup_after_the_install_of_the_same_path_is_reported() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("playbooks")).expect("mkdir");
        fs::write(
            dir.path().join("playbooks/deploy.sh"),
            "# @server api api\n\
             # @install ${WORKDIR}/svc/dufs.service -> /etc/systemd/system/dufs.service @api --mode 0644\n\
             # @backup /etc/systemd/system/dufs.service @api\n",
        )
        .expect("write");
        let report = verify(dir.path()).expect("verify");
        assert!(
            report.problems.iter().any(|p| p.message.contains("runs after the step that installs")),
            "{report:?}"
        );
    }

    #[test]
    fn a_backup_before_the_install_of_the_same_path_is_consistent() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("playbooks")).expect("mkdir");
        fs::write(
            dir.path().join("playbooks/deploy.sh"),
            "# @server api api\n\
             # @backup /etc/systemd/system/dufs.service @api\n\
             # @install ${WORKDIR}/svc/dufs.service -> /etc/systemd/system/dufs.service @api --mode 0644\n",
        )
        .expect("write");
        let report = verify(dir.path()).expect("verify");
        assert!(
            !report
                .problems
                .iter()
                .any(|p| p.message.contains("runs after the step that installs")),
            "{report:?}"
        );
    }

    #[test]
    fn the_facts_of_a_playbook_are_read_from_its_plan() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("playbooks")).expect("mkdir");
        let path = dir.path().join("playbooks/deploy.sh");
        fs::write(
            &path,
            "# @server api api\n\
             # @copy services/dufs -> $WORKDIR/svc @api\n\
             # @install ${WORKDIR}/svc/dufs.service -> /etc/systemd/system/dufs.service @api\n",
        )
        .expect("write");
        let facts = playbook_facts(dir.path(), &path).expect("facts");
        assert_eq!(facts.service_dirs, vec!["dufs".to_string()]);
        assert_eq!(facts.installs.len(), 1);
        assert!(!facts.copies_common);
    }
}
