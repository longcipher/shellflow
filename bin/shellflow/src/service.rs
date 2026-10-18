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

use crate::cli::{ServiceCmd, ServiceInitArgs};

/// The config template (token `__SVC__`).
const CONFIG_TEMPLATE: &str = include_str!("../assets/service-config.tmpl");

/// The systemd unit (token `__SVC__`).
const UNIT_TEMPLATE: &str = include_str!("../assets/service-unit.tmpl");

/// The deploy playbook (tokens `__SVC__`, `__SERVER_LINES__`, `__HOST__`).
const PLAYBOOK_TEMPLATE: &str = include_str!("../assets/service-playbook.tmpl");

/// Scaffold a service.
///
/// # Errors
///
/// Returns when the service name is unusable, when any target path already
/// exists (never overwrites), or on I/O failures.
pub(crate) fn run(cmd: &ServiceCmd) -> Result<()> {
    match cmd {
        ServiceCmd::Init(args) => init(args),
    }
}

/// Scaffold a service (`service init`).
fn init(cmd: &ServiceInitArgs) -> Result<()> {
    let service = cmd.service.trim();
    let hosts: Vec<String> = if cmd.hosts.is_empty() {
        vec!["api".to_string()]
    } else {
        cmd.hosts.iter().map(|h| h.trim().to_string()).filter(|h| !h.is_empty()).collect()
    };
    validate_service_name(service)?;
    if hosts.is_empty() {
        bail!("no hosts given: pass `--host <alias>` with a non-empty value");
    }

    let dir = PathBuf::from(format!("services/{service}"));
    let playbook = PathBuf::from(format!("playbooks/deploy-{service}.sh"));
    let config = dir.join(format!("{service}.json5.tmpl"));
    let unit = dir.join(format!("{service}.service"));
    for path in [&config, &unit, &playbook] {
        if path.exists() {
            bail!("refusing to overwrite existing `{}`", path.display());
        }
    }

    fs::create_dir_all(&dir).wrap_err_with(|| format!("failed to create `{}`", dir.display()))?;
    write_file(&config, &render(CONFIG_TEMPLATE, service))?;
    write_file(&unit, &render(UNIT_TEMPLATE, service))?;

    let server_lines =
        hosts.iter().map(|h| format!("# @server {h:<8} {h}")).collect::<Vec<_>>().join("\n");
    let playbook_body = PLAYBOOK_TEMPLATE
        .replace("__SERVER_LINES__", server_lines.trim_end())
        .replace("__HOST__", &hosts[0])
        .replace("__SVC__", service);
    write_executable(&playbook, &playbook_body)?;

    println!("==> scaffolded:");
    println!("    {}   (plaintext template, placeholder syntax)", config.display());
    println!("    {}      (ExecStart via the shared cred-env helper)", unit.display());
    println!("    {}", playbook.display());
    println!("==> next: create the encrypted env (one per host, same key set):");
    for host in &hosts {
        println!("    {{ printf 'KEY=...\\n'; }} | shellflow secret encrypt \\");
        println!("      -r \"$(cat keys/recipients/*.pub)\" \\");
        println!("      -o services/{service}/{host}.env.age");
    }
    println!("==> then:");
    println!("    1) shellflow secret keys-check services/{service}");
    println!("    2) shellflow template check services/{service}/{service}.json5.tmpl \\");
    println!("         services/{service}/{}.env.age", hosts[0]);
    println!("    3) shellflow secret creds --store-dir /etc/credstore.encrypted/{service} \\");
    println!(
        "         services/{service}/{}.env.age   # paste LoadCredentialEncrypted= lines",
        hosts[0]
    );
    Ok(())
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

/// Replace the `__SVC__` token (used instead of `format!` so template braces
/// and `$`-sigils stay literal).
fn render(template: &str, service: &str) -> String {
    template.replace("__SVC__", service)
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
    use super::{CONFIG_TEMPLATE, PLAYBOOK_TEMPLATE, UNIT_TEMPLATE, render, validate_service_name};

    #[test]
    fn render_replaces_every_token() {
        let unit = render(UNIT_TEMPLATE, "myapp");
        assert!(!unit.contains("__SVC__"));
        assert!(unit.contains("User=myapp"));
        assert!(unit.contains("/etc/myapp/myapp.json5.tmpl"));
        assert!(
            unit.contains("ExecStart=/usr/local/bin/shellflow cred-env exec /opt/myapp/bin/myapp")
        );
    }

    #[test]
    fn generated_unit_targets_the_shared_helper() {
        let unit = render(UNIT_TEMPLATE, "zenoh");
        assert!(unit.contains("cred-env render"));
        assert!(unit.contains("cred-env exec"));
        assert!(!unit.contains("zenoh-start"), "no per-service starter script");
    }

    #[test]
    fn generated_template_uses_real_placeholders() {
        let config = render(CONFIG_TEMPLATE, "myapp");
        assert!(!config.contains("__SVC__"));
        assert!(!config.contains("__LISTEN_ENDPOINT__"));
        assert_eq!(
            shellflow_core::template_keys(&config),
            vec!["LISTEN_ENDPOINT"],
            "scaffold template references exactly LISTEN_ENDPOINT"
        );
    }

    #[test]
    fn playbook_template_keeps_directives_and_drops_tokens() {
        let body = PLAYBOOK_TEMPLATE
            .replace("__SERVER_LINES__", "# @server api      api")
            .replace("__HOST__", "api")
            .replace("__SVC__", "myapp");
        assert!(!body.contains("__SVC__"));
        assert!(!body.contains("__HOST__"));
        assert!(body.contains("# @server api      api"));
        assert!(body.contains("# @secrets services/myapp/{host}.env.age"));
        assert!(body.contains("cred-env credstore-install"));
        assert!(body.contains("cargo zigbuild"));
        for line in body.lines() {
            let trimmed = line.trim_start();
            if let Some(rest) = trimmed.strip_prefix('#') {
                assert!(
                    !rest.trim_start().starts_with('@') || line.starts_with("# @"),
                    "stray directive-looking comment: {line}"
                );
            }
        }
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
