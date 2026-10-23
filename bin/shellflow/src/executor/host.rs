//! The target-side host steps: `@service`, `@install`, `@backup`, `@credstore`,
//! `@unit_inventory`, and `@helper`.
//!
//! Every one of them costs **one** SSH round trip per host: the work happens
//! on the target, in the target-side helper, and the controller only reads
//! the verdict. The playbook's job is to state the intent; the helper's job
//! is to carry it out with the guarantees the shell spelling did not have.

use std::{
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};

use shellflow_core::ResolvedHost;
use tokio::{process::Command, sync::Semaphore};

use crate::executor::{ArcUi, HostOutcome, LogFile, RunError, StepConfig, cancel::Cancel, stream};

/// The exit code the target helper uses for "the condition did not hold".
const EXIT_FAILED: i32 = 3;

/// The exit code the target helper uses for "the budget expired".
const EXIT_TIMEOUT: i32 = 4;

/// Where the target-side helper is installed.
pub(crate) const HELPER_PATH: &str = "/usr/local/bin/shellflow";

/// Quote a value for the remote shell.
fn quote(value: &str) -> String {
    shellflow_core::env::shell_quote_single(value)
}

/// The command that runs a host verb through the target-side helper.
///
/// The helper is the **preferred** path: it carries the real semantics
/// (atomic writes, structural assertions, a restart that never starts a
/// stopped unit). The inline fallback covers a host that has never seen this
/// shellflow; it reproduces the same rules in shell.
fn helper_command(verb: &str, args: &[String], fallback: &str) -> String {
    let mut command = format!("if [ -x {HELPER_PATH} ]; then exec {HELPER_PATH} host {verb}");
    for arg in args {
        command.push(' ');
        if arg.starts_with("--") {
            // A flag is literal; quoting it would make it a *value*.
            command.push_str(arg);
        } else {
            command.push_str(&quote(arg));
        }
    }
    command.push_str("; fi; ");
    command.push_str(fallback);
    command
}

/// The command that fails with a clear message when the helper is missing.
fn needs_helper(verb: &str) -> String {
    format!(
        "echo 'the target-side shellflow helper is required for `{verb}`: install it first with \
         `@helper`' >&2; exit 1"
    )
}

/// The parameters of one target-side command.
pub(super) struct TargetCommand<'a> {
    /// The shared UI handle.
    pub ui: &'a ArcUi,
    /// The remote command to run.
    pub command: String,
    /// The hosts to run it on.
    pub hosts: Vec<ResolvedHost>,
    /// The per-step settings.
    pub config: StepConfig,
    /// The fan-out semaphore.
    pub semaphore: &'a Option<Arc<Semaphore>>,
    /// The audit-log handle.
    pub log_file: &'a LogFile,
    /// The cooperative cancellation signal.
    pub cancel: &'a Cancel,
    /// The label shown in the per-host verdict.
    pub label: &'a str,
    /// The resolved secrets, injected into the command's environment.
    pub secrets: &'a Arc<crate::secrets::ResolvedSecrets>,
    /// The probed remote environments (the shell, the login PATH).
    pub shell_cache: &'a crate::executor::ShellCache,
}

/// Run one target-side command on every host.
///
/// The exit code decides the verdict: `0` is success, `255` is a transport
/// failure (the connection itself broke), anything else is the operation
/// failing.
pub(super) async fn run_target_command(
    args: TargetCommand<'_>,
) -> eyre::Result<Vec<(String, HostOutcome)>> {
    let TargetCommand {
        ui,
        command,
        hosts,
        config,
        semaphore,
        log_file,
        cancel,
        label,
        secrets,
        shell_cache,
    } = args;
    if config.check || config.dry_run {
        crate::ui::note(&format!("  {label}: no-op in check/dry-run"), log_file);
        return Ok(hosts.into_iter().map(|host| (host.alias, HostOutcome::Ok)).collect());
    }

    let budget = Duration::from_secs(config.timeout.unwrap_or(300));
    let mut tasks = tokio::task::JoinSet::new();
    for host in hosts {
        let ui = Arc::clone(ui);
        let command = command.clone();
        let semaphore = semaphore.clone();
        let log_file = log_file.clone();
        let cancel = cancel.clone();
        let label = label.to_string();
        let secrets = Arc::clone(secrets);
        let shell_cache = Arc::clone(shell_cache);
        tasks.spawn(async move {
            let _permit = match semaphore.as_ref() {
                Some(sem) => match sem.clone().acquire_owned().await {
                    Ok(permit) => Some(permit),
                    Err(_) => {
                        return (host.alias.clone(), HostOutcome::Failed(RunError::Transport));
                    }
                },
                None => None,
            };
            if cancel.is_cancelled() {
                return (host.alias.clone(), HostOutcome::Cancelled);
            }
            // The command runs through the target's login shell with the
            // step's environment — including the `@secrets` values — in
            // front of it, exactly like a remote block. A credential that
            // never reaches the command cannot be sealed into the store.
            let remote_env =
                crate::executor::remote::resolve_remote_env(&host, &shell_cache, &cancel).await;
            let mut payload_env = Vec::new();
            secrets.overlay(&mut payload_env, &host.alias);
            let env_header = match shellflow_core::env::render_env(&payload_env) {
                Ok(header) => header,
                Err(_) => {
                    return (host.alias.clone(), HostOutcome::Failed(RunError::Plan));
                }
            };
            let payload = format!("set -eu\n{env_header}{command}\n");
            let mut cmd = Command::new("ssh");
            cmd.args(["-o", "BatchMode=yes"]);
            cmd.args(host.spec.to_ssh_args()).arg("-T").arg(remote_env.shell.invoke(false));
            // The command travels as the remote shell's standard input. With
            // the default (inherited) stdin there is nothing to write to,
            // the remote shell reads EOF, exits 0 -- and the step reports
            // success without having done anything at all.
            cmd.stdin(std::process::Stdio::piped());
            let args = stream::PipedArgs {
                ui: &ui,
                host: &host.alias,
                payload: Some(&payload),
                // The helper enforces its own budget; the transport gets a
                // little more so the helper's own verdict wins.
                timeout: Some(budget.as_secs() + 30),
                diff_filter: None,
                log_file: &log_file,
                cancel: cancel.clone(),
                quiet: false,
                collector: None,
            };
            let outcome = match stream::run_piped_child(args, cmd).await {
                Ok(outcome) => outcome,
                Err(_) => {
                    return (host.alias.clone(), HostOutcome::Failed(RunError::Transport));
                }
            };
            match outcome {
                stream::PipedRun::Completed(status) => {
                    let code = status.code().unwrap_or(-1);
                    match code {
                        0 => {
                            ui.lock().await.masked_note(&format!("[{}] {label} ok", host.alias));
                            (host.alias.clone(), HostOutcome::Ok)
                        }
                        // ssh exits 255 when the connection itself failed:
                        // that is a transport failure, not a failed operation.
                        255 => (host.alias.clone(), HostOutcome::Failed(RunError::Transport)),
                        EXIT_FAILED => {
                            ui.lock()
                                .await
                                .masked_note(&format!("[{}] {label} failed", host.alias));
                            (host.alias.clone(), HostOutcome::Failed(RunError::Script))
                        }
                        EXIT_TIMEOUT => {
                            ui.lock()
                                .await
                                .masked_note(&format!("[{}] {label} timed out", host.alias));
                            (host.alias.clone(), HostOutcome::Failed(RunError::Script))
                        }
                        other => {
                            ui.lock().await.masked_note(&format!(
                                "[{}] {label} failed (exit {other})",
                                host.alias
                            ));
                            (host.alias.clone(), HostOutcome::Failed(RunError::Script))
                        }
                    }
                }
                stream::PipedRun::TimedOut | stream::PipedRun::PipeBroken => {
                    (host.alias.clone(), HostOutcome::Failed(RunError::Transport))
                }
                stream::PipedRun::Cancelled => (host.alias.clone(), HostOutcome::Cancelled),
            }
        });
    }
    let mut out = Vec::new();
    while let Some(res) = tasks.join_next().await {
        match res {
            Ok(pair) => {
                ui.lock().await.host_finished(&pair.0);
                out.push(pair);
            }
            Err(_) => out.push(("unknown".to_string(), HostOutcome::Failed(RunError::Transport))),
        }
    }
    Ok(out)
}

// === the individual verbs ===

/// The lifecycle actions a `@service` step asks for.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct ServiceActions {
    /// Enable the unit at boot.
    pub enable: bool,
    /// Restart the unit — but only when it was running.
    pub restart: bool,
    /// Reload the unit gracefully.
    pub reload: bool,
    /// Wait for the unit to become ready.
    pub wait: bool,
    /// Verify the installed unit first.
    pub verify: bool,
    /// Start the unit even when it was not running.
    pub force_start: bool,
}

/// The remote command for `@service`.
pub(super) fn service_command(unit: &str, actions: ServiceActions, timeout: u64) -> String {
    let mut args = vec![unit.to_string()];
    if actions.enable {
        args.push("--enable".to_string());
    }
    if actions.restart {
        args.push("--restart".to_string());
    }
    if actions.reload {
        args.push("--reload".to_string());
    }
    if actions.wait {
        args.push("--wait".to_string());
    }
    if actions.verify {
        args.push("--verify".to_string());
    }
    if actions.force_start {
        args.push("--force-start".to_string());
    }
    args.push("--timeout".to_string());
    args.push(timeout.to_string());

    // The fallback reproduces the same rules: the unit is restarted only when
    // it was running, so a unit the operator keeps stopped stays stopped.
    let fallback = service_fallback(unit, actions.enable, actions.reload, actions.force_start);
    helper_command("service", &args, &fallback)
}

/// The inline fallback for `@service`, for a host that has never seen this
/// shellflow.
///
/// The rules are the ones the helper implements: the unit is verified before
/// the manager is reloaded, and it is restarted only when it was running.
fn service_fallback(unit: &str, enable: bool, reload: bool, force_start: bool) -> String {
    let enable = if enable { "systemctl enable \"$u\"; " } else { "" };
    let reload = if reload { "systemctl reload \"$u\"; " } else { "" };
    let force = if force_start { "1" } else { "0" };
    format!(
        "u={u}; \
         was=$(systemctl is-active \"$u\" 2>/dev/null || true); \
         [ \"$was\" = active ] && was=1 || was=0; \
         if command -v systemd-analyze >/dev/null 2>&1; then \
           systemd-analyze verify \"$u\" >/dev/null 2>&1 \
             || {{ echo \"unit $u failed verification\" >&2; exit 1; }}; \
         fi; \
         systemctl daemon-reload; \
         {enable}\
         {reload}\
         if [ \"$was\" = 1 ]; then systemctl restart \"$u\"; \
         elif [ \"{force}\" = 1 ]; then systemctl start \"$u\"; \
         else echo \"$u was not running: left it stopped\"; fi",
        u = quote(unit),
    )
}

/// The remote command for `@install`.
pub(super) fn install_command(
    src: &str,
    dst: &str,
    mode: Option<u32>,
    owner: Option<&str>,
    dir_mode: Option<u32>,
) -> String {
    let mut args = vec![src.to_string(), dst.to_string()];
    if let Some(mode) = mode {
        args.push("--mode".to_string());
        args.push(format!("{mode:o}"));
    }
    if let Some(owner) = owner {
        args.push("--owner".to_string());
        args.push(owner.to_string());
    }
    if let Some(dir_mode) = dir_mode {
        args.push("--dir-mode".to_string());
        args.push(format!("{dir_mode:o}"));
    }

    // The fallback writes beside the destination and renames, so the
    // destination is never observed half-written.
    let fallback = install_fallback(src, dst, mode, owner);
    helper_command("install", &args, &fallback)
}

/// The inline fallback for `@install`, for a host that has never seen this
/// shellflow.
fn install_fallback(src: &str, dst: &str, mode: Option<u32>, owner: Option<&str>) -> String {
    let mode = format!("{:o}", mode.unwrap_or(0o644));
    let chown = owner.map_or_else(String::new, |o| format!("chown {o} \"$t\" && "));
    format!(
        "d={dst}; s={src}; \
         dir=$(dirname \"$d\"); \
         [ -d \"$dir\" ] || mkdir -p \"$dir\"; \
         t=\"$dir/.$(basename \"$d\").shellflow-new\"; \
         cat \"$s\" > \"$t\" && chmod {mode} \"$t\" && {chown}mv -f \"$t\" \"$d\"",
        dst = quote(dst),
        src = quote(src),
    )
}

/// The remote command for `@backup`.
pub(super) fn backup_command(
    paths: &[String],
    service: Option<&str>,
    dir: Option<&str>,
    keep: Option<u32>,
    seal: bool,
) -> String {
    let mut args = paths.to_vec();
    if let Some(service) = service {
        args.push("--service".to_string());
        args.push(service.to_string());
    }
    if let Some(dir) = dir {
        args.push("--dir".to_string());
        args.push(dir.to_string());
    }
    if let Some(keep) = keep {
        args.push("--keep".to_string());
        args.push(keep.to_string());
    }
    if seal {
        args.push("--seal".to_string());
    }
    helper_command("backup", &args, &needs_helper("backup"))
}

/// The remote command for `@credstore`.
pub(super) fn credstore_command(service: &str, require: &[String]) -> String {
    let mut args = vec![service.to_string()];
    if !require.is_empty() {
        args.push("--require".to_string());
        args.push(require.join(","));
    }
    helper_command("credstore", &args, &needs_helper("credstore"))
}

/// The remote command for `@unit_inventory`.
pub(super) fn unit_inventory_command() -> String {
    helper_command("inventory", &[], &needs_helper("unit_inventory"))
}

// === the helper bootstrap ===

/// Where the built helper is cached between runs.
pub(crate) fn cache_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("SHELLFLOW_CACHE_DIR") {
        return PathBuf::from(dir);
    }
    let base = std::env::var_os("XDG_CACHE_HOME").map_or_else(
        || PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".cache"),
        PathBuf::from,
    );
    base.join("shellflow")
}

/// The revision of a source tree, used as the cache key.
///
/// A git checkout is keyed by its HEAD; anything else by the modification
/// time of its manifest, which changes whenever the sources change.
pub(crate) fn source_revision(source: &Path) -> eyre::Result<String> {
    let git = source.join(".git");
    if git.exists() {
        let out = std::process::Command::new("git")
            .arg("-C")
            .arg(source)
            .args(["rev-parse", "HEAD"])
            .stdin(Stdio::null())
            .output()
            .map_err(|err| eyre::eyre!("cannot run `git`: {err}"))?;
        if out.status.success() {
            let head = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !head.is_empty() {
                return Ok(head.chars().take(12).collect());
            }
        }
    }
    let manifest = source.join("Cargo.toml");
    let meta = std::fs::metadata(&manifest)
        .map_err(|err| eyre::eyre!("cannot stat `{}`: {err}", manifest.display()))?;
    let modified = meta
        .modified()
        .map_err(|err| eyre::eyre!("cannot read the modification time: {err}"))?
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    Ok(format!("m{modified}"))
}

/// The cached helper for a source revision and target triple.
pub(crate) fn cached_helper(source: &Path, triple: &str) -> eyre::Result<PathBuf> {
    let revision = source_revision(source)?;
    let dir = cache_dir().join(format!("helper-{revision}-{triple}"));
    let binary = dir.join("shellflow");
    if binary.exists() {
        return Ok(binary);
    }
    std::fs::create_dir_all(&dir)
        .map_err(|err| eyre::eyre!("cannot create `{}`: {err}", dir.display()))?;
    build_helper(source, triple, &binary)?;
    Ok(binary)
}

/// Build the target-side helper.
///
/// The build is the expensive part of a deploy, so it happens once per source
/// revision and target triple and is then reused by every playbook.
fn build_helper(source: &Path, triple: &str, out: &Path) -> eyre::Result<()> {
    // `cargo zigbuild --version` is not a thing: cargo-zigbuild has no
    // `--version` option and exits 2 on it. `--help` is the probe that
    // actually answers "is cargo-zigbuild installed?".
    let zigbuild = std::process::Command::new("cargo")
        .arg("zigbuild")
        .arg("--help")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());

    let mut cmd = std::process::Command::new("cargo");
    if zigbuild {
        cmd.arg("zigbuild");
    } else {
        cmd.arg("build");
    }
    cmd.arg("--release").arg("-p").arg("shellflow").arg("--target").arg(triple);
    cmd.current_dir(source);
    cmd.stdin(Stdio::null());
    let status = cmd.status().map_err(|err| eyre::eyre!("cannot run `cargo`: {err}"))?;
    if !status.success() {
        return Err(eyre::eyre!("building the helper for {triple} failed"));
    }
    let built = source.join("target").join(triple).join("release").join("shellflow");
    std::fs::copy(&built, out).map_err(|err| {
        eyre::eyre!("cannot copy `{}` to `{}`: {err}", built.display(), out.display())
    })?;
    Ok(())
}

/// The remote command that installs the helper atomically.
pub(crate) fn helper_install_command(staged: &str, install_path: &str) -> String {
    // The helper lands in a root-owned directory, so every step is
    // elevated. The write goes to a temporary name beside the destination
    // and is renamed into place: a reader of the destination sees either the
    // old helper or the new one, never a half-written file.
    format!(
        "d=$(dirname {install}); t=\"$d/.$(basename {install}).shellflow-new\"; \
         sudo cp {staged} \"$t\" && sudo chmod 0755 \"$t\" && sudo mv -f \"$t\" {install}",
        install = quote(install_path),
        staged = quote(staged),
    )
}

/// The remote staging path of the helper.
pub(crate) fn helper_staging_path(revision: &str) -> String {
    format!("/tmp/.shellflow-helper-{revision}")
}

/// Build the helper and install it on every target.
///
/// The build is the expensive part, and it happens **once**: the artifact is
/// cached by source revision and target triple, so the second service that
/// needs the helper reuses the first one's build.
pub(super) async fn run_helper_step(
    ui: &ArcUi,
    step: &shellflow_core::HelperStep,
    hosts: Vec<ResolvedHost>,
    config: StepConfig,
    semaphore: &Option<Arc<Semaphore>>,
    log_file: &LogFile,
    cancel: &Cancel,
) -> eyre::Result<Vec<(String, HostOutcome)>> {
    if config.check || config.dry_run {
        crate::ui::note("  helper: no-op in check/dry-run", log_file);
        return Ok(hosts.into_iter().map(|host| (host.alias, HostOutcome::Ok)).collect());
    }

    let source = resolve_helper_source(step)?;
    let triple = step.triple.clone().unwrap_or_else(|| "x86_64-unknown-linux-musl".to_string());

    // The build blocks; keep it off the async runtime's worker threads.
    let source_for_build = source.clone();
    let triple_for_build = triple.clone();
    let built = match tokio::task::spawn_blocking(move || {
        cached_helper(&source_for_build, &triple_for_build)
    })
    .await
    {
        Ok(Ok(path)) => path,
        Ok(Err(err)) => {
            crate::ui::step_failed(0, &err.to_string(), log_file);
            return Err(err);
        }
        Err(err) => {
            crate::ui::step_failed(0, &format!("the helper build panicked: {err}"), log_file);
            return Err(eyre::eyre!("the helper build panicked: {err}"));
        }
    };
    ui.lock().await.masked_note(&format!("==> helper staged: {}", built.display()));

    let revision = source_revision(&source).unwrap_or_else(|_| "unknown".to_string());
    let staged = helper_staging_path(&revision);

    let mut tasks = tokio::task::JoinSet::new();
    for host in hosts {
        let ui = Arc::clone(ui);
        let built = built.clone();
        let staged = staged.clone();
        let install_path = step.install_path.clone();
        let semaphore = semaphore.clone();
        let log_file = log_file.clone();
        let cancel = cancel.clone();
        tasks.spawn(async move {
            let _permit = match semaphore.as_ref() {
                Some(sem) => match sem.clone().acquire_owned().await {
                    Ok(permit) => Some(permit),
                    Err(_) => {
                        return (host.alias.clone(), HostOutcome::Failed(RunError::Transport));
                    }
                },
                None => None,
            };
            if cancel.is_cancelled() {
                return (host.alias.clone(), HostOutcome::Cancelled);
            }
            let request = HelperShip {
                host: &host,
                built: &built,
                staged: &staged,
                install_path: &install_path,
                ui: &ui,
                log_file: &log_file,
                config,
                cancel: &cancel,
            };
            match ship_helper(request).await {
                Ok(()) => {
                    ui.lock().await.masked_note(&format!("[{}] helper installed", host.alias));
                    (host.alias.clone(), HostOutcome::Ok)
                }
                Err(err) => {
                    ui.lock()
                        .await
                        .masked_note(&format!("[{}] helper install failed: {err}", host.alias));
                    (host.alias.clone(), HostOutcome::Failed(RunError::Transport))
                }
            }
        });
    }
    let mut out = Vec::new();
    while let Some(res) = tasks.join_next().await {
        match res {
            Ok(pair) => {
                ui.lock().await.host_finished(&pair.0);
                out.push(pair);
            }
            Err(_) => out.push(("unknown".to_string(), HostOutcome::Failed(RunError::Transport))),
        }
    }
    Ok(out)
}

/// The source tree to build the helper from.
fn resolve_helper_source(step: &shellflow_core::HelperStep) -> eyre::Result<PathBuf> {
    let candidate =
        step.source.clone().or_else(|| std::env::var("SHELLFLOW_SRC").ok()).ok_or_else(|| {
            eyre::eyre!(
                "the helper source is unknown: pass `--source <dir>` to `@helper`, or export \
                 SHELLFLOW_SRC"
            )
        })?;
    let path = PathBuf::from(candidate);
    if !path.is_dir() {
        return Err(eyre::eyre!("the helper source `{}` is not a directory", path.display()));
    }
    if !path.join("Cargo.toml").exists() {
        return Err(eyre::eyre!(
            "the helper source `{}` has no Cargo.toml: it is not the shellflow workspace",
            path.display()
        ));
    }
    Ok(path)
}

/// Copy the helper to the target and install it atomically.
///
/// Both children run under the step supervisor: process-group isolated, bound
/// by the step timeout, and observing cooperative cancellation, so a hung
/// transfer cannot hang the step and `Ctrl-C` leaves no orphan.
struct HelperShip<'a> {
    host: &'a ResolvedHost,
    built: &'a Path,
    staged: &'a str,
    install_path: &'a str,
    ui: &'a ArcUi,
    log_file: &'a LogFile,
    config: StepConfig,
    cancel: &'a Cancel,
}

/// Copy the helper to the target and install it atomically.
async fn ship_helper(request: HelperShip<'_>) -> eyre::Result<()> {
    let HelperShip { host, built, staged, install_path, ui, log_file, config, cancel } = request;
    use crate::executor::process::{GroupGuard, isolate};
    async fn supervised_output(
        mut cmd: Command,
        timeout: Option<u64>,
        cancel: &Cancel,
    ) -> eyre::Result<std::process::Output> {
        isolate(&mut cmd);
        cmd.kill_on_drop(true);
        let child = cmd.spawn().map_err(|err| eyre::eyre!("spawn failed: {err}"))?;
        let mut guard = GroupGuard::new(&child);
        let mut cancel_clone = cancel.clone();
        let timeout_dur = timeout.map(Duration::from_secs);
        let output_fut = child.wait_with_output();
        tokio::pin!(output_fut);
        // The guard owns the group kill: on timeout/cancel the future (and
        // its child) is dropped, then the guard SIGKILLs the whole group.
        // `kill_on_drop` alone would reap only the direct child.
        let output = tokio::select! {
            result = &mut output_fut => result.map_err(|err| eyre::eyre!("wait failed: {err}"))?,
            () = async {
                if let Some(dur) = timeout_dur {
                    tokio::time::sleep(dur).await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {
                drop(guard);
                // Reap the group kill promptly.
                return Err(eyre::eyre!("timed out — killed"));
            }
            () = cancel_clone.cancelled() => {
                drop(guard);
                return Err(eyre::eyre!("cancelled"));
            }
        };
        guard.disarm();
        Ok(output)
    }
    let timeout = config.timeout;
    if cancel.is_cancelled() {
        return Err(eyre::eyre!("cancelled"));
    }
    let mut rsync = Command::new("rsync");
    rsync.args(["-a", "-z"]);
    let remote_shell = host.spec.rsync_remote_shell();
    if let Some(shell) = &remote_shell {
        rsync.args(["-e", shell]);
    }
    rsync.arg(built).arg(format!("{}:{staged}", host.spec.dest()));
    rsync.stdout(Stdio::piped()).stderr(Stdio::piped());
    rsync.stdin(Stdio::null());
    let output = supervised_output(rsync, timeout, cancel)
        .await
        .map_err(|err| eyre::eyre!("rsync failed: {err}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(eyre::eyre!("rsync exited with {}: {}", output.status, stderr.trim()));
    }
    let _ = ui;
    let _ = log_file;

    if cancel.is_cancelled() {
        return Err(eyre::eyre!("cancelled"));
    }
    let mut cmd = Command::new("ssh");
    cmd.args(["-o", "BatchMode=yes"]);
    cmd.args(host.spec.to_ssh_args()).arg("-T").arg(helper_install_command(staged, install_path));
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    cmd.stdin(Stdio::null());
    let output = supervised_output(cmd, timeout, cancel)
        .await
        .map_err(|err| eyre::eyre!("ssh failed: {err}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(eyre::eyre!("the install failed: {}", stderr.trim()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        ServiceActions, backup_command, credstore_command, helper_install_command, install_command,
        install_fallback, service_command, service_fallback, unit_inventory_command,
    };

    #[test]
    fn a_service_command_prefers_the_helper() {
        let cmd = service_command(
            "dufs.service",
            ServiceActions {
                enable: true,
                restart: true,
                wait: true,
                verify: true,
                ..ServiceActions::default()
            },
            300,
        );
        assert!(cmd.contains("/usr/local/bin/shellflow host service"), "{cmd}");
        assert!(cmd.contains("'dufs.service'"), "{cmd}");
        assert!(cmd.contains("--enable"), "{cmd}");
        assert!(cmd.contains("--restart"), "{cmd}");
        assert!(cmd.contains("--wait"), "{cmd}");
        assert!(cmd.contains("--verify"), "{cmd}");
    }

    #[test]
    fn a_service_fallback_never_starts_a_stopped_unit() {
        let fallback = service_fallback("dufs.service", false, false, false);
        assert!(fallback.contains("was=0"), "{fallback}");
        assert!(fallback.contains("left it stopped"), "{fallback}");
        assert!(fallback.contains("[ \"0\" = 1 ]"), "{fallback}");
        // The unit is verified before the manager is reloaded.
        let verify = fallback.find("systemd-analyze verify").expect("verify");
        let reload = fallback.find("daemon-reload").expect("daemon-reload");
        assert!(verify < reload, "{fallback}");
    }

    #[test]
    fn a_forced_service_may_start_a_stopped_unit() {
        let fallback = service_fallback("dufs.service", false, false, true);
        assert!(fallback.contains("[ \"1\" = 1 ]"), "{fallback}");
    }

    #[test]
    fn an_install_fallback_is_atomic() {
        let fallback = install_fallback("/tmp/a", "/etc/b", Some(0o644), Some("root:root"));
        assert!(fallback.contains(".shellflow-new"), "{fallback}");
        assert!(fallback.contains("mv -f"), "{fallback}");
        assert!(fallback.contains("chown root:root"), "{fallback}");
        assert!(fallback.contains("chmod 644"), "{fallback}");
    }

    #[test]
    fn an_install_command_carries_the_mode() {
        let cmd = install_command("/tmp/a", "/etc/b", Some(0o644), Some("root:root"), None);
        assert!(cmd.contains("host install"), "{cmd}");
        assert!(cmd.contains("--mode"), "{cmd}");
        assert!(cmd.contains("644"), "{cmd}");
    }

    #[test]
    fn a_backup_command_needs_the_helper() {
        let cmd = backup_command(&["/etc/a".to_string()], Some("dufs"), None, Some(5), true);
        assert!(cmd.contains("/usr/local/bin/shellflow host backup"), "{cmd}");
        assert!(cmd.contains("--keep"), "{cmd}");
        assert!(cmd.contains("--seal"), "{cmd}");
    }

    #[test]
    fn a_credstore_command_carries_the_required_keys() {
        let cmd = credstore_command("dufs", &["TOKEN".to_string(), "API_KEY".to_string()]);
        assert!(cmd.contains("--require"), "{cmd}");
        assert!(cmd.contains("TOKEN,API_KEY"), "{cmd}");
    }

    #[test]
    fn an_inventory_command_needs_the_helper() {
        let cmd = unit_inventory_command();
        assert!(cmd.contains("/usr/local/bin/shellflow host inventory"), "{cmd}");
    }

    #[test]
    fn the_helper_install_is_atomic() {
        let cmd = helper_install_command("/tmp/.shellflow-helper-abc", "/usr/local/bin/shellflow");
        assert!(cmd.contains(".shellflow-new"), "{cmd}");
        assert!(cmd.contains("mv -f"), "{cmd}");
        // the helper lands in a root-owned directory: every step is elevated
        assert!(cmd.contains("sudo cp"), "{cmd}");
        assert!(cmd.contains("sudo mv -f"), "{cmd}");
    }
}
