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

use sha2::{Digest, Sha256};
use shellflow_core::ResolvedHost;
use tokio::{process::Command, sync::Semaphore};

use crate::executor::{
    ArcUi, HostOutcome, LogFile, RunError, StepConfig, cancel::Cancel, fanout_slot, stream,
};

/// The exit code the target helper uses for "the condition did not hold".
const EXIT_FAILED: i32 = 3;

/// The exit code the target helper uses for "the budget expired".
const EXIT_TIMEOUT: i32 = 4;

/// Where the target-side helper is installed.
pub(crate) const HELPER_PATH: &str = "/usr/local/bin/shellflow";

/// Quote a value for the remote shell.
pub(super) fn quote(value: &str) -> String {
    shellflow_core::shell_quote_single(value)
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
    /// Which step class this command is (drives the muxy policy).
    #[cfg(feature = "muxy")]
    pub step_class: crate::executor::StepClass,
    /// Per-run muxy state.
    #[cfg(feature = "muxy")]
    pub muxy: &'a crate::executor::muxy::MuxyRun,
    /// The 1-based plan index (names the muxy payload file).
    #[cfg(feature = "muxy")]
    pub step_no: usize,
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
        #[cfg(feature = "muxy")]
        step_class,
        #[cfg(feature = "muxy")]
        muxy,
        #[cfg(feature = "muxy")]
        step_no,
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
        #[cfg(feature = "muxy")]
        let muxy = muxy.clone();
        tasks.spawn(async move {
            let _permit = fanout_slot!(&semaphore, &log_file, host);
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
            #[cfg(feature = "muxy")]
            {
                let muxy_env = crate::executor::remote::with_login_path(
                    payload_env.clone(),
                    remote_env.path.as_deref(),
                );
                match super::muxy::exec_command(super::muxy::CommandStep {
                    ui: &ui,
                    host: &host,
                    class: step_class,
                    command: command.clone(),
                    env: muxy_env,
                    has_secrets: secrets.has_for_host(&host.alias),
                    probe_muxy: remote_env.has_muxy,
                    timeout: Some(budget.as_secs() + 30),
                    config,
                    log_file: &log_file,
                    cancel: &cancel,
                    muxy: &muxy,
                    step_no,
                    transform: None,
                    explain_exit: None,
                })
                .await
                {
                    super::muxy::CommandAttempt::Done(pair) => return pair,
                    super::muxy::CommandAttempt::Fallback => {}
                }
            }
            let payload = match (super::transport::Payload {
                script: &command,
                guard: None,
                trace: false,
                env: payload_env,
                timeout: Some(budget.as_secs() + 30),
            })
            .render_ssh()
            {
                Ok(payload) => payload,
                Err(_) => {
                    return (host.alias.clone(), HostOutcome::Failed(RunError::Plan));
                }
            };
            let mut cmd = super::transport::ssh_stdin_command(
                &host,
                remote_env.shell.invoke(false),
                config.ssh_reuse,
                config.verbose >= 3,
            );
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
    Ok(stream::collect_hosts(ui, log_file, tasks).await)
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
    let fallback = service_fallback(
        unit,
        actions.enable,
        actions.reload,
        actions.wait,
        actions.force_start,
        timeout,
    );
    helper_command("service", &args, &fallback)
}

/// The inline fallback for `@service`, for a host that has never seen this
/// shellflow.
///
/// The rules are the ones the helper implements: the unit is verified before
/// the manager is reloaded, and it is restarted only when it was running.
fn service_fallback(
    unit: &str,
    enable: bool,
    reload: bool,
    wait: bool,
    force_start: bool,
    timeout: u64,
) -> String {
    let enable = if enable { "$SC enable \"$u\"; " } else { "" };
    let reload = if reload { "$SC reload \"$u\"; " } else { "" };
    let force = if force_start { "1" } else { "0" };
    let wait = if wait {
        format!(
            "if [ \"$was\" = 1 ] || [ \"{force}\" = 1 ]; then \
               d=$(( $(date +%s) + {timeout} )); \
               while :; do \
                 if $SC is-active --quiet \"$u\"; then echo \"$u is active\"; break; fi; \
                 if $SC is-failed --quiet \"$u\"; then echo \"$u failed\" >&2; exit 1; fi; \
                 if [ \"$(date +%s)\" -ge \"$d\" ]; then \
                   echo \"timed out waiting for $u\" >&2; exit 3; \
                 fi; \
                 sleep 2; \
               done; \
             else echo \"$u was left stopped: not waiting for readiness\"; fi; "
        )
    } else {
        String::new()
    };
    format!(
        "u={u}; \
         if [ \"$(id -u)\" = 0 ]; then SC=systemctl; else SC='sudo -n systemctl'; fi; \
         was=$($SC is-active \"$u\" 2>/dev/null || true); \
         case \"$was\" in \"\"|inactive|unknown) was=0 ;; *) was=1 ;; esac; \
         if command -v systemd-analyze >/dev/null 2>&1; then \
           systemd-analyze verify \"$u\" >/dev/null 2>&1 \
             || {{ echo \"unit $u failed verification\" >&2; exit 1; }}; \
         fi; \
         $SC daemon-reload; \
         {enable}\
         {reload}\
         if [ \"$was\" = 1 ]; then $SC restart \"$u\"; \
         elif [ \"{force}\" = 1 ]; then $SC start \"$u\"; \
         else echo \"$u was not running: left it stopped\"; fi; \
         {wait}",
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
    let chown = owner.map_or_else(String::new, |o| format!("chown {} \"$t\" && ", quote(o)));
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
/// The key is a hash of the build **inputs**, not of a VCS pointer or one
/// manifest's mtime: a modified `.rs` file, a changed `Cargo.lock`, and a
/// dirty checkout all produce a new key. The old scheme reused a stale helper
/// after any edit that did not touch `Cargo.toml`.
///
/// In a git checkout the input set is the one git reports (tracked files plus
/// unignored new ones), so generated trees (`target/`, fuzz corpora,
/// `mutants.out/`) are excluded by the same rules that keep them out of a
/// commit. A plain directory is walked instead, skipping VCS metadata,
/// hidden directories and `target`/`mutants.out` by name.
pub(crate) fn source_revision(source: &Path) -> eyre::Result<String> {
    let mut hasher = Sha256::new();
    match git_inputs(source) {
        Some(files) => hash_files(source, &files, &mut hasher)?,
        None => hash_tree(source, source, &mut hasher)?,
    }
    // `Cargo.lock` is ignored by this repository's `.gitignore`, so git does
    // not report it even though the helper's dependency set — and therefore
    // the binary — changes with it.
    let lock = source.join("Cargo.lock");
    if lock.is_file() {
        hash_file(Path::new("Cargo.lock"), &lock, &mut hasher)?;
    }
    let digest = hasher.finalize();
    let mut revision = String::with_capacity(12);
    for byte in digest.iter().take(6) {
        use std::fmt::Write as _;
        // Writing to a `String` cannot fail.
        let _ = write!(revision, "{byte:02x}");
    }
    Ok(revision)
}

/// The files git considers part of the worktree: tracked files plus untracked
/// ones that are not ignored.
///
/// Returns `None` when git is unavailable or `source` is not a checkout, so
/// the caller falls back to walking the tree.
fn git_inputs(source: &Path) -> Option<Vec<PathBuf>> {
    use std::os::unix::ffi::OsStrExt as _;

    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(source)
        .args(["ls-files", "-z", "--cached", "--others", "--exclude-standard"])
        .stdin(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let mut files: Vec<PathBuf> = out
        .stdout
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .map(|path| PathBuf::from(std::ffi::OsStr::from_bytes(path)))
        .collect();
    if files.is_empty() {
        return None;
    }
    files.sort();
    Some(files)
}

/// Hash `files`, whose paths are relative to `root`.
fn hash_files(root: &Path, files: &[PathBuf], hasher: &mut Sha256) -> eyre::Result<()> {
    for rel in files {
        hash_file(rel, &root.join(rel), hasher)?;
    }
    Ok(())
}

/// Hash one file's relative name, length and contents.
///
/// A tracked file can be absent from the worktree (a sparse or partial
/// checkout); the absence is part of the key instead of an error.
fn hash_file(rel: &Path, path: &Path, hasher: &mut Sha256) -> eyre::Result<()> {
    hasher.update(rel.as_os_str().as_encoded_bytes());
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(err) => return Err(eyre::eyre!("cannot read `{}`: {err}", path.display())),
    };
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(&bytes);
    Ok(())
}

/// Hash a tree that git cannot describe, skipping what is not a build input.
///
/// Symlinks are never followed: a link that points back into the tree would
/// recurse forever, so its target is hashed instead. Hidden directories,
/// `target/` and `mutants.out/` are generated state, not sources.
fn hash_tree(root: &Path, dir: &Path, hasher: &mut Sha256) -> eyre::Result<()> {
    let mut entries: Vec<std::fs::DirEntry> = std::fs::read_dir(dir)
        .map_err(|err| eyre::eyre!("cannot read `{}`: {err}", dir.display()))?
        .flatten()
        .collect();
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let rel = path.strip_prefix(root).unwrap_or(&path);
        let file_type = entry
            .file_type()
            .map_err(|err| eyre::eyre!("cannot inspect `{}`: {err}", path.display()))?;
        if file_type.is_symlink() {
            hasher.update(rel.as_os_str().as_encoded_bytes());
            let target = std::fs::read_link(&path)
                .map_err(|err| eyre::eyre!("cannot read the link `{}`: {err}", path.display()))?;
            hasher.update(target.as_os_str().as_encoded_bytes());
            continue;
        }
        if file_type.is_dir() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with('.') || matches!(name.as_ref(), "target" | "mutants.out") {
                continue;
            }
            hash_tree(root, &path, hasher)?;
            continue;
        }
        hash_file(rel, &path, hasher)?;
    }
    Ok(())
}

/// The cached helper for a source revision and target triple.
///
/// Returns the binary **and** the revision it was built from, so the staging
/// path can reuse the exact key the cache used.
pub(crate) fn cached_helper(source: &Path, triple: &str) -> eyre::Result<(PathBuf, String)> {
    let revision = source_revision(source)?;
    let dir = cache_dir().join(format!("helper-{revision}-{triple}"));
    let binary = dir.join("shellflow");
    if binary.exists() {
        return Ok((binary, revision));
    }
    std::fs::create_dir_all(&dir)
        .map_err(|err| eyre::eyre!("cannot create `{}`: {err}", dir.display()))?;
    build_helper(source, triple, &binary)?;
    Ok((binary, revision))
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
    let (built, revision) = match tokio::task::spawn_blocking(move || {
        cached_helper(&source_for_build, &triple_for_build)
    })
    .await
    {
        Ok(Ok((path, revision))) => (path, revision),
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
            let _permit = fanout_slot!(&semaphore, &log_file, host);
            if cancel.is_cancelled() {
                return (host.alias.clone(), HostOutcome::Cancelled);
            }
            let request = HelperShip {
                host: &host,
                built: &built,
                staged: &staged,
                install_path: &install_path,
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
    Ok(stream::collect_hosts(ui, log_file, tasks).await)
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
    config: StepConfig,
    cancel: &'a Cancel,
}

/// Copy the helper to the target and install it atomically.
async fn ship_helper(request: HelperShip<'_>) -> eyre::Result<()> {
    let HelperShip { host, built, staged, install_path, config, cancel } = request;
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
    // The copy must fail closed like every other transfer: rsync starts its
    // own ssh, so it has to be told not to prompt.
    rsync.args(["-e", &host.spec.rsync_transport()]);
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
        install_fallback, service_command, service_fallback, source_revision,
        unit_inventory_command,
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
        let fallback = service_fallback("dufs.service", false, false, false, false, 300);
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
        let fallback = service_fallback("dufs.service", false, false, false, true, 300);
        assert!(fallback.contains("[ \"1\" = 1 ]"), "{fallback}");
    }

    #[test]
    fn a_service_fallback_waits_for_readiness_and_elevates() {
        let fallback = service_fallback("dufs.service", false, false, true, false, 42);
        assert!(fallback.contains("sudo -n systemctl"), "{fallback}");
        assert!(fallback.contains("is-active --quiet"), "{fallback}");
        assert!(fallback.contains("is-failed --quiet"), "{fallback}");
        assert!(fallback.contains("+ 42"), "the wait must carry the budget: {fallback}");
        assert!(fallback.contains("left stopped: not waiting"), "{fallback}");
    }

    #[test]
    fn a_service_fallback_restarts_a_failed_unit() {
        let fallback = service_fallback("dufs.service", false, false, false, false, 300);
        // The helper treats everything except an explicitly inactive state
        // as worth restarting: a failed unit is restarted, and so is one
        // that is still activating. The fallback must not drift from it.
        assert!(fallback.contains("\"\"|inactive|unknown"), "{fallback}");
        assert!(!fallback.contains("|failed)"), "{fallback}");
    }

    #[test]
    fn an_install_fallback_quotes_the_owner() {
        let fallback = install_fallback("/tmp/a", "/etc/b", None, Some("root;id"));
        assert!(fallback.contains("chown 'root;id'"), "{fallback}");
        assert!(!fallback.contains("chown root;id"), "{fallback}");
    }

    #[test]
    fn an_install_fallback_is_atomic() {
        let fallback = install_fallback("/tmp/a", "/etc/b", Some(0o644), Some("root:root"));
        assert!(fallback.contains(".shellflow-new"), "{fallback}");
        assert!(fallback.contains("mv -f"), "{fallback}");
        assert!(fallback.contains("chown 'root:root'"), "{fallback}");
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
    fn the_helper_cache_key_tracks_source_content() {
        // A non-git tree used to be keyed by Cargo.toml's mtime: editing a
        // .rs file kept the stale helper forever. The key now hashes the
        // source itself.
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("src")).expect("src");
        std::fs::write(dir.path().join("Cargo.toml"), "[workspace]\n").expect("manifest");
        std::fs::write(dir.path().join("src/main.rs"), "fn main() {}\n").expect("main");
        let first = source_revision(dir.path()).expect("first revision");
        std::fs::write(dir.path().join("src/main.rs"), "fn main() { let _ = 1; }\n").expect("main");
        let second = source_revision(dir.path()).expect("second revision");
        assert_ne!(first, second, "editing a source file must invalidate the helper cache");
    }

    #[test]
    fn the_helper_cache_key_ignores_build_output() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("Cargo.toml"), "[workspace]\n").expect("manifest");
        let first = source_revision(dir.path()).expect("first revision");
        std::fs::create_dir_all(dir.path().join("target/debug")).expect("target");
        std::fs::write(dir.path().join("target/debug/shellflow"), "binary").expect("binary");
        let second = source_revision(dir.path()).expect("second revision");
        assert_eq!(first, second, "build output must not change the cache key");
    }

    #[test]
    fn the_helper_cache_key_tracks_a_dirty_git_checkout() {
        // In a checkout the input set is git's: a modified tracked file counts
        // even though HEAD is unchanged, ignored output does not, and a new
        // unignored source file does.
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        std::fs::create_dir_all(root.join("src")).expect("src");
        std::fs::write(root.join("Cargo.toml"), "[workspace]\n").expect("manifest");
        std::fs::write(root.join("src/main.rs"), "fn main() {}\n").expect("main");
        std::fs::write(root.join(".gitignore"), "/target/\n").expect("gitignore");
        for args in [["init", "-q"], ["add", "."]] {
            let out = std::process::Command::new("git")
                .arg("-C")
                .arg(root)
                .args(args)
                .output()
                .expect("git");
            assert!(out.status.success(), "git {args:?}: {:?}", out.stderr);
        }

        let first = source_revision(root).expect("first revision");
        std::fs::write(root.join("src/main.rs"), "fn main() { let _ = 1; }\n").expect("main");
        let second = source_revision(root).expect("second revision");
        assert_ne!(first, second, "a dirty tracked file must invalidate the cache");

        std::fs::create_dir_all(root.join("target/debug")).expect("target");
        std::fs::write(root.join("target/debug/shellflow"), "binary").expect("binary");
        let third = source_revision(root).expect("third revision");
        assert_eq!(second, third, "ignored build output must not invalidate the cache");

        std::fs::write(root.join("src/extra.rs"), "pub fn extra() {}\n").expect("extra");
        let fourth = source_revision(root).expect("fourth revision");
        assert_ne!(third, fourth, "an unignored new source file must invalidate the cache");
    }

    #[test]
    fn the_helper_cache_key_ignores_generated_caches() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        std::fs::write(root.join("Cargo.toml"), "[workspace]\n").expect("manifest");
        let first = source_revision(root).expect("first revision");
        std::fs::create_dir_all(root.join("mutants.out/diff")).expect("generated");
        std::fs::write(root.join("mutants.out/diff/m.diff"), "diff").expect("diff");
        std::fs::create_dir_all(root.join(".cache")).expect("cache");
        std::fs::write(root.join(".cache/blob"), "cache").expect("blob");
        let second = source_revision(root).expect("second revision");
        assert_eq!(first, second, "generated trees must not invalidate the cache");
    }

    #[test]
    fn the_helper_cache_key_does_not_follow_a_symlinked_directory() {
        // A link back into the tree used to recurse until the stack ran out.
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        std::fs::write(root.join("Cargo.toml"), "[workspace]\n").expect("manifest");
        std::os::unix::fs::symlink(root, root.join("loop")).expect("symlink");
        let _ = source_revision(root).expect("a symlinked directory must not be followed");
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
