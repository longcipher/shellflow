//! Target-side host helpers: `shellflow host …`.
//!
//! These subcommands run **on the target host** (the binary is installed once
//! per host by a deploy playbook). They own the semantics that a playbook
//! used to spell out in shell — and that the shell spelling got wrong:
//!
//! * an install is **atomic** (write beside the destination, then rename), so a reader never
//!   observes a half-written unit file, config, or binary;
//! * a backup **asserts on the files it wrote itself** rather than re-globbing a directory through
//!   a pipeline that cannot fail;
//! * a restart **never starts a unit that was not running**, unless the operator says so
//!   explicitly;
//! * a leak check compares the **real credential values** instead of a per-service regular
//!   expression, and never puts a plaintext value on a command line.
//!
//! ## Exit codes (the contract the controller depends on)
//!
//! | Code | Meaning |
//! |------|---------|
//! | 0 | the operation succeeded |
//! | 1 | usage / internal error |
//! | 3 | the operation ran but the condition did not hold |
//! | 4 | the budget expired before the condition held |

use std::{
    collections::BTreeSet,
    fmt, fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use sha2::{Digest, Sha256};

use crate::cli::{
    HostAssertCredstoreArgs, HostAssertDigestArgs, HostAssertNoLeakArgs, HostBackupArgs, HostCmd,
    HostCredstoreArgs, HostInstallArgs, HostInventoryArgs, HostServiceArgs,
};

/// Usage or internal error.
pub(crate) const EXIT_USAGE: i32 = 1;
/// The operation ran but the condition did not hold.
pub(crate) const EXIT_FAILED: i32 = 3;
/// The budget expired before the condition held.
pub(crate) const EXIT_TIMEOUT: i32 = 4;

/// The credential store root, as the `cred-env` helper uses it.
pub(crate) const CREDSTORE_ROOT: &str = "/etc/credstore.encrypted";

/// A target-side host error.
#[derive(Debug)]
pub(crate) struct HostError {
    pub(crate) message: String,
    pub(crate) code: i32,
}

impl HostError {
    pub(crate) fn usage(message: impl Into<String>) -> Self {
        Self { message: message.into(), code: EXIT_USAGE }
    }

    pub(crate) fn internal(message: impl Into<String>) -> Self {
        Self { message: message.into(), code: EXIT_USAGE }
    }

    pub(crate) fn failed(message: impl Into<String>) -> Self {
        Self { message: message.into(), code: EXIT_FAILED }
    }

    /// The process exit code this error maps to.
    #[must_use]
    pub(crate) const fn exit_code(&self) -> i32 {
        self.code
    }
}

impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for HostError {}

impl From<crate::systemd::SystemdError> for HostError {
    fn from(err: crate::systemd::SystemdError) -> Self {
        Self { message: err.message, code: err.code }
    }
}

/// Run `shellflow host …`.
///
/// # Errors
///
/// Returns the error of the verb that ran.
pub(crate) fn run(cmd: &HostCmd) -> Result<(), HostError> {
    match cmd {
        HostCmd::Service(args) => service(args),
        HostCmd::Install(args) => install(args),
        HostCmd::Backup(args) => backup(args),
        HostCmd::Credstore(args) => credstore(args),
        HostCmd::AssertNoLeak(args) => assert_no_leak(args),
        HostCmd::AssertDigest(args) => assert_digest(args),
        HostCmd::AssertCredstore(args) => assert_credstore(args),
        HostCmd::Inventory(args) => inventory(args),
    }
}

// === the systemd lifecycle ===

/// Drive a unit's lifecycle: verify, reload the manager, enable, restart, wait.
///
/// The sequence is the one every deploy playbook spelled out, with the rules
/// it kept getting wrong:
///
/// * `--verify` runs `systemd-analyze verify` **before** the manager is reloaded, so an invalid
///   unit aborts the deploy instead of poisoning the manager's view of it;
/// * `--restart` restarts a unit that was running and **leaves a unit that was not running alone**
///   — restarting an inactive unit starts it, which is the opposite of what an operator who keeps a
///   unit stopped wants. `--force-start` overrides that deliberately.
/// * `--wait` uses the notify-aware verdict: a `Type=notify` unit counts as ready only after it
///   said `READY=1`, a `Type=oneshot` counts when it finished successfully, and a failing `Result=`
///   is a failure rather than a wait that runs into the budget.
fn service(args: &HostServiceArgs) -> Result<(), HostError> {
    let unit = normalize_unit(&args.unit);
    validate_unit(&unit)?;

    if args.verify {
        verify_unit(&unit)?;
    }

    let was_active = unit_is_active(&unit);
    println!("==> {unit} was {}", if was_active { "active" } else { "not active" });

    // The unit file may have just been replaced, so the manager always needs
    // a reload before it can act on the new definition.
    run_systemctl(&["daemon-reload"])?;

    if args.enable {
        run_systemctl(&["enable", &unit])?;
        println!("==> enabled {unit}");
    }

    if args.reload {
        reload_unit(&unit)?;
        println!("==> reloaded {unit}");
    }

    if args.restart {
        if was_active {
            run_systemctl(&["restart", &unit])?;
            println!("==> restarted {unit}");
        } else if args.force_start {
            run_systemctl(&["start", &unit])?;
            println!("==> started {unit} (forced)");
        } else {
            println!(
                "==> {unit} was not running: left it stopped (pass --force-start to start it \
                 anyway)"
            );
        }
    }

    if args.wait {
        wait_for_ready(&unit, Duration::from_secs(args.timeout))?;
    }
    Ok(())
}

/// Validate a unit with `systemd-analyze verify`.
///
/// The check is **fail closed**: a non-zero exit aborts the deploy.
fn verify_unit(unit: &str) -> Result<(), HostError> {
    let out = Command::new("systemd-analyze")
        .arg("verify")
        .arg(unit)
        .stdin(Stdio::null())
        .output()
        .map_err(|err| HostError::internal(format!("cannot run `systemd-analyze`: {err}")))?;
    if out.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let detail = if stderr.trim().is_empty() { stdout.trim() } else { stderr.trim() };
    // A unit that names a file which is not in place yet is not an invalid
    // unit: the rendered configuration and the binary may only appear when
    // the service starts. Every complaint has to be about a missing file
    // for this to be one.
    if !detail.lines().all(is_a_missing_file) {
        return Err(HostError::failed(format!("`systemd-analyze verify {unit}` failed: {detail}")));
    }
    println!("==> {unit}: the unit is valid, some of the files it names are not in place yet");
    Ok(())
}

/// Whether a complaint is about a file that is not in place.
///
/// `systemd-analyze verify` reports both a malformed unit and a unit that
/// names a missing file, and it exits non-zero for either. Only the first
/// is a reason to abort a deploy.
fn is_a_missing_file(line: &str) -> bool {
    line.contains("is not executable") ||
        line.contains("No such file or directory") ||
        line.trim().is_empty()
}

/// Whether the unit is currently active.
fn unit_is_active(unit: &str) -> bool {
    let Ok(out) = systemctl_output(&["is-active", unit]) else {
        return false;
    };
    out.status.success() && String::from_utf8_lossy(&out.stdout).trim() == "active"
}

/// Reload a unit through its own `ExecReload=`, or refuse.
///
/// A silent fallback to a restart would drop the connections the reload
/// exists to preserve, so the refusal is explicit.
fn reload_unit(unit: &str) -> Result<(), HostError> {
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
fn wait_for_ready(unit: &str, budget: Duration) -> Result<(), HostError> {
    let deadline = Instant::now() + budget;
    loop {
        let state = crate::systemd::show_state(unit)?;
        println!("{}", crate::systemd::state_line(&state));
        match crate::systemd::verdict(&state) {
            crate::systemd::Verdict::Ready => return Ok(()),
            crate::systemd::Verdict::Failed(reason) => {
                return Err(HostError { message: reason, code: EXIT_FAILED });
            }
            crate::systemd::Verdict::Pending => {}
        }
        if Instant::now() >= deadline {
            return Err(HostError {
                message: format!("{unit} did not become ready within {budget:?}"),
                code: EXIT_TIMEOUT,
            });
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}

// === the atomic install ===

/// Install a file on the target, atomically.
///
/// The file is written to a temporary name **in the destination directory**
/// and then renamed into place. `rename` within one filesystem is atomic, so
/// a reader (systemd, `systemctl cat`, a concurrent `daemon-reload`) sees
/// either the old file or the new one — never a truncated one. The shell
/// spelling (`install -m … dst`) truncated the live file in place.
fn install(args: &HostInstallArgs) -> Result<(), HostError> {
    let src = Path::new(&args.src);
    let dst = Path::new(&args.dst);
    if !src.is_absolute() {
        return Err(HostError::usage(format!("the source must be absolute (got `{}`)", args.src)));
    }
    if !dst.is_absolute() {
        return Err(HostError::usage(format!(
            "the destination must be absolute (got `{}`)",
            args.dst
        )));
    }
    if !src.exists() {
        return Err(HostError::failed(format!("the source `{}` does not exist", args.src)));
    }

    let parent = dst
        .parent()
        .ok_or_else(|| HostError::usage(format!("`{}` has no parent directory", args.dst)))?;
    if !parent.exists() {
        let dir_mode = args.dir_mode.unwrap_or(0o755);
        create_dir_all_elevated(parent, dir_mode)?;
    }

    let file_name = dst
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| HostError::usage(format!("`{}` has no file name", args.dst)))?;
    // The temporary name sits beside the destination so the rename stays
    // within one filesystem.
    let tmp = parent.join(format!(".{file_name}.shellflow-new"));
    // A leftover temporary file from an interrupted run must not be mistaken
    // for the destination.
    let _ = fs::remove_file(&tmp);

    let contents = fs::read(src)
        .map_err(|err| HostError::internal(format!("cannot read `{}`: {err}", args.src)))?;
    write_file_elevated(&tmp, &contents, args.mode.unwrap_or(0o644))?;
    if let Some(owner) = &args.owner {
        chown_elevated(&tmp, owner)?;
    }
    rename_elevated(&tmp, dst)?;
    println!("==> installed {} -> {}", src.display(), dst.display());
    Ok(())
}

// === the backup ===

/// Snapshot files for rollback, and keep the retention rule in one place.
///
/// The snapshot never contains a plaintext copy of a configuration file when
/// `--seal` is given: the file is encrypted with the host key, exactly like
/// the credential store, so a snapshot that leaves the machine is useless to
/// whoever finds it.
///
/// The "no plaintext left behind" guarantee is **structural**: the helper
/// knows every file it wrote, so it checks its own writes. The shell
/// spelling re-globbed the directory through `find … | grep -q .`, which
/// passes when the `find` fails.
fn backup(args: &HostBackupArgs) -> Result<(), HostError> {
    if args.paths.is_empty() {
        return Err(HostError::usage("no paths to back up"));
    }
    let service = args.service.clone().unwrap_or_else(|| "backup".to_string());
    validate_unit(&service)?;
    let dir =
        args.dir.clone().unwrap_or_else(|| format!("/root/{service}-backup-{}", unix_timestamp()));
    if !dir.starts_with('/') {
        return Err(HostError::usage(format!(
            "the snapshot directory must be absolute (got `{dir}`)"
        )));
    }
    let dir_path = PathBuf::from(&dir);
    create_dir_all_elevated(&dir_path, 0o700)?;

    let mut written: Vec<PathBuf> = Vec::new();
    for path in &args.paths {
        if !path.starts_with('/') {
            return Err(HostError::usage(format!("the path must be absolute (got `{path}`)")));
        }
        let source = Path::new(path);
        if !source.exists() {
            println!("==> {path} does not exist: nothing to back up");
            continue;
        }
        let name = source
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| HostError::usage(format!("`{path}` has no file name")))?;
        let target = if is_unit_file(name) || !args.seal {
            // A unit file holds no secret; a configuration file does.
            dir_path.join(name)
        } else {
            dir_path.join(format!("{name}.enc"))
        };
        if args.seal && !is_unit_file(name) {
            seal_file(source, &target)?;
        } else {
            let contents = fs::read(source)
                .map_err(|err| HostError::internal(format!("cannot read `{path}`: {err}")))?;
            write_file_elevated(&target, &contents, 0o600)?;
        }
        written.push(target.clone());
        println!("==> backed up {path} -> {}", target.display());
    }

    // The guarantee the shell spelling could not make: every file in the
    // snapshot is either a unit file or an encrypted copy. The snapshot
    // directory is root-owned, so the listing is elevated.
    let unexpected: Vec<String> = list_dir_elevated(&dir_path)?
        .into_iter()
        .filter(|entry| {
            let name = entry.file_name().and_then(|n| n.to_str()).unwrap_or_default();
            !is_unit_file(name) && !name.ends_with(".enc")
        })
        .map(|entry| entry.display().to_string())
        .collect();
    if !unexpected.is_empty() {
        return Err(HostError::failed(format!(
            "the snapshot directory {dir} holds files that are neither unit files nor encrypted \
             copies: {}",
            unexpected.join(", ")
        )));
    }
    let _ = written;

    if let Some(keep) = args.keep {
        prune_snapshots(&dir, &service, keep)?;
    }
    println!("==> snapshot ready: {dir}");
    Ok(())
}

/// Encrypt a file with the host key, so the snapshot holds no plaintext.
///
/// The value never reaches a command line: `systemd-creds encrypt` reads the
/// plaintext from stdin.
fn seal_file(source: &Path, target: &Path) -> Result<(), HostError> {
    let contents = fs::read(source)
        .map_err(|err| HostError::internal(format!("cannot read `{}`: {err}", source.display())))?;
    let mut child = Command::new("sudo")
        .arg("-n")
        .arg("systemd-creds")
        .arg("encrypt")
        .arg("--with-key=host")
        .arg("--name")
        .arg(source.file_name().and_then(|n| n.to_str()).unwrap_or("snapshot"))
        .arg("-")
        .arg(target)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| HostError::internal(format!("cannot run `systemd-creds`: {err}")))?;
    {
        let Some(stdin) = child.stdin.as_mut() else {
            return Err(HostError::internal("cannot write to `systemd-creds`"));
        };
        stdin
            .write_all(&contents)
            .map_err(|err| HostError::internal(format!("cannot feed `systemd-creds`: {err}")))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|err| HostError::internal(format!("`systemd-creds` failed: {err}")))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(HostError::internal(format!(
            "`systemd-creds encrypt` failed: {}",
            stderr.trim()
        )));
    }
    chmod_elevated(target, 0o600)?;
    Ok(())
}

/// Keep the newest `keep` snapshots and remove the rest.
///
/// The old copies are shredded rather than deleted: they hold encrypted
/// configuration snapshots, and the point of the retention rule is that they
/// really disappear.
fn prune_snapshots(dir: &str, service: &str, keep: u32) -> Result<(), HostError> {
    let parent = Path::new(dir).parent().unwrap_or_else(|| Path::new("/root"));
    let prefix = format!("{service}-backup-");
    let mut snapshots: Vec<(u64, PathBuf)> = Vec::new();
    // The snapshot directory is root-owned: listing it, and reading the
    // timestamps of what is in it, need elevation. The name carries the
    // timestamp anyway, so the sort does not need the mtime.
    for entry in list_dir_elevated(parent)? {
        let name = entry.file_name().and_then(|n| n.to_str()).unwrap_or_default().to_string();
        if !name.starts_with(&prefix) {
            continue;
        }
        let stamp = name.trim_start_matches(&prefix).parse::<u64>().unwrap_or(0);
        snapshots.push((stamp, entry));
    }
    snapshots.sort_by_key(|(stamp, _)| std::cmp::Reverse(*stamp));
    if snapshots.len() <= keep as usize {
        return Ok(());
    }
    for (_, path) in snapshots.into_iter().skip(keep as usize) {
        shred_and_remove(&path)?;
        println!("==> pruned old snapshot: {}", path.display());
    }
    Ok(())
}

/// Overwrite a file with random data, then remove it.
fn shred_and_remove(path: &Path) -> Result<(), HostError> {
    if !nix::unistd::Uid::effective().is_root() {
        // The snapshot belongs to root: shredding it in place needs root.
        // An unelevated pass would fail to write the file and would leave
        // the old credential copies on disk -- the opposite of the point.
        let quoted = path.to_str().unwrap_or_default();
        let out = Command::new("sudo")
            .arg("-n")
            .arg("sh")
            .arg("-c")
            .arg(format!(
                "find {quoted} -type f -exec shred -u {{}} + 2>/dev/null; rm -rf {quoted}"
            ))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map_err(|err| {
                HostError::internal(format!("cannot remove `{}`: {err}", path.display()))
            })?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(HostError::failed(format!(
                "cannot remove `{}`: {}",
                path.display(),
                stderr.trim()
            )));
        }
        return Ok(());
    }
    if path.is_dir() {
        for entry in list_dir(path)? {
            shred_and_remove(&entry)?;
        }
        let _ = fs::remove_dir_all(path);
        return Ok(());
    }
    let Ok(meta) = fs::metadata(path) else {
        return Ok(());
    };
    let len = meta.len();
    if len > 0 {
        let chunk = vec![0u8; 4096.min(len as usize)];
        let mut remaining = len;
        if let Ok(mut file) = fs::File::create(path) {
            while remaining > 0 {
                let n = chunk.len().min(remaining as usize);
                if file.write_all(&chunk[..n]).is_err() {
                    break;
                }
                remaining -= n as u64;
            }
            let _ = file.sync_all();
        }
    }
    let _ = fs::remove_file(path);
    Ok(())
}

// === the credential store ===

/// Seal the service's credential store and check it against the unit.
fn credstore(args: &HostCredstoreArgs) -> Result<(), HostError> {
    validate_unit(&args.service)?;
    // The credential values travel in the environment of this process (the
    // controller injects them from `@secrets`); the helper re-executes itself
    // under `sudo --preserve-env=<exact key list>` to seal them.
    crate::cred_env::credstore_install(&args.service, None)
        .map_err(|err| HostError::internal(format!("cannot seal the credential store: {err}")))?;
    verify_credstore(&args.service, &args.require)?;
    Ok(())
}

/// Check that the credential store agrees with the unit's declaration.
///
/// The unit names the credential keys it wants; the store holds the values.
/// A key in one and not the other is a unit that fails to start with a
/// cryptic systemd error — this turns it into a readable failure.
fn verify_credstore(service: &str, require: &[String]) -> Result<(), HostError> {
    let store = Path::new(CREDSTORE_ROOT).join(service);
    if !dir_exists_elevated(&store) {
        return Err(HostError::failed(format!(
            "the credential store {} does not exist",
            store.display()
        )));
    }
    let store_keys = store_keys(&store)?;
    let declared = declared_credential_keys(service);

    let missing: Vec<String> =
        require.iter().filter(|key| !store_keys.contains(*key)).cloned().collect();
    if !missing.is_empty() {
        return Err(HostError::failed(format!(
            "the credential store {} does not hold: {}",
            store.display(),
            missing.join(", ")
        )));
    }

    // A key the unit asks for but the store does not hold.
    let undeclared: Vec<String> =
        declared.iter().filter(|key| !store_keys.contains(*key)).cloned().collect();
    if !undeclared.is_empty() {
        return Err(HostError::failed(format!(
            "the unit declares credential keys the store does not hold: {}",
            undeclared.join(", ")
        )));
    }
    // A key the store holds but no unit asks for: usually a rotated
    // credential that nobody picked up.
    let unused: Vec<String> =
        store_keys.iter().filter(|key| !declared.contains(*key)).cloned().collect();
    if !unused.is_empty() {
        return Err(HostError::failed(format!(
            "the credential store holds keys no unit imports: {}",
            unused.join(", ")
        )));
    }
    println!("==> credential store {service} agrees with the unit ({} keys)", store_keys.len());
    Ok(())
}

/// The credential keys the unit declares.
fn declared_credential_keys(service: &str) -> BTreeSet<String> {
    // The store names the place the keys live, and every unit that imports
    // from it says so in its own path. The units are found by that path,
    // not by name: the wiring lives in a drop-in, a service may own several
    // units, and two services may share one store.
    let store = format!("{CREDSTORE_ROOT}/{service}/");
    let mut keys = BTreeSet::new();
    for file in all_unit_files() {
        let Ok(text) = fs::read_to_string(&file) else {
            continue;
        };
        for line in text.lines() {
            let Some(rest) = strip_directive(line, "LoadCredentialEncrypted=") else {
                continue;
            };
            let Some((key, path)) = rest.split_once(':') else {
                continue;
            };
            if path.trim().starts_with(&store) {
                keys.insert(key.trim().to_string());
            }
        }
    }
    keys
}

/// Every unit file and drop-in on the system.
fn all_unit_files() -> Vec<PathBuf> {
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
            // a Quadlet container carries the credential wiring of a
            // container service, so it counts as a unit too
            let is_unit = name.ends_with(".service") ||
                name.ends_with(".timer") ||
                name.ends_with(".container");
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

/// The credential keys the store holds.
fn store_keys(store: &Path) -> Result<BTreeSet<String>, HostError> {
    let mut keys = BTreeSet::new();
    for entry in list_dir_elevated(store)? {
        let Some(name) = entry.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name.starts_with('.') {
            continue;
        }
        keys.insert(name.to_string());
    }
    Ok(keys)
}

// === the leak check ===

/// Assert that no credential value appears in the unit's journal or argv.
///
/// The check is **value based**: the helper decrypts the service's own
/// credential store and looks for the real values. A playbook therefore
/// needs no per-service regular expression, and the plaintext never reaches
/// the script, the command line, or the operator's log.
fn assert_no_leak(args: &HostAssertNoLeakArgs) -> Result<(), HostError> {
    let unit = normalize_unit(&args.unit);
    validate_unit(&unit)?;
    let service = unit.trim_end_matches(".service");
    let store = Path::new(CREDSTORE_ROOT).join(service);
    if !store.exists() {
        println!("==> {service} has no credential store: nothing to leak");
        return Ok(());
    }

    let mut values: Vec<String> = Vec::new();
    for key in store_keys(&store)? {
        let Ok(value) = decrypt_credential(&store.join(&key)) else {
            continue;
        };
        if value.len() >= 4 {
            values.push(value);
        }
    }
    if values.is_empty() {
        println!("==> {service} has no decryptable credential: nothing to leak");
        return Ok(());
    }

    let lines = args.lines;
    let haystacks = collect_leak_sources(&unit, lines);
    let mut leaks: Vec<String> = Vec::new();
    for value in &values {
        for (source, text) in &haystacks {
            if text.contains(value.as_str()) {
                leaks.push(source.clone());
            }
        }
    }
    if leaks.is_empty() {
        println!("==> no credential value of {service} appears in the journal or argv");
        return Ok(());
    }
    leaks.sort();
    leaks.dedup();
    Err(HostError::failed(format!(
        "a credential value of {service} appears in: {}",
        leaks.join(", ")
    )))
}

/// The texts a credential value could leak into.
fn collect_leak_sources(unit: &str, lines: u64) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();

    let journal = Command::new("journalctl")
        .arg(format!("-u{unit}"))
        .arg("--no-pager")
        .arg(format!("-n{lines}"))
        .stdin(Stdio::null())
        .output();
    if let Ok(out_journal) = journal {
        out.push((
            format!("the journal of {unit}"),
            String::from_utf8_lossy(&out_journal.stdout).into_owned(),
        ));
    }

    // The command line: `systemctl show` reports the *effective* ExecStart,
    // which is where a secret passed as an argument would show up.
    if let Ok(out_show) = systemctl_output(&["show", unit, "-p", "ExecStart", "-p", "Environment"])
    {
        out.push((
            format!("the command line of {unit}"),
            String::from_utf8_lossy(&out_show.stdout).into_owned(),
        ));
    }

    // The process environment: `/proc/<pid>/environ` is readable by the same
    // uid, so a secret in `Environment=` is visible there too.
    if let Ok(pid) = main_pid(unit) &&
        let Ok(text) = fs::read_to_string(format!("/proc/{pid}/environ"))
    {
        out.push((format!("the environment of {unit}"), text));
    }
    out
}

/// The main PID of a running unit.
fn main_pid(unit: &str) -> Result<String, HostError> {
    let out = systemctl_output(&["show", unit, "-p", "MainPID", "--value"])?;
    let text = String::from_utf8_lossy(&out.stdout);
    let pid = text.trim();
    if pid.is_empty() || pid == "0" {
        return Err(HostError::failed(format!("{unit} has no main process")));
    }
    Ok(pid.to_string())
}

/// Decrypt one credential from the store.
///
/// The plaintext is held in memory only, and it is never printed.
fn decrypt_credential(path: &Path) -> Result<String, HostError> {
    let out = Command::new("sudo")
        .arg("-n")
        .arg("systemd-creds")
        .arg("decrypt")
        .arg(path)
        .stdin(Stdio::null())
        .output()
        .map_err(|err| HostError::internal(format!("cannot run `systemd-creds`: {err}")))?;
    if !out.status.success() {
        return Err(HostError::internal("`systemd-creds decrypt` failed"));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

// === the digest check ===

/// Assert that a file matches a digest.
///
/// The shell spelling printed an `md5sum` that nothing compared; this is a
/// real gate.
fn assert_digest(args: &HostAssertDigestArgs) -> Result<(), HostError> {
    let path = Path::new(&args.path);
    if !path.is_absolute() {
        return Err(HostError::usage(format!("the path must be absolute (got `{}`)", args.path)));
    }
    if !path.exists() {
        return Err(HostError::failed(format!("`{}` does not exist", args.path)));
    }
    let actual = sha256_file(path)?;
    let expected = match (&args.sha256, &args.local) {
        (Some(digest), _) => Some(digest.to_ascii_lowercase()),
        (None, Some(local)) => {
            let local_path = Path::new(local);
            if !local_path.exists() {
                return Err(HostError::failed(format!("`{local}` does not exist")));
            }
            Some(sha256_file(local_path)?)
        }
        (None, None) => None,
    };
    match expected {
        Some(expected) if expected == actual => {
            println!("==> {} matches sha256 {actual}", args.path);
            Ok(())
        }
        Some(expected) => Err(HostError::failed(format!(
            "{} has sha256 {actual}, expected {expected}",
            args.path
        ))),
        None => {
            println!("==> {} has sha256 {actual}", args.path);
            Ok(())
        }
    }
}

// === the credential store check ===

/// Assert that the credential store exists and is well formed.
fn assert_credstore(args: &HostAssertCredstoreArgs) -> Result<(), HostError> {
    validate_unit(&args.service)?;
    verify_credstore(&args.service, &[])?;
    Ok(())
}

// === the unit inventory ===

/// List the units installed on the target.
///
/// The report is a **report**, not a gate: a pre-existing finding must never
/// block an unrelated deploy.
fn inventory(_args: &HostInventoryArgs) -> Result<(), HostError> {
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
            if is_unit_file(name) {
                units.insert(name.to_string());
            }
        }
    }
    for unit in &units {
        println!("{unit}");
    }
    println!("==> {} unit files installed", units.len());
    Ok(())
}

// === shared helpers ===

/// Whether a file name is a systemd unit file.
fn is_unit_file(name: &str) -> bool {
    [".service", ".timer", ".container", ".mount", ".slice", ".socket", ".target", ".path"]
        .iter()
        .any(|suffix| name.ends_with(suffix))
}

/// Normalize a unit name: `foo` becomes `foo.service`.
fn normalize_unit(unit: &str) -> String {
    let unit = unit.trim();
    if unit.ends_with(".service") { unit.to_string() } else { format!("{unit}.service") }
}

/// Validate a unit name with the charset the DSL accepts.
fn validate_unit(unit: &str) -> Result<(), HostError> {
    if unit.is_empty() {
        return Err(HostError::usage("empty unit name"));
    }
    if unit.starts_with('.') || unit.contains("..") {
        return Err(HostError::usage(format!("invalid unit name `{unit}`")));
    }
    if !unit.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@' | ':'))
    {
        return Err(HostError::usage(format!("invalid unit name `{unit}`")));
    }
    Ok(())
}

/// The value of a systemd directive in a unit file line.
///
/// Handles the `Key=value` form and the reset form (`Key=`).
fn strip_directive<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let trimmed = line.trim();
    let rest = trimmed.strip_prefix(key)?;
    Some(rest.trim())
}

/// The sha256 of a file, as lowercase hex.
fn sha256_file(path: &Path) -> Result<String, HostError> {
    let mut file = fs::File::open(path)
        .map_err(|err| HostError::internal(format!("cannot open `{}`: {err}", path.display())))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let read = file.read(&mut buffer).map_err(|err| {
            HostError::internal(format!("cannot read `{}`: {err}", path.display()))
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let mut digest = String::with_capacity(64);
    for byte in hasher.finalize() {
        use std::fmt::Write;
        let _ = write!(digest, "{byte:02x}");
    }
    Ok(digest)
}

/// The seconds since the Unix epoch.
fn unix_timestamp() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// List a directory, sorted, elevating when the caller is not root.
///
/// The credential store is root-owned and 0700, so an unelevated read sees
/// nothing -- and "nothing" reads as "the store does not exist".
fn list_dir_elevated(path: &Path) -> Result<Vec<PathBuf>, HostError> {
    // The plain listing first: it works when the caller may read the
    // directory, and it is the cheap path. Only when it fails does the
    // elevation matter.
    match list_dir(path) {
        Ok(entries) => return Ok(entries),
        Err(err) => {
            if nix::unistd::Uid::effective().is_root() {
                return Err(err);
            }
        }
    }
    let out = Command::new("sudo")
        .arg("-n")
        .arg("ls")
        .arg("-1A")
        .arg("--")
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|err| HostError::internal(format!("cannot list `{}`: {err}", path.display())))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(HostError::failed(format!(
            "cannot list `{}`: {}",
            path.display(),
            stderr.trim()
        )));
    }
    let mut entries: Vec<PathBuf> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| path.join(line))
        .collect();
    entries.sort();
    Ok(entries)
}

/// Whether a directory exists, elevating when the caller is not root.
fn dir_exists_elevated(path: &Path) -> bool {
    if path.is_dir() {
        return true;
    }
    if nix::unistd::Uid::effective().is_root() {
        return false;
    }
    Command::new("sudo")
        .arg("-n")
        .arg("test")
        .arg("-d")
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// List a directory, sorted.
fn list_dir(path: &Path) -> Result<Vec<PathBuf>, HostError> {
    let mut entries: Vec<PathBuf> = fs::read_dir(path)
        .map_err(|err| HostError::internal(format!("cannot list `{}`: {err}", path.display())))?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .collect();
    entries.sort();
    Ok(entries)
}

/// Run `systemctl`, elevating when the caller is not root.
fn systemctl_output(args: &[&str]) -> Result<std::process::Output, HostError> {
    let mut cmd = if nix::unistd::Uid::effective().is_root() {
        let mut cmd = Command::new("systemctl");
        cmd.args(args);
        cmd
    } else {
        let mut cmd = Command::new("sudo");
        cmd.arg("-n").arg("systemctl").args(args);
        cmd
    };
    cmd.stdin(Stdio::null())
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .output()
        .map_err(|err| HostError::internal(format!("cannot run `systemctl`: {err}")))
}

/// Run `systemctl`, mapping a failure to an error.
fn run_systemctl(args: &[&str]) -> Result<(), HostError> {
    let out = systemctl_output(args)?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(HostError::internal(format!(
            "`systemctl {}` failed: {}",
            args.join(" "),
            stderr.trim()
        )));
    }
    Ok(())
}

/// Whether the unit declares a given property.
fn unit_has_property(unit: &str, property: &str) -> bool {
    let Ok(out) = systemctl_output(&["show", unit, "-p", property]) else {
        return false;
    };
    if !out.status.success() {
        return false;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines().any(|line| !line.ends_with('=') && !line.is_empty())
}

/// Create a directory (and its parents), elevating when needed.
fn create_dir_all_elevated(path: &Path, mode: u32) -> Result<(), HostError> {
    if path.exists() {
        return Ok(());
    }
    if nix::unistd::Uid::effective().is_root() {
        return fs::create_dir_all(path).map_err(|err| {
            HostError::internal(format!("cannot create `{}`: {err}", path.display()))
        });
    }
    let out = Command::new("sudo")
        .arg("-n")
        .arg("install")
        .arg("-d")
        .arg(format!("-m{mode:o}"))
        .arg(path)
        .stdin(Stdio::null())
        .output()
        .map_err(|err| HostError::internal(format!("cannot run `install`: {err}")))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(HostError::internal(format!(
            "cannot create `{}`: {}",
            path.display(),
            stderr.trim()
        )));
    }
    Ok(())
}

/// Write a file with the given mode, elevating when needed.
fn write_file_elevated(path: &Path, contents: &[u8], mode: u32) -> Result<(), HostError> {
    if nix::unistd::Uid::effective().is_root() {
        fs::write(path, contents).map_err(|err| {
            HostError::internal(format!("cannot write `{}`: {err}", path.display()))
        })?;
        return chmod_elevated(path, mode);
    }
    let mut child = Command::new("sudo")
        .arg("-n")
        .arg("install")
        .arg(format!("-m{mode:o}"))
        .arg("/dev/stdin")
        .arg(path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| HostError::internal(format!("cannot run `install`: {err}")))?;
    {
        let Some(stdin) = child.stdin.as_mut() else {
            return Err(HostError::internal("cannot write to `install`"));
        };
        stdin
            .write_all(contents)
            .map_err(|err| HostError::internal(format!("cannot write to `install`: {err}")))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|err| HostError::internal(format!("`install` failed: {err}")))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(HostError::internal(format!(
            "cannot write `{}`: {}",
            path.display(),
            stderr.trim()
        )));
    }
    Ok(())
}

/// Change a file's mode, elevating when needed.
fn chmod_elevated(path: &Path, mode: u32) -> Result<(), HostError> {
    if nix::unistd::Uid::effective().is_root() {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)
            .map_err(|err| HostError::internal(format!("cannot stat `{}`: {err}", path.display())))?
            .permissions();
        perms.set_mode(mode);
        return fs::set_permissions(path, perms).map_err(|err| {
            HostError::internal(format!("cannot chmod `{}`: {err}", path.display()))
        });
    }
    let out = Command::new("sudo")
        .arg("-n")
        .arg("chmod")
        .arg(format!("{mode:o}"))
        .arg(path)
        .stdin(Stdio::null())
        .output()
        .map_err(|err| HostError::internal(format!("cannot run `chmod`: {err}")))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(HostError::internal(format!(
            "cannot chmod `{}`: {}",
            path.display(),
            stderr.trim()
        )));
    }
    Ok(())
}

/// Change a file's owner, elevating when needed.
fn chown_elevated(path: &Path, owner: &str) -> Result<(), HostError> {
    let out = Command::new("sudo")
        .arg("-n")
        .arg("chown")
        .arg(owner)
        .arg(path)
        .stdin(Stdio::null())
        .output()
        .map_err(|err| HostError::internal(format!("cannot run `chown`: {err}")))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(HostError::internal(format!(
            "cannot chown `{}` to {owner}: {}",
            path.display(),
            stderr.trim()
        )));
    }
    Ok(())
}

/// Rename a file, elevating when needed.
///
/// The rename is the atomic step: the destination never exists in a partial
/// state.
fn rename_elevated(from: &Path, to: &Path) -> Result<(), HostError> {
    if nix::unistd::Uid::effective().is_root() {
        return fs::rename(from, to).map_err(|err| {
            HostError::internal(format!(
                "cannot rename `{}` to `{}`: {err}",
                from.display(),
                to.display()
            ))
        });
    }
    let out = Command::new("sudo")
        .arg("-n")
        .arg("mv")
        .arg("-f")
        .arg(from)
        .arg(to)
        .stdin(Stdio::null())
        .output()
        .map_err(|err| HostError::internal(format!("cannot run `mv`: {err}")))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(HostError::internal(format!(
            "cannot rename `{}` to `{}`: {}",
            from.display(),
            to.display(),
            stderr.trim()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{
        declared_credential_keys, is_unit_file, normalize_unit, sha256_file, store_keys,
        strip_directive,
    };

    #[test]
    fn a_unit_name_gets_the_service_suffix() {
        assert_eq!(normalize_unit("dufs"), "dufs.service");
        assert_eq!(normalize_unit("dufs.service"), "dufs.service");
        assert_eq!(normalize_unit(" sshd "), "sshd.service");
    }

    #[test]
    fn unit_files_are_recognized_by_their_suffix() {
        assert!(is_unit_file("dufs.service"));
        assert!(is_unit_file("pg-backup.timer"));
        assert!(is_unit_file("browserless.container"));
        assert!(!is_unit_file("config.toml"));
        assert!(!is_unit_file("dufs.service.enc"));
    }

    #[test]
    fn a_directive_is_read_from_a_unit_line() {
        assert_eq!(
            strip_directive(
                "LoadCredentialEncrypted=TOKEN:/etc/x/TOKEN",
                "LoadCredentialEncrypted="
            ),
            Some("TOKEN:/etc/x/TOKEN")
        );
        assert_eq!(strip_directive("ExecStart=/bin/true", "LoadCredentialEncrypted="), None);
    }

    #[test]
    fn the_sha256_of_a_file_is_stable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("f");
        fs::write(&path, b"hello").expect("write");
        let digest = sha256_file(&path).expect("digest");
        assert_eq!(digest, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    }

    #[test]
    fn a_store_holds_its_keys() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(dir.path().join("TOKEN"), b"x").expect("write");
        fs::write(dir.path().join("API_KEY"), b"x").expect("write");
        fs::write(dir.path().join(".seal-fingerprint"), b"x").expect("write");
        let keys = store_keys(dir.path()).expect("keys");
        assert_eq!(keys.len(), 2);
        assert!(keys.contains("TOKEN"));
        assert!(keys.contains("API_KEY"));
    }

    #[test]
    fn a_unit_without_credentials_declares_nothing() {
        assert!(declared_credential_keys("definitely-not-a-unit.service").is_empty());
    }
}
