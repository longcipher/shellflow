//! Process group lifecycle management: isolate, signal, terminate, and the
//! GroupGuard drop-guard that ensures no orphan process trees survive.

use std::time::Duration;

use nix::{
    sys::signal::{Signal, killpg},
    unistd::Pid,
};
use tokio::process::Child;

use super::KILL_GRACE;

/// Put `cmd` in a fresh process group so its whole tree can be signalled.
///
/// `process_group(0)` makes the child a group leader (its pgid equals its
/// pid), so [`signal_group`] reaches every descendant.
pub(crate) fn isolate(cmd: &mut tokio::process::Command) {
    use std::os::unix::process::CommandExt as _;
    cmd.as_std_mut().process_group(0);
}

/// Signal every process in `pid`'s group, tolerating an already-dead group.
///
/// `pid` must be the pid of a child spawned through [`isolate`], so the group
/// holds only this run's descendants.
pub(crate) fn signal_group(pid: u32, signal: Signal) {
    let _ = killpg(Pid::from_raw(pid as i32), signal);
}

/// Terminate a child and everything it spawned.
///
/// Sends `SIGTERM`, waits up to [`KILL_GRACE`] for the direct child, then
/// escalates to `SIGKILL` for the **whole group**. Safe to call on an
/// already-reaped child.
pub(crate) async fn terminate(child: &mut Child) {
    let Some(pid) = child.id() else {
        return;
    };
    signal_group(pid, Signal::SIGTERM);
    let _ = tokio::time::timeout(KILL_GRACE, child.wait()).await;
    signal_group(pid, Signal::SIGKILL);
    let _ = child.start_kill();
    let _ = child.wait().await;
}

/// Keeps a spawned child's process group from outliving the current scope.
///
/// `Command::kill_on_drop` reaps only the direct child, so a block's
/// background descendants (`cargo` -> `rustc`, `sleep 300 &`) would survive an
/// aborted run and contradict the "no orphans" guarantee. Dropping this guard
/// — which happens on *every* exit path, including a task cancelled by
/// SIGINT — escalates the whole group to `SIGKILL`.
///
/// Call [`GroupGuard::disarm`] once the child has been reaped normally, so a
/// step that finished cleanly signals nothing.
pub(crate) struct GroupGuard(Option<u32>);

impl GroupGuard {
    /// Track the group of an already-spawned child.
    pub(crate) fn new(child: &Child) -> Self {
        Self(child.id())
    }

    /// Stop guarding: the child completed normally.
    pub(crate) const fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for GroupGuard {
    fn drop(&mut self) {
        if let Some(pid) = self.0 {
            signal_group(pid, Signal::SIGKILL);
        }
    }
}

/// Per-step statistics for the final summary.
///
/// `pub(crate)` so `main` can print an interrupt summary from the shared
/// progress list while the plan is cancelled by a signal.
#[derive(Clone, Debug)]
pub(crate) struct StepStats {
    /// 1-based step index.
    pub(crate) index: usize,
    /// Wall-clock duration.
    pub(crate) elapsed: Duration,
    /// Per-host outcomes.
    pub(crate) statuses: Vec<crate::ui::HostStatus>,
}
