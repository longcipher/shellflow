//! Cooperative cancellation for the execution engine.
//!
//! The engine must be able to stop every in-flight child process when the
//! operator interrupts the run. Cancelling by *dropping* the executor's
//! future is not enough: the per-host tasks are aborted asynchronously, so
//! the process-group guards that tear the children down may never run before
//! the process exits — which is exactly how an orphaned `ssh` survives a
//! Ctrl-C.
//!
//! Instead the run is cancelled cooperatively: every host task observes the
//! signal, terminates its own child group, and returns normally. The
//! executor is then awaited to completion, so the teardown is guaranteed to
//! have happened before the process exits.

use tokio::sync::watch;

/// A cooperative cancellation signal.
///
/// Cloning yields an independent receiver, so every host task can observe
/// the same cancellation without sharing a lock.
#[derive(Clone, Debug)]
pub(crate) struct Cancel {
    tx: watch::Sender<bool>,
    rx: watch::Receiver<bool>,
}

impl Cancel {
    /// Create a signal that has not been triggered.
    #[must_use]
    pub(crate) fn new() -> Self {
        let (tx, rx) = watch::channel(false);
        Self { tx, rx }
    }

    /// Request cancellation.
    pub(crate) fn cancel(&self) {
        let _ = self.tx.send(true);
    }

    /// Whether cancellation has been requested.
    pub(crate) fn is_cancelled(&self) -> bool {
        *self.rx.borrow()
    }

    /// Resolve once cancellation has been requested.
    ///
    /// Cancel-safe: dropping the future loses nothing, because the state
    /// lives in the channel rather than in the future.
    pub(crate) async fn cancelled(&mut self) {
        if *self.rx.borrow() {
            return;
        }
        while self.rx.changed().await.is_ok() {
            if *self.rx.borrow() {
                return;
            }
        }
    }
}

impl Default for Cancel {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::Cancel;

    #[tokio::test]
    async fn a_fresh_signal_is_not_cancelled() {
        let cancel = Cancel::new();
        assert!(!cancel.is_cancelled());
    }

    #[tokio::test]
    async fn cancelled_resolves_after_the_signal() {
        let cancel = Cancel::new();
        let mut waiter = cancel.clone();
        let handle = tokio::spawn(async move {
            waiter.cancelled().await;
        });
        cancel.cancel();
        handle.await.expect("the waiter must resolve");
        assert!(cancel.is_cancelled());
    }

    #[tokio::test]
    async fn a_signal_cancelled_before_the_wait_resolves_immediately() {
        let cancel = Cancel::new();
        cancel.cancel();
        let mut waiter = cancel.clone();
        // Must not hang: the flag is checked before the channel is awaited.
        tokio::time::timeout(std::time::Duration::from_secs(1), waiter.cancelled())
            .await
            .expect("an already-cancelled signal must resolve immediately");
    }
}
