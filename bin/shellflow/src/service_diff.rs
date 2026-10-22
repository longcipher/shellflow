//! `shellflow service diff` — compare a file in the repository with the
//! file the target actually runs.
//!
//! A deployed unit drifts: someone edits the unit on the host, a template
//! is rendered from a changed secret, a hand-made edit survives a redeploy
//! because the playbook does not overwrite it. The audit that catches this
//! used to be written by hand in every playbook — a `cmp`, a `diff`, and a
//! rule about what a difference means.
//!
//! This subcommand owns that rule: it fetches the remote file, compares it
//! with the local one, prints a unified diff, and exits non-zero when
//! anything differs.

use std::path::{Path, PathBuf};

use eyre::Result;
use shellflow_core::env::shell_quote_single;

use crate::{
    cli::ServiceDiffArgs,
    diffutil::unified_diff,
    rbatch::Batch,
    service::{ServiceError, ServiceError::Other},
};

/// Run `service diff`.
///
/// # Errors
///
/// Returns [`ServiceError::Other`] when the request is malformed, a file
/// cannot be read, or the target differs from the repository.
pub(crate) fn diff(args: &ServiceDiffArgs) -> Result<(), ServiceError> {
    let pairs = resolve_pairs(args)?;

    // One round trip fetches every remote file.
    let mut batch = Batch::new();
    for (idx, (_, remote)) in pairs.iter().enumerate() {
        batch.section(&format!("f{idx}"), &format!("cat -- {}", shell_quote_single(remote)));
    }
    let sections = batch.run(&args.host)?;

    let mut drift = 0usize;
    for (idx, (local, remote)) in pairs.iter().enumerate() {
        let section = sections.get(&format!("f{idx}"));
        let remote_body = section.map_or("", |s| s.body.as_str());
        let remote_ok = section.is_some_and(|s| s.rc == 0);

        let local_text = match std::fs::read_to_string(local) {
            Ok(text) => text,
            Err(err) => {
                println!("[FAIL] cannot read {}: {err}", local.display());
                drift += 1;
                continue;
            }
        };
        if !remote_ok {
            println!("[FAIL] {remote} is not readable on {} (drift)", args.host);
            drift += 1;
            continue;
        }
        // The remote answer arrives without its trailing newline (the
        // remote's command substitution strips it), so the two sides are
        // compared without their trailing newlines. A difference in the
        // last blank line is not a drift worth failing a deploy over.
        let local_body = local_text.trim_end_matches(['\n', '\r']);
        let remote_body = remote_body.trim_end_matches(['\n', '\r']);
        if local_body == remote_body {
            println!("[ok] {} == {remote}", local.display());
            continue;
        }
        println!("[FAIL] {} != {remote} (drift)", local.display());
        if !args.quiet {
            let local_name = local.display().to_string();
            print!("{}", unified_diff(local_body, remote_body, &local_name, remote));
        }
        drift += 1;
    }

    if drift > 0 {
        return Err(Other(eyre::eyre!(
            "service diff: {drift} drifted file(s) between the repository and {}",
            args.host
        )));
    }
    println!("service diff: {} clean", args.host);
    Ok(())
}

/// The local/remote pairs to compare.
fn resolve_pairs(args: &ServiceDiffArgs) -> Result<Vec<(PathBuf, String)>, ServiceError> {
    if !args.local.is_empty() || !args.remote.is_empty() {
        if args.local.len() != args.remote.len() {
            return Err(Other(eyre::eyre!(
                "service diff: --local and --remote must be given the same number of times \
                 ({} local, {} remote)",
                args.local.len(),
                args.remote.len()
            )));
        }
        let pairs = args
            .local
            .iter()
            .zip(args.remote.iter())
            .map(|(l, r)| (PathBuf::from(l), r.clone()))
            .collect();
        return Ok(pairs);
    }

    let Some(service) = args.service.as_deref() else {
        return Err(Other(eyre::eyre!(
            "service diff: name a service or give --local/--remote pairs"
        )));
    };
    let local = local_unit_for(&args.repo, service)?;
    Ok(vec![(local, format!("/etc/systemd/system/{service}.service"))])
}

/// The repository's unit file for a service.
///
/// The convention is `services/<svc>/<svc>.service`; a service whose unit
/// carries another name (a template, a `.socket` pair) falls back to the
/// single `*.service` file in the service directory.
fn local_unit_for(repo: &Path, service: &str) -> Result<PathBuf, ServiceError> {
    let dir = repo.join("services").join(service);
    let preferred = dir.join(format!("{service}.service"));
    if preferred.is_file() {
        return Ok(preferred);
    }
    let mut candidates: Vec<PathBuf> = match std::fs::read_dir(&dir) {
        Ok(entries) => entries
            .filter_map(std::result::Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "service"))
            .collect(),
        Err(err) => {
            return Err(Other(eyre::eyre!("service diff: cannot read {}: {err}", dir.display())));
        }
    };
    candidates.sort();
    candidates.into_iter().next().ok_or_else(|| {
        Other(eyre::eyre!("service diff: no unit file for `{service}` under {}", dir.display()))
    })
}

#[cfg(test)]
mod tests {
    use super::local_unit_for;
    use crate::service::ServiceError;

    #[test]
    fn the_conventional_unit_is_found() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("services/dufs")).expect("dirs");
        std::fs::write(dir.path().join("services/dufs/dufs.service"), "[Unit]\n").expect("write");
        let found = local_unit_for(dir.path(), "dufs").expect("found");
        assert!(found.ends_with("services/dufs/dufs.service"), "{}", found.display());
    }

    #[test]
    fn a_differently_named_unit_is_found_too() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("services/rpxy")).expect("dirs");
        std::fs::write(dir.path().join("services/rpxy/rpxy.service"), "[Unit]\n").expect("write");
        let found = local_unit_for(dir.path(), "rpxy").expect("found");
        assert!(found.ends_with("services/rpxy/rpxy.service"), "{}", found.display());
    }

    #[test]
    fn a_service_without_a_unit_is_an_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = local_unit_for(dir.path(), "nope").expect_err("should fail");
        assert!(matches!(err, ServiceError::Other(_)), "{err:?}");
    }
}
