//! `shellflow service manifest` / `shellflow service verify` — the
//! integrity list of what a service actually runs.
//!
//! A manifest is the sha256 of every file under a deployed tree, sorted by
//! path. It answers two questions that a deploy otherwise leaves open:
//!
//! * *Is what runs the thing the repository describes?* — `verify` recomputes the manifest on the
//!   host and compares it with a saved one; a changed, missing or extra file is drift.
//! * *Did the transfer land intact?* — the manifest is computed from the files on the host, so it
//!   is a statement about the host, not about the controller's copy.
//!
//! The manifest is plain text (`<sha256>  <path>` per line, with a header
//! naming the roots), so it diffs, greps and version-controls like any
//! other file.

use std::collections::{BTreeMap, BTreeSet};

use shellflow_core::env::shell_quote_single;

use crate::{
    cli::{ServiceManifestArgs, ServiceVerifyArgs},
    rbatch::Batch,
    service::{ServiceError, ServiceError::Other},
};

/// The manifest format marker.
const MANIFEST_VERSION: &str = "# shellflow-manifest v1";

/// A manifest: the roots it covers and the hash of every file under them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Manifest {
    /// The remote paths the manifest was taken over.
    pub(crate) roots: Vec<String>,
    /// Path to sha256, sorted by path.
    pub(crate) entries: BTreeMap<String, String>,
}

impl Manifest {
    /// Render the manifest as text.
    #[must_use]
    pub(crate) fn to_text(&self) -> String {
        let mut out = String::from(MANIFEST_VERSION);
        out.push('\n');
        for root in &self.roots {
            out.push_str(&format!("# root {root}\n"));
        }
        for (path, hash) in &self.entries {
            out.push_str(&format!("{hash}  {path}\n"));
        }
        out
    }

    /// Parse a manifest from text.
    ///
    /// # Errors
    ///
    /// Returns an error when the text is not a manifest this version reads.
    pub(crate) fn from_text(text: &str) -> Result<Self, ServiceError> {
        let mut roots = Vec::new();
        let mut entries = BTreeMap::new();
        // The header identifies the format: check it before the entries, so
        // a foreign file is reported as "not a manifest" rather than as a
        // malformed hash.
        if !text.lines().any(|line| line == MANIFEST_VERSION) {
            return Err(Other(eyre::eyre!(
                "service verify: not a shellflow manifest (missing `{MANIFEST_VERSION}` header)"
            )));
        }
        for line in text.lines() {
            if line.starts_with('#') {
                if let Some(root) = line.strip_prefix("# root ") {
                    roots.push(root.trim().to_string());
                }
                continue;
            }
            let line = line.trim_end();
            if line.is_empty() {
                continue;
            }
            let Some((hash, path)) = line.split_once("  ") else {
                return Err(Other(eyre::eyre!(
                    "service verify: malformed manifest line (want `<sha256>  <path>`): {line}"
                )));
            };
            if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(Other(eyre::eyre!(
                    "service verify: malformed sha256 in manifest line: {line}"
                )));
            }
            entries.insert(path.trim().to_string(), hash.to_string());
        }
        Ok(Self { roots, entries })
    }
}

/// Run `service manifest`.
///
/// # Errors
///
/// Returns [`ServiceError::Transport`] when the host is unreachable and
/// [`ServiceError::Other`] when the manifest cannot be written.
pub(crate) fn manifest(args: &ServiceManifestArgs) -> Result<(), ServiceError> {
    if args.paths.is_empty() {
        return Err(Other(eyre::eyre!("service manifest: give at least one --path")));
    }
    let current = compute(&args.host, &args.paths)?;
    let count = current.len();
    let manifest = Manifest { roots: args.paths.clone(), entries: current };
    let text = manifest.to_text();

    match &args.output {
        Some(path) => {
            crate::fsx::write_public_file(path, text.as_bytes()).map_err(|err| {
                Other(eyre::eyre!("service manifest: cannot write {}: {err}", path.display()))
            })?;
            println!("service manifest: {count} file(s) written to {}", path.display());
        }
        None => print!("{text}"),
    }
    Ok(())
}

/// Run `service verify`.
///
/// # Errors
///
/// Returns [`ServiceError::Transport`] when the host is unreachable and
/// [`ServiceError::Other`] when the manifest cannot be read or the host
/// drifted away from it.
pub(crate) fn verify(args: &ServiceVerifyArgs) -> Result<(), ServiceError> {
    let text = std::fs::read_to_string(&args.manifest).map_err(|err| {
        Other(eyre::eyre!("service verify: cannot read {}: {err}", args.manifest.display()))
    })?;
    let expected = Manifest::from_text(&text)?;

    let mut roots = expected.roots.clone();
    for path in &args.paths {
        if !roots.contains(path) {
            roots.push(path.clone());
        }
    }
    if roots.is_empty() {
        return Err(Other(eyre::eyre!("service verify: the manifest names no root; pass --path")));
    }
    let current = compute(&args.host, &roots)?;

    let expected_paths: BTreeSet<&String> = expected.entries.keys().collect();
    let current_paths: BTreeSet<&String> = current.keys().collect();

    let mut drift = 0usize;
    for path in expected_paths.difference(&current_paths) {
        println!("[FAIL] missing on {}: {path}", args.host);
        drift += 1;
    }
    for path in current_paths.difference(&expected_paths) {
        println!("[FAIL] not in the manifest: {path}");
        drift += 1;
    }
    for (path, hash) in &current {
        if let Some(want) = expected.entries.get(path) &&
            want != hash
        {
            println!("[FAIL] changed: {path}");
            drift += 1;
        }
    }

    if drift > 0 {
        return Err(Other(eyre::eyre!("service verify: {drift} file(s) drifted from the manifest")));
    }
    println!("service verify: {} file(s) match the manifest", current.len());
    Ok(())
}

/// Compute the sha256 of every file under the given remote roots.
///
/// # Errors
///
/// Returns [`ServiceError::Transport`] when the host is unreachable.
fn compute(host: &str, roots: &[String]) -> Result<BTreeMap<String, String>, ServiceError> {
    let mut batch = Batch::new();
    for (idx, root) in roots.iter().enumerate() {
        batch.section(
            &format!("r{idx}"),
            &format!(
                "find {} -type f -exec sha256sum {{}} + 2>/dev/null",
                shell_quote_single(root)
            ),
        );
    }
    let sections = batch.run(host)?;

    let mut out = BTreeMap::new();
    for (idx, root) in roots.iter().enumerate() {
        let body = sections.get(&format!("r{idx}")).map_or("", |s| s.body.as_str());
        for line in body.lines() {
            let Some((hash, path)) = line.split_once("  ") else {
                continue;
            };
            let path = path.trim();
            if hash.len() != 64 {
                continue;
            }
            // The path is reported as the host reported it; the root prefix
            // is kept so the manifest names absolute paths.
            let _ = root;
            out.insert(path.to_string(), hash.to_string());
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::Manifest;

    #[test]
    fn a_manifest_round_trips() {
        let text = "# shellflow-manifest v1\n# root /opt/dufs\n\
                    aaaa000000000000000000000000000000000000000000000000000000000000  /opt/dufs/bin/dufs\n";
        let manifest = Manifest::from_text(text).expect("parse");
        assert_eq!(manifest.roots, vec!["/opt/dufs".to_string()]);
        assert_eq!(manifest.entries.len(), 1);
        assert_eq!(manifest.to_text(), text);
    }

    #[test]
    fn a_manifest_without_the_header_is_rejected() {
        let err = Manifest::from_text("aaaa  /opt/x\n").expect_err("should fail");
        assert!(err.to_string().contains("not a shellflow manifest"), "{err}");
    }

    #[test]
    fn a_malformed_hash_is_rejected() {
        let text = "# shellflow-manifest v1\nnothex  /opt/x\n";
        let err = Manifest::from_text(text).expect_err("should fail");
        assert!(err.to_string().contains("malformed sha256"), "{err}");
    }

    #[test]
    fn a_malformed_line_is_rejected() {
        let text = "# shellflow-manifest v1\nno-separator-here\n";
        let err = Manifest::from_text(text).expect_err("should fail");
        assert!(err.to_string().contains("malformed manifest line"), "{err}");
    }
}
