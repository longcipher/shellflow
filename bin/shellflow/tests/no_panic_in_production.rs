//! The production code must not panic on bad input.
//!
//! A deploy tool that panics on a malformed file, a corrupt age blob or an
//! unexpected argument takes the whole run down with a Rust backtrace
//! instead of a diagnosable error. The rule is therefore enforced by a
//! test rather than by convention: the production part of every source
//! file must be free of `unwrap`, `expect`, `panic!` and friends.
//!
//! The check is deliberately simple — it scans the text of every `.rs`
//! file under the workspace's `src/` directories and ignores everything
//! from the first `#[cfg(test)]` module onwards. Comment lines are skipped
//! so that a doc comment mentioning `unwrap` does not trip it.

// The workspace denies `panic`/`unwrap`/`expect` in production code; this
// file is an integration-test crate, so it opts out explicitly rather than
// relying on the lint gate silently skipping test targets.
#![allow(clippy::pedantic, clippy::nursery)]
#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

use std::{
    fs,
    path::{Path, PathBuf},
};

/// The constructs that turn an error into a panic.
const PANIC_MARKERS: &[&str] = &[
    ".unwrap()",
    ".expect(",
    "panic!(",
    "unreachable!(",
    "todo!(",
    "unimplemented!",
];

/// The workspace root (the directory holding the workspace `Cargo.toml`).
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the workspace root is two levels above the binary crate")
        .to_path_buf()
}

/// Every Rust source file of the workspace's production code.
///
/// Only the `src/` directory of a crate is production code: a crate's
/// `tests/` directory holds integration tests, which are allowed to be
/// blunt about their fixtures.
fn production_sources(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for crate_root in ["bin", "crates"] {
        let dir = root.join(crate_root);
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let src = entry.path().join("src");
            if src.is_dir() {
                collect_rs(&src, &mut out);
            }
        }
    }
    out.sort();
    out
}

/// Collect the `.rs` files under `dir`, skipping build output.
fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or_default();
            // `target/` holds build output and `fuzz/` holds its own crate.
            if name == "target" || name == "fuzz" {
                continue;
            }
            collect_rs(&path, out);
            continue;
        }
        if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// The production part of a file: everything before the first test module.
fn production_lines(text: &str) -> Vec<(usize, &str)> {
    let mut out = Vec::new();
    for (idx, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("#[cfg(test)]") {
            break;
        }
        out.push((idx + 1, line));
    }
    out
}

#[test]
fn the_production_code_does_not_panic() {
    let root = workspace_root();
    let mut findings: Vec<String> = Vec::new();
    for path in production_sources(&root) {
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        let relative = path.strip_prefix(&root).unwrap_or(&path).display().to_string();
        for (lineno, line) in production_lines(&text) {
            let trimmed = line.trim_start();
            // A comment is not code: a doc comment may mention `unwrap`.
            if trimmed.starts_with("//") {
                continue;
            }
            for marker in PANIC_MARKERS {
                if line.contains(marker) {
                    findings.push(format!("{relative}:{lineno}: `{marker}` in `{trimmed}`"));
                }
            }
        }
    }
    assert!(
        findings.is_empty(),
        "production code must report errors, not panic:\n{}",
        findings.join("\n")
    );
}
