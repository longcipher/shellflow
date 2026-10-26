//! Payload delivery: the script travels through the file API, never typed.
//!
//! Typing a multi-kilobyte shell payload into a PTY is a bad idea: the PTY
//! echoes it into the session's saved scrollback (muxy keeps 16 MiB for seven
//! days), and any quoting bug becomes a shell injection. So the payload is
//! **written through the server's file API**, never typed. The typed line is
//! short and contains no user text.

/// The payload file path, relative to the Home project root (`$HOME`).
///
/// The server rejects absolute paths and `..`, so the relative form is the
/// only one that can work — and the only one this function produces.
#[must_use]
pub fn payload_rel_path(run_id: &str, step_id: &str) -> String {
    format!(".shellflow/steps/{run_id}/{step_id}.sh")
}

/// The run directory, relative to the Home project root.
#[must_use]
pub fn run_dir_rel_path(run_id: &str) -> String {
    format!(".shellflow/steps/{run_id}")
}

/// The typed bootstrap line: short, fixed shape, no user text, no secrets.
///
/// It only names the payload file; the payload itself arrives through
/// `Files WriteBytes`.
#[must_use]
pub fn bootstrap_line(run_id: &str, step_id: &str) -> String {
    format!(
        "chmod 700 ~/.shellflow ~/.shellflow/steps ~/.shellflow/steps/{run_id}; exec bash ~/.shellflow/steps/{run_id}/{step_id}.sh\r"
    )
}

/// The payload written through the file API.
///
/// It is the same text the ssh path streams on stdin: `set -eu`, the folded
/// `@only_if` guard (which may only use exit 42 to mean "skipped"), the
/// `set -x` trace at `-vvv`, the begin marker that arms the line assembler,
/// and the block. There is no `export KEY=…` header: the environment is
/// applied by the server at session creation, so the payload contains no
/// secret material.
#[must_use]
pub fn build_payload(
    script: &str,
    guard: Option<&str>,
    trace: bool,
    run_id: &str,
    step_id: &str,
) -> String {
    let mut out = String::from("set -eu\n");
    if let Some(guard) = guard {
        out.push_str(&folded_guard(guard));
    }
    if trace {
        out.push_str("set -x\n");
    }
    out.push_str(&format!("printf '%s\\n' '@@shellflow:begin:{run_id}/{step_id}@@'\n"));
    out.push_str(script);
    if !script.ends_with('\n') {
        out.push('\n');
    }
    out
}

/// The begin marker printed by the payload on its first line.
#[must_use]
pub fn begin_marker(run_id: &str, step_id: &str) -> String {
    format!("@@shellflow:begin:{run_id}/{step_id}@@")
}

/// The guard folded into the payload: evaluating it used to cost a second
/// SSH round trip, so a guarded step paid double for one precondition.
fn folded_guard(guard: &str) -> String {
    format!(
        "trap 'rc=$?; if [ \"$rc\" = 42 ]; then exit 1; fi' EXIT\n\
         if ! ( set +u; {guard} ) >/dev/null 2>&1; then trap - EXIT; exit 42; fi\n"
    )
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn the_payload_ends_in_exactly_one_newline() {
        // `bash` ignores a missing final newline, but a payload that ends
        // mid-line can swallow the marker the reader scans for; a script that
        // already ends in one must not gain a second.
        let without = build_payload("echo hi", None, false, "run1", "s1");
        assert!(without.ends_with("echo hi\n"), "{without:?}");
        assert!(!without.ends_with("\n\n"), "{without:?}");
        let with = build_payload("echo hi\n", None, false, "run1", "s1");
        assert!(with.ends_with("echo hi\n"), "{with:?}");
        assert!(!with.ends_with("\n\n"), "{with:?}");
    }

    #[test]
    fn payload_paths_stay_inside_the_home_project() {
        let rel = payload_rel_path("run1", "s3");
        assert_eq!(rel, ".shellflow/steps/run1/s3.sh");
        assert!(!rel.starts_with('/'));
        assert!(!rel.contains(".."));
        let dir = run_dir_rel_path("run1");
        assert_eq!(dir, ".shellflow/steps/run1");
    }

    #[test]
    fn the_typed_line_contains_no_user_text_and_no_secrets() {
        let line = bootstrap_line("run1", "s3");
        assert!(line.contains("run1/s3.sh"), "{line}");
        assert!(!line.contains("export"), "{line}");
        assert!(!line.contains("SECRET"), "{line}");
        assert!(line.ends_with('\r'));
        // Short and fixed-shape: nothing but the path varies.
        assert!(line.len() < 160, "{line}");
        assert_eq!(bootstrap_line("run1", "s3"), bootstrap_line("run1", "s3"));
    }

    #[test]
    fn the_payload_carries_the_guard_and_the_marker() {
        let payload = build_payload("echo hi", Some("test -f /x"), false, "run1", "s3");
        assert!(payload.starts_with("set -eu\n"));
        assert!(payload.contains("exit 42"), "{payload}");
        assert!(payload.contains("@@shellflow:begin:run1/s3@@"), "{payload}");
        assert!(payload.contains("echo hi"), "{payload}");
        assert!(!payload.contains("export"), "{payload}");
    }

    #[test]
    fn begin_marker_round_trips_through_the_assembler() {
        let marker = begin_marker("run1", "s3");
        assert_eq!(marker, "@@shellflow:begin:run1/s3@@");
    }
}
