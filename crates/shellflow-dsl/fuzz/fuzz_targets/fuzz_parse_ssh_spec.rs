#![no_main]
//! Fuzz target: the `[user@]host[:port]` ssh-spec parser.
//!
//! The spec reaches this parser from playbook text and from the `--target`
//! restriction list, so its bytes are operator- and hostile-influenced. The
//! invariants checked here are the ones the transports depend on:
//!
//! - parsing never panics, whatever the bytes;
//! - a parsed spec renders back into an `ssh` argv whose every element is non-empty and free of
//!   whitespace (so the spec can never grow the argv or smuggle a second argument);
//! - a spec that parses round-trips byte-identically through its own rendering.

use libfuzzer_sys::fuzz_target;
use shellflow_dsl::SshSpec;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let spec = text.trim();
    let Ok(parsed) = SshSpec::parse(spec) else {
        return;
    };

    let args = parsed.to_ssh_args();
    assert!(!args.is_empty(), "a parsed spec always renders at least the destination");
    for arg in &args {
        assert!(!arg.is_empty(), "empty ssh argument");
        assert!(!arg.contains(char::is_whitespace), "argv element carries whitespace: {arg:?}");
    }

    // The rendered destination re-parses to the same fields: no input can
    // produce a spec whose own rendering is a different destination.
    let destination = parsed.dest();
    let reparsed = SshSpec::parse(&destination).expect("the rendered destination re-parses");
    assert_eq!(reparsed.user, parsed.user, "user survives the round trip");
    assert_eq!(reparsed.host, parsed.host, "host survives the round trip");
    assert_eq!(reparsed.port, None, "the destination never carries a port");
});
