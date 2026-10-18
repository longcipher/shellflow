//! Shell-safe environment rendering and secret redaction helpers.

/// The placeholder used when redacting known secret values.
pub const MASK: &str = "***";

/// Single-quote a value for safe inclusion in a `bash` export line.
///
/// A literal `'` is escaped as `'\''`, which is valid inside single quotes.
#[must_use]
pub fn shell_quote_single(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('\'');
    for ch in value.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// Render already-resolved `(key, value)` pairs as `export` lines.
///
/// The returned string is the payload header that precedes any `set -x`
/// tracing, so the exported values themselves are never traced.
#[must_use]
pub fn render_env(entries: &[(String, String)]) -> String {
    let mut out = String::new();
    for (key, value) in entries {
        out.push_str("export ");
        out.push_str(key);
        out.push('=');
        out.push_str(&shell_quote_single(value));
        out.push_str(";\n");
    }
    out
}

/// Redact a value by replacing every occurrence of known secrets with
/// [`MASK`].
///
/// Secrets are masked longest-first (and de-duplicated) so a value that is a
/// prefix of another (e.g. `KEY=abc` vs `KEY_LONG=abcdef`) cannot leave the
/// longer secret's tail exposed after the shorter one is replaced.
#[must_use]
pub fn mask_line(line: &str, secrets: &[String]) -> String {
    if secrets.is_empty() {
        return line.to_string();
    }
    // Longest-first, de-duplicated, non-empty. Sorting a small list per line is
    // cheap and keeps the masking order-independent of caller insertion order.
    let mut ordered: Vec<&String> = secrets.iter().filter(|s| !s.is_empty()).collect();
    ordered.sort_unstable_by_key(|a| std::cmp::Reverse(a.len()));
    ordered.dedup();
    let mut out = line.to_string();
    for secret in ordered {
        out = out.replace(secret, MASK);
    }
    out
}

#[cfg(test)]
mod tests {
    use proptest::prelude::{prop_assert, prop_assert_eq};

    use super::{MASK, mask_line, render_env, shell_quote_single};

    #[test]
    fn quotes_plain_value() {
        assert_eq!(shell_quote_single("abc123"), "'abc123'");
    }

    #[test]
    fn quotes_embedded_single_quote() {
        assert_eq!(shell_quote_single("a'b"), "'a'\\''b'");
    }

    #[test]
    fn renders_export_lines() {
        let entries = vec![
            ("KEY".to_string(), "value".to_string()),
            ("SECRET".to_string(), "s3cr3t".to_string()),
        ];
        let out = render_env(&entries);
        assert_eq!(out, "export KEY='value';\nexport SECRET='s3cr3t';\n");
    }

    #[test]
    fn renders_empty() {
        assert_eq!(render_env(&[]), "");
    }

    #[test]
    fn masks_secret_occurrences() {
        let line = "export DB_PASSWORD='s3cr3t';";
        let redacted = mask_line(line, &["s3cr3t".to_string()]);
        assert_eq!(redacted, "export DB_PASSWORD='***';");
    }

    #[test]
    fn mask_longest_first_avoid_prefix_leak() {
        // The shorter secret is a prefix of the longer one. Masking longest
        // first must not leave the longer secret's tail exposed.
        let line = "KEY=abcdef KEY_LONG=abcdefXYZ";
        let redacted = mask_line(line, &["abcdef".to_string(), "abcdefXYZ".to_string()]);
        assert_eq!(redacted, "KEY=*** KEY_LONG=***");
        assert!(!redacted.contains("XYZ"));
    }

    #[test]
    fn mask_dedups_repeated_values() {
        let line = "A=secret B=secret";
        let redacted = mask_line(line, &["secret".to_string(), "secret".to_string()]);
        assert_eq!(redacted, "A=*** B=***");
    }

    #[test]
    fn mask_ignores_empty_secret() {
        assert_eq!(mask_line("hello", &[String::new()]), "hello");
    }

    #[test]
    fn mask_is_stable_constant() {
        assert_eq!(MASK, "***");
    }

    /// Inverse of [`shell_quote_single`] for property testing: returns `None`
    /// when the input is not a well-formed single-quoted shell word.
    fn unquote_single(quoted: &str) -> Option<String> {
        let inner = quoted.strip_prefix('\'')?.strip_suffix('\'')?;
        let mut out = String::new();
        let mut chars = inner.chars();
        while let Some(ch) = chars.next() {
            if ch != '\'' {
                out.push(ch);
                continue;
            }
            // A literal quote is emitted as the 4-char sequence `'\''`.
            for expected in ['\\', '\'', '\''] {
                if chars.next()? != expected {
                    return None;
                }
            }
            out.push('\'');
        }
        Some(out)
    }

    proptest::proptest! {
        /// Quoting is lossless: any value survives a shell round-trip, so a
        /// value containing `'`, spaces, or metacharacters reaches the remote
        /// byte-for-byte.
        #[test]
        fn shell_quote_single_round_trips(
            value in "[a-zA-Z0-9 '\"$`\\\\;|&*?\t/._-]{0,40}",
        ) {
            let quoted = shell_quote_single(&value);
            prop_assert!(quoted.starts_with('\'') && quoted.ends_with('\''));
            prop_assert_eq!(unquote_single(&quoted), Some(value));
        }

        /// A known secret never survives masking, and the result is
        /// independent of the order the secrets were collected in.
        #[test]
        fn mask_line_removes_every_secret_and_is_order_independent(
            // Each secret carries a marker character unique to it, so no
            // secret can be a substring of another (the case `mask_line`
            // handles by masking longest-first).
            secrets in proptest::collection::vec(("[A-Z]", "[a-z0-9]{0,8}"), 1..5),
            filler in "[a-z ]{0,20}",
        ) {
            let values: Vec<String> =
                secrets.iter().map(|(marker, tail)| format!("s{marker}{tail}")).collect();
            let line = values.join(&filler);
            let masked = mask_line(&line, &values);
            for secret in &values {
                prop_assert!(
                    !masked.contains(secret.as_str()),
                    "secret leaked through masking: {masked:?}"
                );
            }
            let mut reversed = values.clone();
            reversed.reverse();
            prop_assert_eq!(&masked, &mask_line(&line, &reversed));
        }

        /// Masking twice is the same as masking once: an operator cannot
        /// re-introduce a secret by re-running the redaction pass.
        #[test]
        fn masking_is_idempotent(
            secrets in proptest::collection::vec(("[A-Z]", "[a-z0-9]{0,8}"), 1..4),
            filler in "[a-z ]{0,16}",
        ) {
            let values: Vec<String> =
                secrets.iter().map(|(marker, tail)| format!("s{marker}{tail}")).collect();
            let line = values.join(&filler);
            let once = mask_line(&line, &values);
            prop_assert_eq!(mask_line(&once, &values), once);
        }

        /// `render_env` emits exactly one `export` line per pair, keys are
        /// never quoted or mangled, and masking the rendered payload with its
        /// own values redacts every one of them.
        #[test]
        fn render_env_is_one_line_per_pair(
            entries in proptest::collection::vec(("[A-Z_][A-Z0-9_]{0,8}", "[a-zA-Z0-9/_-]{0,20}"), 0..6),
        ) {
            let rendered = render_env(&entries);
            prop_assert_eq!(rendered.lines().count(), entries.len());
            for (key, value) in &entries {
                // Built outside the macro: `prop_assert!` re-wraps its
                // arguments in `concat!`, which would swallow `{}` here.
                let needle = format!("export {}=", key);
                let quoted = shell_quote_single(value);
                prop_assert!(rendered.contains(&needle));
                prop_assert!(rendered.contains(&quoted));
            }
            let values: Vec<String> = entries.iter().map(|(_, v)| v.clone()).collect();
            let masked = mask_line(&rendered, &values);
            for value in values.iter().filter(|v| !v.is_empty() && **v != MASK) {
                prop_assert!(
                    !masked.contains(value.as_str()),
                    "value survived masking: {masked:?}"
                );
            }
        }
    }
}
