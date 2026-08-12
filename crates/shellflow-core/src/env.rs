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
}
