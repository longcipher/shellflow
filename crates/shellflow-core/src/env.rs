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
#[must_use]
pub fn mask_line(line: &str, secrets: &[String]) -> String {
    let mut out = line.to_string();
    for secret in secrets {
        if secret.is_empty() {
            continue;
        }
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
    fn mask_ignores_empty_secret() {
        assert_eq!(mask_line("hello", &[String::new()]), "hello");
    }

    #[test]
    fn mask_is_stable_constant() {
        assert_eq!(MASK, "***");
    }
}
