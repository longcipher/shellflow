//! `shellflow audit` — static secret scan of a repository.
//!
//! Catches the class of accident where a live credential lands in a
//! plaintext template, playbook, doc, or config: URL-embedded
//! `user:password@` values, non-empty `password/secret/token` assignments,
//! well-known token shapes (`sk-`, `ghp_`, ...), and PEM private-key blocks.
//! Placeholders (`${KEY}`), empty values, and `user:password` documentation
//! literals are ignored. Age-encrypted (`*.age`) files are never read.
//!
//! Exit status is non-zero when any finding fires, so it fits pre-commit.

use std::{
    fs,
    path::{Path, PathBuf},
};

use eyre::{Context, Result, bail};

use crate::cli::AuditArgs;

/// Run `audit`.
///
/// # Errors
///
/// Returns when the directory cannot be walked or when any finding fires.
pub(crate) fn audit(args: &AuditArgs) -> Result<()> {
    let root = &args.path;
    let mut files = Vec::new();
    collect_files(root, &mut files)?;
    files.sort();
    let mut findings = 0;
    for file in &files {
        let Ok(content) = fs::read_to_string(file) else {
            continue; // binary or unreadable — not our business
        };
        for finding in scan_file(&content) {
            let rel = file.strip_prefix(root).unwrap_or(file);
            println!("FAIL {}:{}: {}", rel.display(), finding.line, finding.message);
            findings += 1;
            if findings >= 20 {
                println!("… stopping after 20 findings");
                bail!("audit: {findings}+ secret-shaped finding(s) under {}", root.display());
            }
        }
    }
    if findings > 0 {
        bail!("audit: {findings} secret-shaped finding(s) under {}", root.display());
    }
    println!("audit: {} file(s) clean", files.len());
    Ok(())
}

/// One finding: 1-based line plus a redacted message (never the value).
pub(crate) struct Finding {
    pub(crate) line: usize,
    pub(crate) message: String,
}

/// Collect scannable files: skip `.git/`, `target/`, encrypted blobs, and
/// lockfiles full of hashes.
fn collect_files(root: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let entries = fs::read_dir(root).wrap_err_with(|| format!("cannot read {}", root.display()))?;
    for entry in entries {
        let entry = entry.wrap_err("cannot read directory entry")?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == ".git" || name == "target" || name == "node_modules" || name == ".codebuddy" {
            continue;
        }
        let file_type = entry.file_type().wrap_err("cannot stat directory entry")?;
        if file_type.is_dir() {
            collect_files(&path, out)?;
        } else if file_type.is_file() {
            if path.extension().is_some_and(|e| e == "age" || e == "lock") {
                continue;
            }
            out.push(path);
        }
    }
    Ok(())
}

/// Scan file content for secret shapes. Values are never included in
/// messages — only the shape and the key/field name.
pub(crate) fn scan_file(content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        let line_no = idx + 1;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(message) = scan_line(line) {
            out.push(Finding { line: line_no, message });
        }
    }
    out
}

/// Scan one line. Returns a redacted message on a hit.
fn scan_line(line: &str) -> Option<String> {
    let lower = line.to_lowercase();
    // URL-embedded credentials: scheme://user:PASS@host (skip user:password
    // documentation literals and empty passwords).
    if let Some(message) = url_credential(line, &lower) {
        return Some(message);
    }
    // Well-known token shapes.
    for prefix in ["sk-", "ghp_", "gho_", "xoxb-", "xoxp-", "AKIA"] {
        if let Some(pos) = line.find(prefix) {
            let tail: String = line[pos + prefix.len()..]
                .chars()
                .take_while(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '.'))
                .collect();
            if tail.len() >= 8 {
                return Some(format!("{prefix}… token-shaped value ({} chars)", tail.len()));
            }
        }
    }
    // PEM private key blocks.
    if line.contains("-----BEGIN") && line.contains("PRIVATE KEY") {
        return Some("PEM private key block".to_string());
    }
    // password=/secret=/token= assignments with non-trivial quoted values.
    if let Some(message) = assignment_secret(line, &lower) {
        return Some(message);
    }
    None
}

/// `scheme://user:PASS@host` with a non-empty, non-documentation password.
fn url_credential(line: &str, lower: &str) -> Option<String> {
    let scheme_end = lower.find("://")?;
    let after = &line[scheme_end + 3..];
    let at = after.find('@')?;
    let creds = &after[..at];
    let (user, pass) = creds.split_once(':')?;
    if user.is_empty() || pass.is_empty() {
        return None;
    }
    // Strip quotes/brackets for the doc-literal check.
    let pass_clean: String =
        pass.chars().filter(|c| !matches!(c, '"' | '\'' | '[' | ']')).collect();
    if pass_clean.is_empty() ||
        pass_clean == "password" ||
        pass_clean == "user" ||
        pass_clean.eq_ignore_ascii_case("changeme") ||
        pass_clean.contains("example") ||
        pass_clean.contains("...") ||
        pass_clean.contains("***") ||
        // A password that is nothing but a shell placeholder (`${DB_PASS}`,
        // `$DB_PASS`) is the mechanism, not a leak — same exemption as the
        // `KEY=VALUE` path below.
        is_placeholder_only(&pass_clean)
    {
        return None;
    }
    Some(format!("URL-embedded credential for user `{user}`"))
}

/// `password|secret|token|api_key = "VALUE"` with a non-empty, non-example value.
fn assignment_secret(line: &str, lower: &str) -> Option<String> {
    // URLs are handled by url_credential (their `user:password@` shape has
    // its own documentation-literal rules).
    if lower.contains("://") {
        return None;
    }
    let keys = ["password", "passwd", "secret", "token", "api_key", "apikey", "private_key"];
    let key = keys.iter().find(|k| lower.contains(*k))?;
    // Split on the first `=` and inspect the value.
    let (_, value) = line.split_once('=')?;
    let value = value.trim().trim_matches(|c| c == '"' || c == '\'').trim();
    if value.is_empty() || value == "\"\"" || value == "''" {
        return None;
    }
    let vl = value.to_lowercase();
    // Short values are shell fragments (`cut -d=`), versions, or counters —
    // never credentials (mirrors the `@secrets` masking threshold).
    if value.len() < 6 {
        return None;
    }
    // Placeholder-shaped values are skipped. The list names *shapes* that are
    // conventionally placeholders, not specific credential values: a real
    // default (a database superuser password, for instance) must be flagged
    // even when it is a well-known word, because a well-known password is
    // still a password.
    if ["dummy", "changeme", "example", "test", "none", "false", "true"].contains(&vl.as_str()) ||
        value.starts_with("xxxx") ||
        value.contains("...") ||
        value.contains("***") ||
        value.parse::<i64>().is_ok()
    {
        return None;
    }
    // A value that is *only* a shell placeholder is the *mechanism*, not a
    // leak. The exemption is scoped to the whole value: a value that merely
    // mentions `${…}` — `password = "Hunt3r!${v}"` — still carries a literal
    // credential and must be reported, because the literal prefix is exactly
    // the kind of hard-coded secret this scan exists to find.
    if is_placeholder_only(value) {
        return None;
    }
    Some(format!("live-looking `{key}` assignment"))
}

/// Whether the value consists of nothing but shell placeholder references.
///
/// Both the braced (`${NAME}`) and the unbraced (`$NAME`) forms count, and
/// each referenced name must be a plain identifier. A single placeholder
/// (`${DB_PASSWORD}`) is the mechanism, not a leak — and so is a
/// concatenation of placeholders (`${PREFIX}${SUFFIX}`), which carries no
/// literal credential text either. `${A}b` is *not* exempt: the trailing `b`
/// is literal text that happens to follow a placeholder.
fn is_placeholder_only(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    let mut rest = value;
    while !rest.is_empty() {
        if let Some(after) = rest.strip_prefix("${") {
            let Some(end) = after.find('}') else {
                return false;
            };
            if !is_placeholder_name(&after[..end]) {
                return false;
            }
            rest = &after[end + 1..];
        } else if let Some(after) = rest.strip_prefix('$') {
            let len = after
                .char_indices()
                .take_while(|(_, c)| c.is_ascii_alphanumeric() || *c == '_')
                .map(|(i, c)| i + c.len_utf8())
                .last()
                .unwrap_or(0);
            if len == 0 || !is_placeholder_name(&after[..len]) {
                return false;
            }
            rest = &after[len..];
        } else {
            return false;
        }
    }
    true
}

/// Whether `name` is a valid shell identifier.
fn is_placeholder_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::scan_file;

    fn hits(content: &str) -> usize {
        scan_file(content).len()
    }

    #[test]
    fn flags_url_embedded_password() {
        assert_eq!(hits("url = \"postgresql://akagi201:s3cr3tpass@localhost/db\""), 1);
    }

    #[test]
    fn ignores_documentation_literals() {
        assert_eq!(hits("url = \"postgresql://user:password@localhost/db\""), 0);
        assert_eq!(hits("# password = \"hunter2\""), 0);
        assert_eq!(hits("password = \"hunter2\""), 1);
        assert_eq!(hits("password = \"${DB_PASSWORD}\""), 0);
        assert_eq!(hits("password = \"\""), 0);
        // A well-known default is still a password: the scanner must not be
        // silenced by the *value* being a common word.
        assert_eq!(hits("password = \"postgres\""), 1);
        // Placeholder-shaped values are still skipped.
        assert_eq!(hits("password = \"changeme\""), 0);
        assert_eq!(hits("password = \"dummy\""), 0);
    }

    #[test]
    fn flags_token_shapes() {
        assert_eq!(hits("key = \"sk-abcdefgh12345678\""), 1);
        assert_eq!(hits("# token = \"ghp_xxxx\""), 0);
    }

    #[test]
    fn flags_pem_blocks() {
        assert_eq!(hits("-----BEGIN EC PRIVATE KEY-----\nabc"), 1);
    }

    #[test]
    fn flags_assignments() {
        assert_eq!(hits("bot_token = \"123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11\""), 1);
        assert_eq!(hits("port = 8080"), 0);
        assert_eq!(hits("api_tokens_post_expiry_days = 30"), 0);
    }

    #[test]
    fn only_a_pure_placeholder_is_exempt() {
        // A value that is nothing but a placeholder is the mechanism.
        assert_eq!(hits("password = \"${DB_PASSWORD}\""), 0);
        assert_eq!(hits("password = \"$DB_PASSWORD\""), 0);
        // A concatenation of placeholders carries no literal text either.
        assert_eq!(hits("password = \"${PREFIX}${SUFFIX}\""), 0);
        assert_eq!(hits("password = \"$A$B\""), 0);
        // A value that merely *contains* a placeholder still carries a literal
        // credential, so it must be reported.
        assert_eq!(hits("password = \"Hunt3r!${v}\""), 1);
        assert_eq!(hits("password = \"prefix-${DB_PASSWORD}\""), 1);
        assert_eq!(hits("password = \"${DB_PASSWORD}-suffix\""), 1);
        assert_eq!(hits("password = \"${ABCD}e\""), 1);
        // A malformed placeholder is not a placeholder.
        assert_eq!(hits("password = \"${1PASSWORD}\""), 1);
        assert_eq!(hits("password = \"${DB-PASSWORD}\""), 1);
        assert_eq!(hits("password = \"${UNTERMINATED\""), 1);
    }

    #[test]
    fn url_passwords_that_are_placeholders_are_exempt() {
        // A templated URL carries no literal credential.
        assert_eq!(hits("url = \"postgresql://app:${DB_PASSWORD}@localhost/db\""), 0);
        assert_eq!(hits("url = \"postgresql://app:$DB_PASSWORD@localhost/db\""), 0);
        // A literal password in a URL is still a finding.
        assert_eq!(hits("url = \"postgresql://app:s3cr3tpass@localhost/db\""), 1);
    }
}
