//! `shellflow audit` — static secret scan of a repository.
//!
//! Catches the class of accident where a live credential lands in a
//! plaintext template, playbook, doc, or config: URL-embedded
//! `user:password@` values, non-empty `password/secret/token` assignments,
//! well-known token shapes (`sk-`, `ghp_`, ...), and PEM private-key blocks.
//!
//! The key and the value are matched **together**: an assignment is only a
//! finding when the token immediately left of the `=` (or the `--flag`
//! immediately left of the value) is itself a secret-bearing name. A line
//! that merely *mentions* a secret word — `grep -iE "database-password"`,
//! `LoadCredentialEncrypted=API_KEY:/etc/credstore.encrypted/…` — is not a
//! finding, and neither is a value that is a path or a redaction marker.
//!
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
    if let Some(message) = assignment_secret(line) {
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

/// Words that make an assignment key secret-bearing.
///
/// Matched two ways: an *exact* match on the normalized key (`pass`,
/// `dbpass`, `requirepass`, ...) and a *substring* match for the unambiguous
/// ones (`password`, `secret`, `token`, ...). A bare `pass` is only matched
/// exactly, so `bypass` / `compass` do not trip it.
///
/// `credential` / `credentials` are exact-match only: they are substrings of
/// systemd's own `LoadCredentialEncrypted=`, which names a *path*, not a
/// secret.
const SECRET_KEY_WORDS: &[&str] = &[
    "password",
    "passwd",
    "requirepass",
    "secret",
    "token",
    "apikey",
    "privatekey",
    "credential",
    "pass",
    "dbpass",
    "userpass",
    "adminpass",
];

/// Substrings that mark a compound key (`db_password`, `DUFS_AUTH_PASSWORD`).
const SECRET_KEY_SUBSTRINGS: &[&str] =
    &["password", "passwd", "secret", "token", "apikey", "privatekey"];

/// The secret word a key carries, if any.
///
/// `key` is the token immediately left of the `=` (or the flag name). The
/// token is normalized by dropping every non-alphanumeric character, so
/// `DUFS_AUTH_PASSWORD`, `db-password`, and `apiKey` all reduce to forms
/// this can recognize.
fn secret_word(key: &str) -> Option<&'static str> {
    let norm: String = key.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    let norm = norm.to_lowercase();
    if norm.is_empty() {
        return None;
    }
    if let Some(word) = SECRET_KEY_WORDS.iter().find(|w| norm == **w) {
        return Some(word);
    }
    SECRET_KEY_SUBSTRINGS.iter().find(|w| norm.contains(*w)).copied()
}

/// The identifier-ish run immediately left of `pos`.
///
/// This is what separates a real assignment from a line that merely
/// *mentions* a secret word: in `LoadCredentialEncrypted=API_KEY:/etc/...`
/// the run is `LoadCredentialEncrypted` (not a secret), while in
/// `DUFS_AUTH_PASSWORD=x` it is `DUFS_AUTH_PASSWORD` (a secret). Returns an
/// empty slice when the character before `pos` cannot be part of a key.
fn key_token_before(line: &str, pos: usize) -> &str {
    // The key and the `=` may be separated by spaces (`password = "x"`).
    let lhs = line[..pos].trim_end();
    let start = lhs
        .char_indices()
        .rev()
        .take_while(|(_, c)| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        .last()
        .map_or(lhs.len(), |(i, _)| i);
    &lhs[start..]
}

/// The value text that follows an `=` at `pos`.
///
/// A quoted value is taken up to its closing quote. An angle-bracketed
/// value (`<redacted: ...>`) is taken up to its closing `>`, so that a
/// redaction marker containing spaces stays one value instead of being
/// truncated at the first space.
fn value_after_eq(line: &str, pos: usize) -> &str {
    let rest = line[pos..].trim_start();
    if let Some(inner) = rest.strip_prefix('"') {
        return inner.split('"').next().unwrap_or("");
    }
    if let Some(inner) = rest.strip_prefix('\'') {
        return inner.split('\'').next().unwrap_or("");
    }
    if rest.starts_with('<') {
        return match rest.find('>') {
            Some(end) => &rest[..=end],
            None => rest,
        };
    }
    // `}` must NOT terminate the value: it closes a `${PLACEHOLDER}`, and
    // cutting there would turn `${SECRET}` into `${SECRET` — no longer a
    // placeholder, so the exemption below would never fire.
    rest.split(|c: char| c.is_whitespace() || matches!(c, ',' | ';' | ')' | ']' | '|' | '`'))
        .next()
        .unwrap_or("")
}

/// The byte ranges of the line covered by a quoted string.
///
/// A candidate inside a quoted region is prose or a pattern, not an
/// assignment: `grep -iE 'password='` and `echo "must have NO --token flag"`
/// both *look* like a secret and are not one.
fn quoted_spans(line: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let bytes = line.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let quote = bytes[i];
        if quote != b'"' && quote != b'\'' {
            i += 1;
            continue;
        }
        // A single quote that never closes is an apostrophe in prose
        // (`don't`), not a quoting context — so it must not swallow the
        // rest of the line.
        let close = line[i + 1..].find(quote as char).map(|idx| i + 1 + idx);
        let Some(close) = close else {
            i += 1;
            continue;
        };
        spans.push((i, close + 1));
        i = close + 1;
    }
    spans
}

/// Whether a byte position falls inside a quoted region.
fn in_quoted(spans: &[(usize, usize)], pos: usize) -> bool {
    spans.iter().any(|(start, end)| pos >= *start && pos < *end)
}

/// The `--flag value` shape: a secret-ish flag followed by its value.
///
/// Only flags that stand outside a quoted region count: inside quotes the
/// same text is prose (`must have NO --token flag`).
fn flag_value<'a>(line: &'a str, quoted: &[(usize, usize)]) -> Option<(&'static str, &'a str)> {
    let mut previous: Option<(usize, &str)> = None;
    let mut rest = line;
    let mut offset = 0usize;
    while !rest.is_empty() {
        let trimmed = rest.trim_start();
        offset += rest.len() - trimmed.len();
        if trimmed.is_empty() {
            break;
        }
        let (word, tail) = match trimmed.find(char::is_whitespace) {
            Some(idx) => (&trimmed[..idx], &trimmed[idx..]),
            None => (trimmed, ""),
        };
        rest = tail;
        if let Some((prev_pos, prev)) = previous &&
            prev.starts_with('-') &&
            !prev.contains('=') &&
            !in_quoted(quoted, prev_pos) &&
            let Some(word_key) = secret_word(prev.trim_start_matches('-')) &&
            !word.starts_with('-') &&
            !in_quoted(quoted, offset)
        {
            let value = word.trim_matches(|c| c == '"' || c == '\'');
            return Some((word_key, value));
        }
        previous = Some((offset, word));
    }
    None
}

/// `password|secret|token|api_key = "VALUE"` with a non-empty, non-example value.
///
/// The key must be the token immediately left of the `=` — not merely
/// mentioned somewhere on the line. Matching key and value independently is
/// what produced the false positives: `grep -iE "database-password"` and
/// `LoadCredentialEncrypted=API_KEY:/etc/...` both *mention* a secret word
/// while assigning something that is not a secret.
fn assignment_secret(line: &str) -> Option<String> {
    let quoted = quoted_spans(line);
    // Every `=` on the line is a candidate: a line can hold more than one
    // assignment, and the secret one is not necessarily the first.
    for (idx, ch) in line.char_indices() {
        if ch != '=' || in_quoted(&quoted, idx) {
            continue;
        }
        let Some(word) = secret_word(key_token_before(line, idx)) else {
            continue;
        };
        if let Some(message) = live_value(word, value_after_eq(line, idx + 1)) {
            return Some(message);
        }
    }
    // `--flag VALUE` — how a command-line password actually shows up.
    if let Some((word, value)) = flag_value(line, &quoted) &&
        let Some(message) = live_value(word, value)
    {
        return Some(message);
    }
    None
}

/// Whether a value looks like a live credential, and the message to report.
fn live_value(word: &str, value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    // Short values are shell fragments (`cut -d=`), versions, or counters --
    // never credentials (mirrors the `@secrets` masking threshold).
    if value.len() < 6 {
        return None;
    }
    let vl = value.to_lowercase();
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
    // A value that *says* it is a placeholder (`shadow-placeholder`,
    // `REDACTED`, `TODO`) is a placeholder, whatever its key is called.
    if ["placeholder", "redacted", "todo", "fixme"].iter().any(|w| vl.contains(w)) {
        return None;
    }
    // A value that is *only* a shell placeholder is the *mechanism*, not a
    // leak. The exemption is scoped to the whole value: a value that merely
    // mentions `${...}` — `password = "Hunt3r!${v}"` — still carries a
    // literal credential and must be reported, because the literal prefix is
    // exactly the kind of hard-coded secret this scan exists to find.
    if is_placeholder_only(value) {
        return None;
    }
    // A *reference* to a secret is not a secret: a path (`password=/run/
    // creds/DB_PASSWORD`) and a redaction marker (`<redacted: ...>`) are
    // documentation, not a leak.
    if is_path_like(value) || is_redaction_marker(value) {
        return None;
    }
    // A URL's own credentials are handled by `url_credential`; do not
    // double-report the whole URL as if it were a password value.
    if value.contains("://") {
        return None;
    }
    Some(format!("live-looking `{word}` assignment"))
}

/// Whether the value is a filesystem path (a reference to where a secret
/// lives, not the secret itself).
fn is_path_like(value: &str) -> bool {
    if value.starts_with('/') ||
        value.starts_with("./") ||
        value.starts_with("../") ||
        value.starts_with("~/")
    {
        return true;
    }
    // A repository-relative path names where the secret lives, exactly like an
    // absolute one does: a manifest's `secret_file = "services/dufs/{host}
    // .env.age"` points at the *encrypted* env file, it is not a credential.
    // The last segment must look like a file name, so a value that merely
    // contains a slash is still a value.
    if let Some((_dir, name)) = value.rsplit_once('/') &&
        !name.is_empty() &&
        name.contains('.') &&
        !name.starts_with('.')
    {
        return true;
    }
    false
}

/// Whether the value is a redaction marker (`<redacted: ...>`, `<see ...>`).
fn is_redaction_marker(value: &str) -> bool {
    value.starts_with('<') && value.ends_with('>')
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
    fn a_mention_is_not_an_assignment() {
        // The key must be the token immediately left of the `=`. These lines
        // all *mention* a secret word while assigning something else.
        assert_eq!(hits("LoadCredentialEncrypted=API_KEY:/etc/credstore.encrypted/x/API_KEY"), 0);
        assert_eq!(
            hits(
                "LoadCredentialEncrypted=DUFS_AUTH_PASSWORD:/etc/credstore.encrypted/dufs/DUFS_AUTH_PASSWORD"
            ),
            0
        );
        assert_eq!(hits("secret creds --store-dir /etc/credstore.encrypted/x"), 0);
        assert_eq!(hits("grep -iE \"database-password\""), 0);
        assert_eq!(hits("| 4 | **meme token plaintext** | `Environment=` | risk |"), 0);
        assert_eq!(hits("shellflow >= 0.3.0 (needs secret creds)"), 0);
    }

    #[test]
    fn template_placeholders_are_exempt() {
        // The repo's own config templates: a secret-ish KEY whose value is a
        // placeholder. This is the *mechanism*, not a leak.
        assert_eq!(hits("TOKEN=${BROWSERLESS_TOKEN}"), 0);
        assert_eq!(hits("--requirepass=${DFLY_PASSWORD}"), 0);
        assert_eq!(hits("API_KEY=${API_KEY}"), 0);
    }

    #[test]
    fn a_quoted_pattern_is_not_a_secret() {
        // A `=` (or a secret-ish flag) inside a quoted string is a pattern or
        // prose, not an assignment.
        assert_eq!(hits("sudo grep -iE 'password='"), 0);
        assert_eq!(hits(r#"sudo grep -E "requirepass=\\$\{DFLY_PASSWORD\}" file"#), 0);
        assert_eq!(hits("echo \"==> effective ExecStart (must have NO --token flag):\""), 0);
        // An apostrophe in prose is not a quoting context.
        assert_eq!(hits("it's fine: password = \"hunter2\""), 1);
    }

    #[test]
    fn a_value_that_says_it_is_a_placeholder_is_one() {
        // The repo's archived strategy templates carry `shadow-placeholder`.
        assert_eq!(hits("api_key = \"shadow-placeholder\""), 0);
        assert_eq!(hits("api_secret = \"shadow-placeholder\""), 0);
        assert_eq!(hits("passphrase = \"shadow-placeholder\""), 0);
        // ... but a real value next to the same key is still a finding.
        assert_eq!(hits("api_key = \"3Gyxtb1VtZbf\""), 1);
    }

    #[test]
    fn a_selector_key_is_not_a_secret() {
        // `credentials = "bitget"` names a venue, not a secret.
        assert_eq!(hits("credentials = \"bitget\""), 0);
        assert_eq!(hits("[credentials.bitget]"), 0);
    }

    #[test]
    fn a_reference_to_a_secret_is_not_a_secret() {
        // A path says *where* the secret lives; a redaction marker says the
        // value was removed on purpose. Neither is the secret itself.
        assert_eq!(hits("DB_PASSWORD=/etc/credstore.encrypted/x/DB_PASSWORD"), 0);
        assert_eq!(hits("password=/run/creds/db/password"), 0);
        assert_eq!(hits("--requirepass=<redacted: see /etc/credstore.encrypted/x>"), 0);
        assert_eq!(hits("requirepass=<redacted>"), 0);
    }

    #[test]
    fn a_repository_relative_path_is_not_a_secret() {
        // A manifest names the encrypted env file that holds the credentials:
        // that is a reference to where the secret lives, not the secret.
        assert_eq!(hits("secret_file = \"services/dufs/{host}.env.age\""), 0);
        assert_eq!(hits("secret_file = \"services/cidx/{host}.env.age\""), 0);
        // A value that merely contains a slash is still a value.
        assert_eq!(hits("secret_file = \"abc/def\""), 1);
    }

    #[test]
    fn a_real_value_next_to_a_secret_key_is_still_found() {
        // The tightened key matching must not lose the real thing.
        assert_eq!(hits("FERRISKEY_DB_PASSWORD=3Gyxtb1VtZbf"), 1);
        assert_eq!(hits("requirepass=3Gyxtb1VtZbf"), 1);
        assert_eq!(
            hits(
                "ExecStart=/home/akagi201/ferriskey/bin/ferriskey-api --database-password 3Gyxtb1VtZbf"
            ),
            1
        );
        assert_eq!(hits("dufs.service: DUFS_AUTH_PASSWORD=3Gyxtb1VtZbf"), 1);
    }

    #[test]
    fn the_bare_pass_family_does_not_swallow_english() {
        // `bypass` / `compass` end in "pass" but are not credentials.
        assert_eq!(hits("bypass=3Gyxtb1VtZbf"), 0);
        assert_eq!(hits("compass=3Gyxtb1VtZbf"), 0);
        // ... but a key that really is a password still is one.
        assert_eq!(hits("pass=3Gyxtb1VtZbf"), 1);
        assert_eq!(hits("db_pass=3Gyxtb1VtZbf"), 1);
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
