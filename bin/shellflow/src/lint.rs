//! Shell-dialect lint for playbook blocks.
//!
//! The executor runs local blocks under the controller's login shell and
//! remote blocks under the *target's* login shell, which is `zsh` on a
//! meaningful share of hosts. `bash -n` accepts constructs that silently
//! misbehave under `zsh` with `set -eu`, so `-k` alone cannot catch them.
//! This module scans block bodies for the three patterns that have caused
//! real production incidents:
//!
//! 1. `for x in $VAR` / `for x in ${VAR}` — `zsh` does not word-split
//!    unquoted expansions, so the loop runs once with the whole string.
//!    (Fix: literal lists, `for x in a b c`.)
//! 2. `${!name}` indirect expansion — unsupported by `zsh`.
//! 3. `${}` empty braces — a syntax error at runtime under `set -u`.
//!
//! Findings are advisory warnings (never fatal): the same script may
//! legitimately target bash-only hosts. Callers print them next to the
//! `bash -n` result during `--check` / `--dry-run`.

/// One lint finding: 1-based line number within the block plus a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Lint {
    pub(crate) line: usize,
    pub(crate) message: String,
}

/// Scan a block body for zsh-unsafe constructs.
///
/// Comment lines (`# …`, including `# @` directives) and single-quoted
/// regions are ignored; everything else is scanned literally.
pub(crate) fn lint_block(script: &str) -> Vec<Lint> {
    let mut out = Vec::new();
    for (idx, raw_line) in script.lines().enumerate() {
        let line_no = idx + 1;
        let code = strip_comment(&strip_single_quoted(raw_line));
        if code.trim().is_empty() {
            continue;
        }
        if let Some(var) = for_unquoted_expansion(&code) {
            out.push(Lint {
                line: line_no,
                message: format!(
                    "zsh-risk: for-loop over unquoted expansion {var} does not word-split \
                     under zsh; the loop runs once with the whole string (use a literal list)"
                ),
            });
        }
        if code.contains("${!") {
            out.push(Lint {
                line: line_no,
                message: "zsh-risk: indirect expansion ${!name} is unsupported by zsh".to_string(),
            });
        }
        if has_empty_braces(&code) {
            out.push(Lint {
                line: line_no,
                message: "zsh-risk: empty braces are a runtime error under `set -u`".to_string(),
            });
        }
    }
    out
}

/// Remove a trailing `#` comment (naive: `#` inside double quotes is rare in
/// the flagged patterns and over-reporting here is safe — findings are
/// advisory).
fn strip_comment(line: &str) -> String {
    match line.find('#') {
        Some(pos) => line[..pos].to_string(),
        None => line.to_string(),
    }
}

/// Blank out single-quoted regions so `'...${...}...'` literals are not
/// flagged. Keeps string length stable for later diagnostics.
fn strip_single_quoted(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut in_single = false;
    for c in line.chars() {
        if c == '\'' {
            in_single = !in_single;
            out.push(' ');
        } else if in_single {
            out.push(' ');
        } else {
            out.push(c);
        }
    }
    out
}

/// Detect `for <var> in $X` / `for <var> in ${X}…` with an unquoted
/// expansion. Returns the variable reference for the message.
fn for_unquoted_expansion(code: &str) -> Option<String> {
    let tokens: Vec<&str> = code.split_whitespace().collect();
    if tokens.len() < 4 || tokens[0] != "for" || tokens[2] != "in" {
        return None;
    }
    let word = tokens[3];
    // Quoted expansions are safe under both shells.
    if word.starts_with('"') || word.starts_with('\'') {
        return None;
    }
    if word.starts_with('$') && word.len() > 1 {
        // `$@`, `$*`, `$1`… are positional/special — unaffected.
        let second = word.as_bytes()[1];
        if second.is_ascii_digit() || matches!(second, b'@' | b'*' | b'#' | b'?' | b'-' | b'$' | b'!') {
            return None;
        }
        return Some(word.to_string());
    }
    None
}

/// Detect a literal `${}` (empty braces), ignoring `${VAR:-default}` and
/// other valid forms.
fn has_empty_braces(code: &str) -> bool {
    let bytes = code.as_bytes();
    let mut i = 0;
    while i + 2 < bytes.len() {
        if bytes[i] == b'$' && bytes[i + 1] == b'{' {
            // Find the closing brace for this expansion.
            if let Some(end) = code[i + 2..].find('}') {
                if end == 0 {
                    return true;
                }
                i += end;
            }
        }
        i += 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::lint_block;

    #[test]
    fn flags_unquoted_for_loop() {
        let findings = lint_block("for u in ${UNITS}; do\necho hi\ndone");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("word-split"));
    }

    #[test]
    fn literal_for_loop_is_clean() {
        let findings = lint_block("for u in a b c; do\necho hi\ndone");
        assert!(findings.is_empty());
    }

    #[test]
    fn quoted_expansion_is_clean() {
        let findings = lint_block("for u in \"$UNITS\"; do\necho hi\ndone");
        assert!(findings.is_empty());
    }

    #[test]
    fn flags_indirect_expansion() {
        let findings = lint_block("echo ${!key}");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_empty_braces() {
        let findings = lint_block("echo \"no ${} here\"");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn default_expansion_is_clean() {
        let findings = lint_block("SVC=\"${SVC:-sws}\"");
        assert!(findings.is_empty());
    }

    #[test]
    fn comments_and_single_quotes_ignored() {
        let findings = lint_block("# for x in $Y\necho '${!k}'\n");
        assert!(findings.is_empty());
    }
}
