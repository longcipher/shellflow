//! Shell-dialect lint for playbook blocks.
//!
//! The executor runs local blocks under the controller's login shell and
//! remote blocks under the *target's* login shell, which is `zsh` on a
//! meaningful share of hosts. `bash -n` accepts constructs that silently
//! misbehave under `zsh` with `set -eu`, so `-k` alone cannot catch them.
//! This module scans block bodies for the patterns that have caused real
//! production incidents:
//!
//! 1. `for x in $VAR` / `for x in ${VAR}` — `zsh` does not word-split unquoted expansions, so the
//!    loop runs once with the whole string. (Fix: literal lists, `for x in a b c`.)
//! 2. `${!name}` indirect expansion — unsupported by `zsh`.
//! 3. `${}` empty braces — a syntax error at runtime under `set -u`.
//! 4. `status=` / `for status in …` — `status` is a read-only special variable in `zsh` (an alias
//!    for `$?`); assigning it aborts the block.
//! 5. `local` outside any function — `local` is only valid inside a function; a straight-line block
//!    that declares one fails under `bash`.
//! 6. `read` without `-r` — backslashes in the input are mangled; the fleet convention is `while
//!    IFS= read -r`.
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
    let lines: Vec<&str> = script.lines().collect();
    let has_function = lines.iter().any(|raw| is_function_def(&strip_single_quoted(raw)));
    for (idx, raw_line) in lines.iter().enumerate() {
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
        if is_status_assignment(&code) {
            out.push(Lint {
                line: line_no,
                message: "zsh-risk: `status` is a read-only special variable in zsh; \
                          assigning it aborts the block (rename the variable)"
                    .to_string(),
            });
        }
        if !has_function && is_bare_local(&code) {
            out.push(Lint {
                line: line_no,
                message: "shell-risk: `local` outside any function fails; \
                          move the declaration into a function"
                    .to_string(),
            });
        }
        if is_read_without_r(&code) {
            out.push(Lint {
                line: line_no,
                message: "shell-risk: `read` without `-r` mangles backslashes; \
                          prefer `while IFS= read -r`"
                    .to_string(),
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
        if second.is_ascii_digit() ||
            matches!(second, b'@' | b'*' | b'#' | b'?' | b'-' | b'$' | b'!')
        {
            return None;
        }
        return Some(word.to_string());
    }
    None
}

/// Detect an assignment to the read-only `status` variable: `status=…`
/// (after `;`, `&&`, `||`, or at line start) or `for status in …`.
///
/// Reads (`$status`, `${status}`) are fine and never match: only the
/// assignment aborts the block under `zsh`.
fn is_status_assignment(code: &str) -> bool {
    // `match_indices` yields byte offsets at char boundaries, so multibyte
    // lines (CJK comments are common in playbooks) can never panic this
    // scan the way a manual byte-index walk would.
    for (i, _) in code.match_indices("status") {
        let before_ok = if i == 0 {
            true
        } else {
            matches!(code[..i].chars().next_back(), Some(' ' | '\t' | ';' | '&' | '|' | '('))
        };
        if !before_ok {
            continue;
        }
        let after = &code[i + "status".len()..];
        // `status=...` assigns; `for status in ...` assigns via the loop.
        if after.starts_with('=') {
            return true;
        }
        if after.starts_with(' ') || after.starts_with('\t') {
            let rest = after.trim_start();
            if rest.starts_with("in ") || rest.starts_with("in\t") {
                // Confirm the `for` keyword precedes it on this line.
                let head = code[..i].trim_end();
                if head == "for" || head.ends_with("; for") || head.ends_with("&& for") {
                    return true;
                }
            }
        }
    }
    false
}

/// Detect a `local` declaration: `local x` / `local -r x`.
fn is_bare_local(code: &str) -> bool {
    let trimmed = code.trim_start();
    trimmed == "local" ||
        trimmed.starts_with("local ") ||
        trimmed.starts_with("local\t") ||
        trimmed.starts_with("local -")
}

/// Detect a `name() {` / `name {` / `function name {` definition line.
fn is_function_def(code: &str) -> bool {
    let trimmed = code.trim();
    let body = trimmed.strip_prefix("function ").unwrap_or(trimmed);
    let Some(paren) = body.find('(') else {
        // `name {`: a bare name followed by an opening brace.
        if let Some(brace) = body.find('{') {
            let name = body[..brace].trim();
            return !name.is_empty() &&
                name.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == ' ');
        }
        return false;
    };
    let name = body[..paren].trim();
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return false;
    }
    let after = body[paren..].trim_start_matches('(').trim_start();
    let after = after.strip_prefix(')').unwrap_or(after).trim_start();
    after.starts_with('{')
}

/// Detect a `read` invocation without `-r`.
///
/// The line is split into simple commands on `;`, `&&`, `||` and `|`; a
/// `read` token counts as a command when everything before it in its
/// segment is a keyword (`while`, `if`, `do`, …), an assignment, or a
/// redirection — so `while IFS= read x` is caught and `echo read` is not.
fn is_read_without_r(code: &str) -> bool {
    let normalized = code.replace("&&", ";").replace("||", ";").replace('|', ";");
    for segment in normalized.split(';') {
        let words: Vec<&str> = segment.split_whitespace().collect();
        for (idx, word) in words.iter().enumerate() {
            if *word != "read" {
                continue;
            }
            let prefix_ok = words[..idx].iter().all(|w| {
                matches!(*w, "while" | "until" | "if" | "do" | "!" | "{" | "(") ||
                    w.contains('=') ||
                    w.starts_with('<') ||
                    w.starts_with('>')
            });
            if !prefix_ok {
                continue;
            }
            let has_r = words[idx + 1..]
                .iter()
                .any(|w| *w == "-r" || (w.starts_with('-') && w.contains('r')));
            if !has_r {
                return true;
            }
        }
    }
    false
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
    fn multibyte_lines_never_panic_the_scan() {
        // Non-ASCII comments are common in playbooks (a localised comment is a
        // comment); a byte-index walk would panic on a split char boundary
        // (`start byte index … is not a char boundary`). Cyrillic is used here
        // rather than an Asian script so the repositories' English-only gate
        // (`just check-cn`) stays meaningful. The scan must stay silent on all
        // of these.
        let findings = lint_block(
            "# \u{43f}\u{435}\u{440}\u{435}\u{437}\u{430}\u{433}\u{440}\u{443}\u{437}\u{43a}\u{430}: \u{44f}\u{434}\u{440}\u{43e}\n             status=0 # \u{441}\u{43e}\u{441}\u{442}\u{43e}\u{44f}\u{43d}\u{438}\u{435}\n             for x in a b; do echo \u{43f}\u{440}\u{438}\u{432}\u{435}\u{442}; done\n",
        );
        assert!(findings.iter().any(|f| f.message.contains("read-only")));
        let clean = lint_block(
            "# \u{43a}\u{43e}\u{43c}\u{43c}\u{435}\u{43d}\u{442}\u{430}\u{440}\u{438}\u{439}\necho ok\n",
        );
        assert!(clean.is_empty());
    }

    #[test]
    fn comments_and_single_quotes_ignored() {
        let findings = lint_block("# for x in $Y\necho '${!k}'\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn flags_status_assignment() {
        let findings = lint_block("status=0\necho ok\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("read-only"));
    }

    #[test]
    fn flags_status_in_a_for_loop() {
        let findings = lint_block("for status in a b; do echo $status; done\n");
        assert!(findings.iter().any(|f| f.message.contains("read-only")));
    }

    #[test]
    fn status_reads_are_clean() {
        assert!(lint_block("echo $status\n").is_empty());
        assert!(lint_block("echo ${status}\n").is_empty());
        assert!(lint_block("verdict=0\n").is_empty());
    }

    #[test]
    fn flags_local_without_any_function() {
        let findings = lint_block("local x=1\necho $x\n");
        assert!(findings.iter().any(|f| f.message.contains("outside any function")));
    }

    #[test]
    fn local_inside_a_function_is_clean() {
        let findings = lint_block("f() {\nlocal x=1\necho $x\n}\n");
        assert!(!findings.iter().any(|f| f.message.contains("outside any function")));
    }

    #[test]
    fn flags_read_without_r() {
        let findings = lint_block("while IFS= read -r line; do echo \"$line\"; done\n");
        assert!(!findings.iter().any(|f| f.message.contains("without `-r`")));
        let missing = lint_block("while IFS= read line; do echo \"$line\"; done\n");
        assert!(missing.iter().any(|f| f.message.contains("without `-r`")));
        assert!(lint_block("echo read\n").is_empty());
    }
}
