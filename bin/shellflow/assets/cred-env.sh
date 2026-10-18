#!/usr/bin/env bash
# ============================================================
# cred-env — generic systemd-credential helper (bash fallback)
# ============================================================
# FALLBACK: the primary implementation is `shellflow cred-env exec|render`
# (subcommands of the shellflow binary itself, installed once per target host
# as /usr/local/bin/shellflow). This bash asset, printed by
# `shellflow emit cred-env`, implements the same `exec`/`render` semantics for
# targets that cannot host the binary. Both are verified against shared
# integration fixtures — keep them in sync (see docs/design-secrets.md §12).
#
# Install once per host (e.g. /usr/local/bin/cred-env). Services reference it
# from their unit instead of hand-writing a per-service starter:
#
#   [Service]
#   RuntimeDirectory=<svc>
#   LoadCredentialEncrypted=API_KEY:/etc/credstore.encrypted/<svc>/API_KEY
#   ExecStartPre=/usr/local/bin/cred-env render \
#       /etc/<svc>/<svc>.json5.tmpl /run/<svc>/<svc>.json5
#   ExecStart=/usr/local/bin/cred-env exec /usr/local/bin/<svc> -c /run/<svc>/<svc>.json5
#
# Subcommands:
#   exec <cmd> [args...]   Export every $CREDENTIALS_DIRECTORY/* as an env var
#                          (filename = variable name), then exec <cmd>.
#   render <tmpl> <out>    Substitute ${KEY} placeholders in <tmpl> with the
#                          credential values and write <out> (mode 0600).
#
# Security properties:
#   - Values are read from systemd's tmpfs credential directory; they are
#     never printed, so journald and `ps` stay clean.
#   - `render` fails closed before writing anything when a referenced
#     credential is missing, and writes via a same-directory temp file so
#     <out> appears atomically.
#   - Substitution is literal bash pattern replacement: values containing
#     quotes, `&`, `|`, `$` or backslashes are inserted verbatim (sed would
#     reinterpret them).
#
# Requires bash (pattern replacement + BASH_REMATCH); the unit's ExecStart
# runs this script directly, so the login shell is irrelevant.
set -eu

usage() {
    echo "usage: cred-env exec <cmd> [args...]" >&2
    echo "       cred-env render <template> <output>" >&2
}

# Print the credential directory or fail closed when nothing was imported.
credential_dir() {
    if [ -z "${CREDENTIALS_DIRECTORY:-}" ] || [ ! -d "${CREDENTIALS_DIRECTORY}" ]; then
        echo "cred-env: CREDENTIALS_DIRECTORY is not set (no credentials imported?)" >&2
        exit 1
    fi
    printf '%s' "${CREDENTIALS_DIRECTORY}"
}

# Export every credential as an environment variable, then exec the command.
cmd_exec() {
    if [ "$#" -lt 1 ]; then
        usage >&2
        exit 2
    fi
    local dir f key val
    dir="$(credential_dir)"
    for f in "${dir}"/*; do
        [ -f "$f" ] || continue
        key="$(basename "$f")"
        # Exact variable-name check (mirrors shellflow's env parser): a glob
        # case pattern would let `BAD-NAME` through and fail the export.
        [[ "${key}" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue
        # Preserve trailing newlines: command substitution strips them, so
        # append a sentinel `x` then strip it. Matches the Rust `cred-env
        # exec` (exact bytes); plain `$(cat)` would lose a trailing `\n`.
        val="$(cat "${f}"; printf x)"
        val="${val%x}"
        export "${key}=${val}"
    done
    exec "$@"
}

# Literal placeholder substitution: replace every occurrence of $2 in $1 with
# $3, storing the result in SUBST_RESULT.
#
# Deliberately NOT `${text//needle/val}`: in the replacement string, `&`
# expands to the matched text on some bash versions (sed-like semantics), so a
# password containing `&` would corrupt the render. Building the result with
# `${text%%"$needle"*}` / `${text#*"$needle"}` is literal on every bash.
SUBST_RESULT=""
substitute() {
    local text="$1" needle="$2" val="$3" out="" prefix
    while :; do
        prefix="${text%%"$needle"*}"
        if [ "${prefix}" = "${text}" ]; then
            SUBST_RESULT="${out}${text}"
            return
        fi
        out="${out}${prefix}${val}"
        text="${text#*"$needle"}"
    done
}

# Render a template with ${KEY} placeholders into <out> (0600).
cmd_render() {
    if [ "$#" -ne 2 ]; then
        usage >&2
        exit 2
    fi
    local tmpl="$1" out="$2"
    [ -r "${tmpl}" ] || { echo "cred-env: cannot read template: ${tmpl}" >&2; exit 1; }
    local dir f key val line rest tmp missing missing_final_newline
    dir="$(credential_dir)"

    # Fail closed first: every ${KEY} the template references must exist as a
    # credential, so a typo or a missing key aborts the unit before any file
    # is written.
    missing=0
    while IFS= read -r line || [ -n "${line}" ]; do
        rest="${line}"
        while [[ "${rest}" =~ \$\{([A-Za-z_][A-Za-z0-9_]*)\} ]]; do
            key="${BASH_REMATCH[1]}"
            if [ ! -f "${dir}/${key}" ]; then
                echo "cred-env: template references missing credential: ${key}" >&2
                missing=1
            fi
            rest="${rest#*"${BASH_REMATCH[0]}"}"
        done
    done < "${tmpl}"
    [ "${missing}" -eq 0 ] || exit 1

    # Atomic render inside the destination directory (tmpfs when <out> is
    # under /run). `mktemp` creates 0600 from the start: a predictable
    # `${out}.cred-env.$$` + `: >` would be briefly 0644 (world-readable) and
    # symlink-plantable.
    tmp="$(mktemp "${out}.cred-env.XXXXXX")" || {
        echo "cred-env: cannot create temp file" >&2
        exit 1
    }
    # shellcheck disable=SC2064
    trap "rm -f '${tmp//\'/\'\\\'\'}'" EXIT
    chmod 0600 "${tmp}"
    # Preserve a missing trailing newline: `tail -c1` + command substitution
    # yields empty when the last byte is `\n` (stripped), non-empty otherwise.
    # Newlines are written *between* lines plus one final newline only when
    # the template had one (matches the Rust `render`, which splices exact
    # spans). Portable: no `truncate` (absent on macOS).
    missing_final_newline=0
    if [ -s "${tmpl}" ] && [ -n "$(tail -c 1 "${tmpl}")" ]; then
        missing_final_newline=1
    fi
    first=1
    while IFS= read -r line || [ -n "${line}" ]; do
        for f in "${dir}"/*; do
            [ -f "${f}" ] || continue
            key="$(basename "${f}")"
            [[ "${key}" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue
            val="$(cat "${f}"; printf x)"
            val="${val%x}"
            substitute "${line}" "\${${key}}" "${val}"
            line="${SUBST_RESULT}"
        done
        if [ "${first}" -eq 1 ]; then
            printf '%s' "${line}" >> "${tmp}"
            first=0
        else
            printf '\n%s' "${line}" >> "${tmp}"
        fi
    done < "${tmpl}"
    if [ "${first}" -eq 0 ] && [ "${missing_final_newline}" -eq 0 ]; then
        printf '\n' >> "${tmp}"
    fi
    chmod 0600 "${tmp}"
    mv -f "${tmp}" "${out}"
    trap - EXIT
}

case "${1:-}" in
    exec)
        shift
        cmd_exec "$@"
        ;;
    render)
        shift
        cmd_render "$@"
        ;;
    -h | --help | help)
        usage
        exit 0
        ;;
    *)
        echo "cred-env: unknown subcommand: ${1:-<none>}" >&2
        usage >&2
        exit 2
        ;;
esac
