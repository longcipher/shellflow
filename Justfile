# Default recipe to display help
default:
  @just --list

# The fuzz crates are detached workspaces, so `cargo fmt --all` skips them.
#
# Format markdown, TOML and Rust sources
format:
  rumdl fmt .
  cargo sort -w -g
  cargo +nightly fmt --all
  rustfmt +nightly --edition 2024 crates/shellflow-core/fuzz/fuzz_targets/*.rs
  rustfmt +nightly --edition 2024 crates/shellflow-dsl/fuzz/fuzz_targets/*.rs
  rustfmt +nightly --edition 2024 crates/shellflow-secrets/fuzz/fuzz_targets/*.rs

# Auto-fix what `format` cannot: markdown lints and clippy findings
fix:
  rumdl check --fix .
  RUSTC_WRAPPER= cargo +nightly clippy --fix --all --allow-dirty

# Run all lints (every tool used here is installed by .github/workflows/ci.yml)
lint:
  typos
  rumdl check .
  cargo sort -w -g -c
  cargo +nightly fmt --all -- --check
  RUSTC_WRAPPER= cargo +nightly clippy --workspace --all-targets --all-features -- -D warnings
  just check-mutation-scope

# Run the prek commit hooks on every tracked file (requires prek)
hooks:
  prek run --all-files

# Run the workspace test suite
test:
  cargo test --all-features

# Mutation testing is intentionally absent from the default loop and from CI.
#
# Whole-workspace mutation runs are PROHIBITED here: a `cargo mutants` run over
# the whole workspace takes hours and rarely finishes, so it is never a gate and
# never a completion check. Only the lines the current change touched are
# mutated, within the /pb-build budget: at most 3 files, 60 mutants, 300 s.
#
#   just mutation                            # every changed .rs file
#   just mutation crates/core/src/parser.rs  # one specific file
#
# The budget is verified before the run starts, so an over-large change fails
# immediately instead of grinding for hours. A surviving mutant is a test
# failure: strengthen the assertion, or record an exemption in
# `.cargo/mutants.toml` under `exclude_re` with a one-line reason.
#
# Mutate the lines this change touched, within the /pb-build budget.
mutation *args:
  #!/usr/bin/env bash
  set -euo pipefail
  max_files=3
  max_mutants=60
  max_seconds=300

  base=""
  upstream=$(git rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' 2>/dev/null || true)
  for ref in "$upstream" origin/main origin/master main master; do
    [ -n "$ref" ] || continue
    if git rev-parse --verify --quiet "$ref" >/dev/null 2>&1; then
      base=$(git merge-base HEAD "$ref" 2>/dev/null || true)
      [ -n "$base" ] && break
    fi
  done
  [ -n "$base" ] || base=HEAD

  work=$(mktemp -d)
  trap 'rm -rf "$work"' EXIT
  if [ "$#" -gt 0 ]; then
    printf '%s\n' "$@" | sed '/^[[:space:]]*$/d' > "$work/files"
  else
    git diff --name-only --diff-filter=ACMR "$base" -- '*.rs' | sort -u > "$work/files"
  fi
  file_count=$(grep -c . "$work/files" || true)
  if [ "$file_count" -eq 0 ]; then
    echo "error: no changed Rust files against $base; there is nothing to mutate." >&2
    echo "       Whole-workspace mutation is prohibited: it takes hours and rarely finishes." >&2
    exit 2
  fi
  if [ "$file_count" -gt "$max_files" ]; then
    echo "error: $file_count files exceed the ${max_files}-file mutation budget." >&2
    echo "       Mutate fewer files at a time; never raise the budget, never run the workspace." >&2
    exit 3
  fi

  : > "$work/diff"
  while IFS= read -r file; do
    [ -n "$file" ] || continue
    git diff --no-ext-diff --no-textconv "$base" -- "$file" >> "$work/diff" || true
  done < "$work/files"
  if ! grep -q '^diff --git ' "$work/diff"; then
    echo "error: the diff against $base is empty; there is nothing to mutate." >&2
    exit 2
  fi
  RUSTC_WRAPPER= cargo mutants --workspace --in-diff "$work/diff" --list --no-times > "$work/list" 2>&1 \
    || { cat "$work/list" >&2; echo "error: cargo-mutants could not list the mutants." >&2; exit 1; }
  mutant_count=$(grep -Ec ':[0-9]+:[0-9]+:' "$work/list" || true)
  if [ "$mutant_count" -gt "$max_mutants" ]; then
    echo "error: $mutant_count mutants exceed the ${max_mutants}-mutant budget." >&2
    echo "       Narrow the change; never raise the budget, never fall back to a workspace run." >&2
    exit 3
  fi
  if [ "$mutant_count" -eq 0 ]; then
    echo "ok: no mutants in the changed lines."
    exit 0
  fi

  echo "mutating $mutant_count mutant(s) in $file_count file(s) (budget: $max_mutants mutants / ${max_seconds}s)"
  if command -v timeout >/dev/null 2>&1; then
    timeout "$max_seconds" env RUSTC_WRAPPER= cargo mutants --workspace --in-diff "$work/diff" --timeout-multiplier 2 --no-times
  elif command -v gtimeout >/dev/null 2>&1; then
    gtimeout "$max_seconds" env RUSTC_WRAPPER= cargo mutants --workspace --in-diff "$work/diff" --timeout-multiplier 2 --no-times
  else
    echo "warning: neither 'timeout' nor 'gtimeout' is available; the ${max_seconds}s wall-clock cap is not enforced." >&2
    echo "         Install coreutils ('brew install coreutils') to get 'gtimeout'." >&2
    env RUSTC_WRAPPER= cargo mutants --workspace --in-diff "$work/diff" --timeout-multiplier 2 --no-times
  fi

# Fail if an unbounded mutation command reappears in a build or CI file.
# Whole-workspace mutation runs take hours and rarely finish, so they are
# prohibited: the only permitted forms are a diff-scoped (`--in-diff`), a
# file-scoped (`--file`), or a branch-scoped (`--since`) run.
#
# Check that no build or CI file regains an unbounded mutation command.
check-mutation-scope:
  #!/usr/bin/env bash
  set -euo pipefail
  status=0
  for file in Justfile justfile Makefile makefile .github/workflows/*.yml .github/workflows/*.yaml; do
    [ -f "$file" ] || continue
    offenders=$(grep -nE 'cargo[[:space:]]+mutants' "$file" \
      | grep -vE '^[0-9]+:[[:space:]]*#' \
      | grep -vE -- '--in-diff|--file|--list|--since|-f[[:space:]]' \
      || true)
    if [ -n "$offenders" ]; then
      echo "error: $file runs an unbounded mutation command:" >&2
      printf '%s\n' "$offenders" >&2
      echo "       Whole-workspace mutation runs are prohibited. Use the diff-scoped 'just mutation'." >&2
      status=1
    fi
  done
  exit "$status"

# Mutation-test only the lines changed in the working tree. The full gate above
# scans ~2900 mutants (a long-running local gate); this is the gate for one
# change.
mutation-diff:
  @set -eu; d=$(mktemp); trap 'rm -f "$d"' EXIT; git diff > "$d"; cargo mutants --in-diff "$d"

# Type-check every fuzz target (no execution)
#
# Plain `cargo check` on each detached fuzz workspace. `cargo fuzz check` is
# unfit for this gate: its default `--target` is the triple the cargo-fuzz
# binary was built for, which on Linux CI is x86_64-unknown-linux-musl. That
# target has no std installed and its static libc conflicts with ASan, so the
# gate failed before it ever checked our code.
fuzz-check:
  cargo +nightly check --manifest-path crates/shellflow-core/fuzz/Cargo.toml --bins
  cargo +nightly check --manifest-path crates/shellflow-dsl/fuzz/Cargo.toml --bins
  cargo +nightly check --manifest-path crates/shellflow-secrets/fuzz/Cargo.toml --bins

# Run every fuzz target for SECS seconds (hostile-input parsers)
fuzz SECS="20":
  cd crates/shellflow-core && cargo +nightly fuzz run fuzz_parse_script -- -max_total_time={{SECS}}
  cd crates/shellflow-core && cargo +nightly fuzz run fuzz_interpolate -- -max_total_time={{SECS}}
  cd crates/shellflow-dsl && cargo +nightly fuzz run fuzz_parse_ssh_spec -- -max_total_time={{SECS}}
  cd crates/shellflow-secrets && cargo +nightly fuzz run fuzz_parse_env_file -- -max_total_time={{SECS}}

# Run tests with coverage
test-coverage:
  cargo tarpaulin --all-features --workspace --timeout 300

# Build entire workspace
build:
  cargo build --workspace

# Check all targets compile
check:
  cargo check --all-targets --all-features

# Publish all crates to crates.io (dry run)
publish-check:
  cargo publish --workspace --dry-run --allow-dirty

# Publish the library crates to crates.io (irreversible: run only with a
# registry token). Published per-crate in dependency order rather than via
# `cargo publish --workspace` so the step is idempotent: a crate that is
# already on crates.io is skipped instead of aborting the whole run, which is
# what lets a retagged force-push re-run resume after a partial upload. A crate
# is retried while its just-published sibling is still propagating through
# crates.io's index — cargo otherwise fails the entire run the moment a
# dependent cannot yet resolve that dependency. `shellflow-muxy` and the
# `shellflow` binary are `publish = false` (their deps are git-only) and are
# not published here.
publish:
  #!/usr/bin/env bash
  set -uo pipefail
  CRATES=(shellflow-text shellflow-dsl shellflow-core shellflow-secrets)
  n=${#CRATES[@]}
  for ((i = 0; i < n; i++)); do
    pkg=${CRATES[i]}
    published=0
    for attempt in $(seq 1 30); do
      # Drop the cached crates.io index so each attempt re-fetches the latest
      # entry for a freshly published sibling. The `just ci` step populates the
      # index cache before any crate is published, so without this cargo trusts
      # a stale conditional-GET copy and never sees the new version.
      rm -rf "${CARGO_HOME:-$HOME/.cargo}/registry/index"
      if out=$(cargo publish -p "$pkg" 2>&1); then
        echo "published $pkg (attempt $attempt)"; published=1; break
      elif echo "$out" | grep -qiE "already (uploaded|published)|already exists|is already"; then
        echo "skip $pkg (already on crates.io)"; published=1; break
      elif echo "$out" | grep -qiE "no matching package|timed out|waiting for published"; then
        echo "$pkg blocked on dependency index propagation (attempt $attempt/30); retrying in 20s"; sleep 20
      else
        echo "failed to publish $pkg:"; printf '%s\n' "$out"; exit 1
      fi
    done
    if ((published == 0)); then echo "gave up on $pkg after 30 attempts"; exit 1; fi
    if ((i < n - 1)); then sleep 60; fi
  done

# Fail if Chinese characters are present in tracked files
check-cn:
  #!/usr/bin/env bash
  set -euo pipefail
  if rg --line-number --column "\p{Han}" . ; then
    echo "error: Chinese characters found" >&2
    exit 1
  fi
  echo "ok: no Chinese characters found"

# Full CI check
#
# `fuzz-check` is part of the gate, not an optional extra: the fuzz crates are
# detached workspaces, so neither `cargo check` nor `cargo test` at the root
# compiles them, and a fuzz target broken by a parser change would otherwise
# stay broken until someone ran it by hand. `check-cn` enforces AGENTS.md's
# English-only rule.
ci: lint test build fuzz-check check-cn

# ============================================================
# Maintenance & Tools
# ============================================================

# Clean build artifacts
clean:
  cargo clean

# Install all required development tools
setup:
  cargo install cargo-mutants
  cargo install cargo-sort
  cargo install typos-cli
  cargo install rumdl
  cargo install cargo-tarpaulin
  cargo install cargo-nextest
  cargo install cargo-fuzz
  cargo install cargo-audit
  cargo install cargo-outdated

# Generate documentation for the workspace
docs:
  cargo doc --no-deps --open

# Scan the working tree and full git history for leaked secrets
secrets:
  gitleaks git . --config .gitleaks.toml --redact --no-banner --log-opts="--all"
  gitleaks dir . --config .gitleaks.toml --redact --no-banner

# Run security audit
audit:
  cargo audit

# Check for outdated dependencies
outdated:
  cargo outdated

# Run clippy with all lints
clippy-all:
  RUSTC_WRAPPER= cargo +nightly clippy --all-targets --all-features -- -W clippy::pedantic -W clippy::nursery -W clippy::cargo

# Run tests with nextest
test-nextest:
  cargo nextest run --all-features

# Update all dependencies
update-deps:
  cargo update

# Full check (lint + test + build + audit)
full-check: lint test build audit
