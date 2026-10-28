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
  RUSTC_WRAPPER= cargo shear

# Run the workspace test suite
test:
  cargo test --all-features

# .cargo/mutants.toml excludes only the modules whose behaviour lives in the
# integration suite (`main.rs`, `executor/process.rs`) and the demo targets;
# see the file for why.
#
# Run mutation tests with cargo-mutants
mutation:
  cargo mutants --workspace

# Type-check every fuzz target (no execution)
fuzz-check:
  cd crates/shellflow-core && cargo +nightly fuzz check
  cd crates/shellflow-dsl && cargo +nightly fuzz check
  cd crates/shellflow-secrets && cargo +nightly fuzz check

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
  cargo install cargo-shear
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

# Check for unused dependencies
unused-deps:
  cargo shear --check

# Update all dependencies
update-deps:
  cargo update

# Full check (lint + test + build + audit)
full-check: lint test build audit
