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

# .cargo/mutants.toml excludes the binary and example crates: cargo-mutants
# only runs each crate's own test target.
#
# Run mutation tests with cargo-mutants
mutation:
  cargo mutants

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

# Publish all crates to crates.io (irreversible: run only with a registry token)
publish:
  cargo publish --workspace

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
ci: lint test build

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
