# Default recipe to display help
default:
  @just --list

# Format all code
format:
  rumdl fmt .
  cargo sort -w -g
  cargo +nightly fmt --all
  # The fuzz crates are detached workspaces, so `cargo fmt --all` skips them.
  rustfmt --edition 2024 crates/shellflow-core/fuzz/fuzz_targets/*.rs
  rustfmt --edition 2024 crates/shellflow-secrets/fuzz/fuzz_targets/*.rs

# Auto-fix linting issues
fix:
  rumdl check --fix .
  RUSTC_WRAPPER= cargo +nightly clippy --fix --all --allow-dirty

# Run all lints
lint:
  typos
  rumdl check .
  cargo sort -w -g -c
  cargo +nightly fmt --all -- --check
  RUSTC_WRAPPER= cargo +nightly clippy --all -- -D warnings
  RUSTC_WRAPPER= cargo shear

# Run tests
test:
  cargo test --all-features

# Run mutation tests with cargo-mutants
mutation:
  cargo mutants

# Type-check every fuzz target (no execution)
fuzz-check:
  cd crates/shellflow-core && cargo +nightly fuzz check
  cd crates/shellflow-secrets && cargo +nightly fuzz check

# Run every fuzz target for SECS seconds (hostile-input parsers)
fuzz SECS="20":
  cd crates/shellflow-core && cargo +nightly fuzz run fuzz_parse_script -- -max_total_time={{SECS}}
  cd crates/shellflow-core && cargo +nightly fuzz run fuzz_interpolate -- -max_total_time={{SECS}}
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

# Publish all crates to crates.io
publish:
  cargo publish --workspace

# Check for Chinese characters (fail when any are found)
check-cn:
  ! rg --line-number --column "\p{Han}"

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

# Generate documentation for the workspace
docs:
  cargo doc --no-deps --open
