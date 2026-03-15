# Default recipe to display help
default:
  @just --list

# Sync all dependencies
sync:
  uv sync --all-groups

# Format all code
format:
  rumdl fmt .
  uv run ruff format .
  uv run ruff check --fix .

# Auto-fix linting issues
fix:
  rumdl check --fix .
  uv run ruff check --fix .

# Run all lints
lint:
  typos
  rumdl check .
  uv run ruff check .
  uv run ruff format --check .
  uv run ty check src tests

# Run tests
test:
  uv run pytest

# Run BDD scenarios
bdd:
  uv run behave

# Run both TDD and BDD suites
test-all:
  uv run pytest
  uv run behave

# Run tests with coverage
test-coverage:
  uv run pytest --cov=uv_app --cov-report=term-missing --cov-report=html

# Run benchmarks
bench:
  uv run pytest -m benchmark --benchmark-only

# Build the package
build:
  uv build

# Type check with ty
typecheck:
  uv run ty check src tests

# Check for Chinese characters
check-cn:
  rg --line-number --column "\p{Han}"

# Full CI check
ci: lint test-all build

# ============================================================
# Maintenance & Tools
# ============================================================

# Clean build artifacts
clean:
  rm -rf dist/ .pytest_cache/ .ruff_cache/ htmlcov/ .coverage
  find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
  find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true

# Install all required development tools
setup:
  uv sync --all-groups
  cargo install typos-cli

# Lock dependencies
lock:
  uv lock

# Update all dependencies
update:
  uv lock --upgrade
