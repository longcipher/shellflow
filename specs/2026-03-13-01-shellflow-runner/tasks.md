# Shellflow Runner — Implementation Tasks (Simplified)

| Metadata | Details |
| :--- | :--- |
| **Design Doc** | specs/2026-03-13-01-shellflow-runner/design.md |
| **Owner** | TBD |
| **Start Date** | 2026-03-13 |
| **Target Date** | TBD |
| **Status** | Planning (Simplified) |

## Summary

Implementation of the **simplified** Shellflow bash script runner. This is a minimal, single-file implementation (~500 lines) that:
- Parses `.sh` files with comment markers (`# @LOCAL`, `# @REMOTE <host>`)
- Executes blocks sequentially (local subprocess or SSH)
- Provides fail-fast behavior with clear error reporting
- Reuses `~/.ssh/config` for host definitions

**Design Philosophy:** Simple and direct. No complex abstraction layers, no over-engineering.

---

## Phase 1: Foundation

### Task 1.1: Single-File Implementation

> **Context:** Create the complete implementation in a single file `src/shellflow.py`. This file will contain ~500 lines covering CLI, parser, runner, and SSH execution.
> **Verification:** The file can be executed directly and passes basic tests.

- **Priority:** P0
- **Scope:** Complete single-file implementation
- **Loop Type:** TDD
- **Status:** 🟢 DONE
- [x] **Step 1:** Create `src/shellflow.py` with module docstring and imports
- [x] **Step 2:** Define dataclasses: `Block`, `ExecutionContext`, `ExecutionResult`, `RunResult`, `SSHConfig`
- [x] **Step 3:** Define exception classes: `ShellflowError`, `ParseError`, `ExecutionError`
- [x] **Step 4:** Implement `parse_script(content: str) -> list[Block]`:
- [x] **Step 5:** Implement `read_ssh_config(host: str) -> SSHConfig | None`
- [x] **Step 6:** Implement `execute_local(block: Block, context: ExecutionContext) -> ExecutionResult`
- [x] **Step 7:** Implement `execute_remote(block: Block, context: ExecutionContext, ssh_config: SSHConfig) -> ExecutionResult`
- [x] **Step 8:** Implement `run_script(blocks: list[Block], verbose: bool = False) -> RunResult`
- [x] **Step 9:** Implement CLI using `argparse`
- [x] **Step 10:** Add `if __name__ == "__main__": main()` entry point
- [x] **Verification:** Run `uv run python src/shellflow.py --version` and see output
- [x] **Verification:** Run `uv run python src/shellflow.py run tests/fixtures/local_only.sh` and see success

---

## Phase 2: Testing

### Task 2.1: Unit Tests

> **Context:** Write focused unit tests for the core functions in `src/shellflow.py`.
> **Verification:** All unit tests pass.

- **Priority:** P0
- **Scope:** Unit tests for parser and execution logic
- **Loop Type:** TDD
- **Status:** 🟢 DONE
- [x] **Step 1:** Create `tests/test_shellflow.py` with comprehensive tests
- [x] **Verification:** 85 tests passing
- [x] **Verification:** `uv run ty check tests/test_shellflow.py` passes
- [x] **Verification:** `uv run ruff check tests/test_shellflow.py` passes
- [ ] **Step 2:** Write tests for `parse_script()`:
  - Test parsing `# @LOCAL` blocks
  - Test parsing `# @REMOTE <host>` blocks
  - Test parsing mixed local and remote blocks
  - Test empty script
  - Test script with no markers (treat as single local block?)
- [ ] **Step 3:** Write tests for `execute_local()`:
  - Test successful command execution
  - Test command failure (non-zero exit)
  - Test environment variable passing
  - Test stdout/stderr capture
- [ ] **Step 4:** Write tests for `run_script()` (integration):
  - Test sequential execution of multiple blocks
  - Test fail-fast behavior
  - Test context passing between blocks
- [ ] **Verification:** Run `uv run pytest tests/test_shellflow.py -v` and confirm 100% pass

---

### Task 2.2: BDD Scenarios

> **Context:** Create simplified BDD feature files that match the simplified implementation.
> **Verification:** BDD scenarios are defined and pass.

- **Priority:** P1
- **Scope:** BDD scenarios for core behaviors
- **Loop Type:** BDD+TDD
- **Status:** 🟡 IN PROGRESS
- [ ] **Step 1:** Create `features/runner.feature` with scenarios:
  - Execute local-only script
  - Execute remote-only script
  - Execute mixed local and remote script
  - Fail fast on block failure
- [ ] **Step 2:** Create `features/parser.feature` with scenarios:
  - Parse local marker
  - Parse remote marker with host
- [ ] **Step 3:** Create `features/steps/shellflow_steps.py` with step definitions
- [ ] **Verification:** Run `uv run behave features/` and confirm scenarios pass

---

## Phase 3: Integration & Polish

### Task 3.1: Integration & Documentation

> **Context:** Ensure all components work together, write README, and add example scripts.
> **Verification:** End-to-end tests pass, documentation is complete.

- **Priority:** P1
- **Scope:** Integration and documentation
- **Loop Type:** TDD
- **Status:** 🔴 TODO
- [ ] **Step 1:** Create test fixtures in `tests/fixtures/`:
  - `local_only.sh` - Simple local script
  - `with_error.sh` - Script that fails
  - `local_and_remote.sh` - Mixed script
- [ ] **Step 2:** Test end-to-end execution:
  - `uv run shellflow run tests/fixtures/local_only.sh`
  - `uv run shellflow run tests/fixtures/local_and_remote.sh`
- [ ] **Step 3:** Update `README.md` with:
  - Project description
  - Installation instructions
  - Quick start guide
  - Example usage
- [ ] **Step 4:** Create `examples/` directory with sample scripts:
  - `simple.sh` - Basic local script
  - `deploy.sh` - Local + remote deployment example
- [ ] **Verification:** Run `uv run pytest tests/ -v` and confirm all tests pass
- [ ] **Verification:** Run `uv run ruff check src/` and confirm no lint errors
- [ ] **Verification:** Run `uv run ty check src/` and confirm no type errors

---

## Definition of Done

Every task must meet these criteria before being marked complete.

1. [ ] **Linted:** No lint errors (`uv run ruff check src/` passes).
2. [ ] **Tested:** Unit tests covering the added logic (`uv run pytest tests/` passes).
3. [ ] **Formatted:** Code formatter applied (`uv run ruff format src/`).
4. [ ] **Verified:** The task's specific Verification criterion is met.
5. [ ] **Behavior-Preserved or Documented:** The task confirms behavior preservation or documents the intentional behavior change.
