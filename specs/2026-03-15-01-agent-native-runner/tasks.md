# Agent Native Runner — Tasks

| Metadata | Details |
| :--- | :--- |
| **Design Doc** | specs/2026-03-15-01-agent-native-runner/design.md |
| **Status** | Complete |

## Summary & Timeline

| Phase | Focus | Outcome |
| :--- | :--- | :--- |
| **Phase 1** | BDD harness and structured contract | Acceptance coverage for machine-readable behavior |
| **Phase 2** | Core execution changes | JSON/JSONL, exit codes, no-input, timeout, retry, export support |
| **Phase 3** | Safety and docs | Dry-run, audit log, README and CLI updates |
| **Phase 4** | Verification polish | Property tests and cleanup |

## Phase 1: BDD Harness

### Task 1.1: Add agent-native acceptance scenarios

> **Context:** Reuse the existing Behave harness in [features/steps/shellflow_steps.py](/Users/akagi201/src/github.com/longcipher/shellflow/features/steps/shellflow_steps.py) and the current script-execution scenarios in [features/runner.feature](/Users/akagi201/src/github.com/longcipher/shellflow/features/runner.feature). Add new root feature scenarios for JSON output, JSONL streaming, exit-code classes, no-input, timeout, retry, export propagation, dry-run, and audit logging.
> **Scenario Coverage:** `execution_contract.feature`, `resilience_and_context.feature`, `safety_controls.feature`
> **Verification:** Behave scenarios fail first, then pass against the new behavior.

- **Loop Type:** `BDD+TDD`
- **Behavioral Contract:** Preserve existing local/remote execution semantics while adding new explicit agent-facing behavior.
- **Simplification Focus:** Consolidate new acceptance coverage into the existing Behave harness instead of creating a second runner.
- **Advanced Test Coverage:** `Example-based only`
- **Status:** 🟢 DONE
- [x] Step 1: Add root Behave feature files mirroring this spec's scenarios.
- [x] Step 2: Extend step definitions for structured output assertions, no-input behavior, timeout behavior, retry counts, and audit-log files.
- [x] Step 3: Keep remote-execution mocking aligned with current step-definition style.
- [x] BDD Verification: `uv run behave features`
- [x] Verification: Confirm at least one scenario fails before implementation and all pass after implementation.
- [x] Advanced Test Verification: `N/A` because this task is acceptance-harness setup only.
- [x] Runtime Verification (if applicable): `N/A` because Shellflow is a one-shot CLI, not a long-running service.

### Task 1.2: Refine result and event data model

> **Context:** The current result types in [src/shellflow.py](/Users/akagi201/src/github.com/longcipher/shellflow/src/shellflow.py) only carry combined output and a coarse success flag. Add a single structured report/event model that can drive human output, JSON output, JSONL output, and audit logging without duplicating business logic.
> **Scenario Coverage:** `execution_contract.feature` — JSON report mode returns machine-readable run and block results; `execution_contract.feature` — JSONL mode emits ordered events suitable for live observation.
> **Verification:** Pytest coverage proves serializer fields and event ordering.

- **Loop Type:** `BDD+TDD`
- **Behavioral Contract:** Preserve existing success/failure flow while enriching metadata.
- **Simplification Focus:** Remove output-format branching from execution flow by centralizing reporting data.
- **Advanced Test Coverage:** `Property`
- **Status:** 🟢 DONE
- [x] Step 1: Introduce data fields for block id, source line, stdout, stderr, duration, attempts, and timeout status.
- [x] Step 2: Add a single event/report builder used by all output modes.
- [x] Step 3: Ensure existing human-readable verbose output still reads naturally from the new model.
- [x] BDD Verification: `uv run behave features -n "JSON report mode returns machine-readable run and block results"`
- [x] Verification: `uv run pytest -q tests/test_shellflow.py -k "json or report or event"`
- [x] Advanced Test Verification: `uv run pytest -q tests/test_shellflow.py -k hypothesis`
- [x] Runtime Verification (if applicable): `N/A` because output rendering is process-local CLI behavior.

## Phase 2: Scenario Implementation

### Task 2.1: Implement JSON and JSONL output modes

> **Context:** The current CLI in [src/shellflow.py](/Users/akagi201/src/github.com/longcipher/shellflow/src/shellflow.py) exposes `run`, `--verbose`, and `--ssh-config` only. Add machine-readable output modes on top of the structured report model from Task 1.2.
> **Scenario Coverage:** `execution_contract.feature` — JSON report mode returns machine-readable run and block results; `execution_contract.feature` — JSONL mode emits ordered events suitable for live observation.
> **Verification:** CLI output can be parsed as JSON or JSONL and contains stable schema fields.

- **Loop Type:** `BDD+TDD`
- **Behavioral Contract:** Default human output remains unchanged unless the caller explicitly requests machine output.
- **Simplification Focus:** Reuse one report model across all sinks instead of maintaining parallel renderers with separate business rules.
- **Advanced Test Coverage:** `Property`
- **Status:** 🟢 DONE
- [x] Step 1: Extend the CLI with structured-output flags and mutual-exclusion rules.
- [x] Step 2: Emit a final JSON run report when JSON mode is enabled.
- [x] Step 3: Emit ordered event records when JSONL mode is enabled.
- [x] Step 4: Include `schema_version`, `run_id`, block ids, source lines, durations, and separate `stdout`/`stderr` fields.
- [x] BDD Verification: `uv run behave features -n "JSONL mode emits ordered events suitable for live observation"`
- [x] Verification: `uv run pytest -q tests/test_shellflow.py -k "jsonl or schema_version or run_id"`
- [x] Advanced Test Verification: `uv run pytest -q tests/test_shellflow.py -k hypothesis`
- [x] Runtime Verification (if applicable): `N/A` because Shellflow does not expose service logs or a probe endpoint.

### Task 2.2: Add exit-code taxonomy and no-input mode

> **Context:** Current `cmd_run()` returns `1` for most failures in [src/shellflow.py](/Users/akagi201/src/github.com/longcipher/shellflow/src/shellflow.py). Agents need machine-distinguishable failure classes, and automated runs must not hang on input prompts.
> **Scenario Coverage:** `execution_contract.feature` — exit codes distinguish parse, SSH config, runtime, and timeout failures; `safety_controls.feature` — no-input prevents blocking on stdin.
> **Verification:** CLI exits are stable and tests prove stdin is not consumed in no-input mode.

- **Loop Type:** `BDD+TDD`
- **Behavioral Contract:** Existing success code remains `0`; failures become more precise without changing default fail-fast ordering.
- **Simplification Focus:** Centralize exit-code mapping in one helper rather than scattering numeric returns across the CLI.
- **Advanced Test Coverage:** `Example-based only`
- **Status:** 🟢 DONE
- [x] Step 1: Add a central exit-code mapping for parse, SSH config, runtime, and timeout failures.
- [x] Step 2: Add CLI support for `--no-input`.
- [x] Step 3: Make local and remote execution paths treat stdin as unavailable when `--no-input` is set.
- [x] Step 4: Reflect timeout failures distinctly in both structured output and process exit status.
- [x] BDD Verification: `uv run behave features -n "no-input prevents blocking on stdin"`
- [x] Verification: `uv run pytest -q tests/test_shellflow.py -k "exit code or no_input or timeout"`
- [x] Advanced Test Verification: `N/A` because this task is driven by deterministic examples, not broad generated domains.
- [x] Runtime Verification (if applicable): `N/A` because Shellflow is not a resident runtime with logs or health checks.

### Task 2.3: Parse and enforce timeout and retry directives

> **Context:** User requirements explicitly call for timeout and retry, but the design rejects a general branching DSL. Extend the existing line-oriented parser in [src/shellflow.py](/Users/akagi201/src/github.com/longcipher/shellflow/src/shellflow.py) with bounded directives only.
> **Scenario Coverage:** `resilience_and_context.feature` — timeout stops a stuck block and reports a timeout-specific failure; `resilience_and_context.feature` — retry reruns a transiently failing block and reports attempts.
> **Verification:** Retries are counted correctly, timeout behavior is bounded, and invalid directives fail parsing.

- **Loop Type:** `BDD+TDD`
- **Behavioral Contract:** Existing scripts without directives continue to parse and execute exactly as before.
- **Simplification Focus:** Keep directives as leading block comment lines instead of inventing a full marker-option grammar.
- **Advanced Test Coverage:** `Combination`
- **Status:** 🟢 DONE
- [x] Step 1: Extend the parser to recognize `@TIMEOUT` and `@RETRY` as block-local directives.
- [x] Step 2: Validate directive values and produce parse errors for invalid arguments.
- [x] Step 3: Apply timeout and retry policies consistently in both local and remote execution paths.
- [x] Step 4: Emit retry and timeout metadata through the structured event/report pipeline.
- [x] BDD Verification: `uv run behave features -n "retry reruns a transiently failing block and reports attempts"`
- [x] Verification: `uv run pytest -q tests/test_shellflow.py -k "retry or timeout or directive"`
- [x] Advanced Test Verification: `uv run pytest -q tests/test_shellflow.py -k hypothesis`
- [x] Runtime Verification (if applicable): `N/A` because this is bounded CLI execution rather than a continuously running service.

### Task 2.4: Add named export propagation

> **Context:** `ExecutionContext` currently carries `SHELLFLOW_LAST_OUTPUT` only in [src/shellflow.py](/Users/akagi201/src/github.com/longcipher/shellflow/src/shellflow.py). Expand context in a narrow way by letting blocks export named scalar values from their own result into later block environments.
> **Scenario Coverage:** `resilience_and_context.feature` — named exports become environment variables for later blocks.
> **Verification:** Exported values appear in later local and remote block environments and invalid export names are rejected.

- **Loop Type:** `BDD+TDD`
- **Behavioral Contract:** `SHELLFLOW_LAST_OUTPUT` remains supported; named exports are additive.
- **Simplification Focus:** Reuse `ExecutionContext.env` instead of adding a separate import/export subsystem.
- **Advanced Test Coverage:** `Property`
- **Status:** 🟢 DONE
- [x] Step 1: Add `@EXPORT NAME=source` parsing and validation.
- [x] Step 2: Map supported sources such as `stdout`, `stderr`, `output`, and `exit_code` into `ExecutionContext.env`.
- [x] Step 3: Ensure exported values are visible in later local and remote execution paths.
- [x] Step 4: Redact secret-like variable names when these exports appear in audit-oriented structured sinks.
- [x] BDD Verification: `uv run behave features -n "named exports become environment variables for later blocks"`
- [x] Verification: `uv run pytest -q tests/test_shellflow.py -k "export or env or SHELLFLOW_LAST_OUTPUT"`
- [x] Advanced Test Verification: `uv run pytest -q tests/test_shellflow.py -k hypothesis`
- [x] Runtime Verification (if applicable): `N/A` because export propagation is verified within one CLI process.

## Phase 3: Integration

### Task 3.1: Implement dry-run and audit-log using the shared event pipeline

> **Context:** The design accepts dry-run and audit logging, but explicitly rejects a second bespoke logging system. Build both features on the JSONL event stream added earlier.
> **Scenario Coverage:** `safety_controls.feature` — dry-run previews execution without running commands; `safety_controls.feature` — audit-log writes structured events for later inspection.
> **Verification:** Dry-run skips actual execution, and audit logs contain parseable event records with redaction applied where required.

- **Loop Type:** `BDD+TDD`
- **Behavioral Contract:** Normal execution remains unchanged when neither safety flag is enabled.
- **Simplification Focus:** Reuse event emission for audit logging rather than building parallel log formatting and storage paths.
- **Advanced Test Coverage:** `Example-based only`
- **Status:** 🟢 DONE
- [x] Step 1: Add CLI support for `--dry-run` and `--audit-log`.
- [x] Step 2: Make dry-run emit block plan events and skip command execution entirely.
- [x] Step 3: Mirror JSONL events into the audit-log file when configured.
- [x] Step 4: Add simple redaction coverage for obvious secret-bearing export names.
- [x] BDD Verification: `uv run behave features -n "dry-run previews execution without running commands"`
- [x] Verification: `uv run pytest -q tests/test_shellflow.py -k "dry_run or audit_log or redact"`
- [x] Advanced Test Verification: `N/A` because the main concern is deterministic side-effect control.
- [x] Runtime Verification (if applicable): `N/A` because Shellflow is a single-run CLI with file artifacts rather than service logs and probes.

### Task 3.2: Update documentation and CLI help for agent-native usage

> **Context:** [README.md](/Users/akagi201/src/github.com/longcipher/shellflow/README.md) currently describes human-oriented usage, `SHELLFLOW_LAST_OUTPUT`, and existing CLI flags. It must explain when to use JSON vs JSONL, why Shellflow intentionally avoids internal branching, and how agents should author bounded directives.
> **Scenario Coverage:** All scenarios indirectly, because the documentation must match the shipped behavior.
> **Verification:** README examples and CLI help reflect actual flags and behaviors.

- **Loop Type:** `TDD-only`
- **Behavioral Contract:** Documentation reflects implemented behavior; no runtime behavior change beyond help text.
- **Simplification Focus:** Document one recommended agent workflow instead of a menu of speculative advanced patterns.
- **Advanced Test Coverage:** `Example-based only`
- **Status:** 🟢 DONE
- [x] Step 1: Update README usage, script examples, and execution model sections.
- [x] Step 2: Document accepted directives and explicitly document rejected patterns such as conditional DSLs.
- [x] Step 3: Update CLI epilog/help text with agent-native examples.
- [x] BDD Verification: `N/A` because documentation changes are verified against implemented behavior, not separate scenarios.
- [x] Verification: Run `uv run python src/shellflow.py --help` and compare with README examples.
- [x] Advanced Test Verification: `N/A` because documentation is not a property/fuzz/benchmark target.
- [x] Runtime Verification (if applicable): `N/A` because this task does not introduce runtime behavior.

## Phase 4: Polish

### Task 4.1: Add Hypothesis coverage for parser and report invariants

> **Context:** Directive parsing and structured serialization are broad input-domain logic and should not rely on examples alone. The repository already includes Hypothesis in [pyproject.toml](/Users/akagi201/src/github.com/longcipher/shellflow/pyproject.toml).
> **Scenario Coverage:** Supports `execution_contract.feature` and `resilience_and_context.feature` by hardening parser and serializer invariants.
> **Verification:** Generated tests prove export-name validity, directive parsing stability, and schema serialization invariants.

- **Loop Type:** `TDD-only`
- **Behavioral Contract:** No user-visible change; this task hardens correctness around the accepted contract.
- **Simplification Focus:** Add focused generators around the new parser and serializer instead of broad random end-to-end fuzzing.
- **Advanced Test Coverage:** `Property`
- **Status:** 🟢 DONE
- [x] Step 1: Add Hypothesis strategies for valid and invalid directive lines.
- [x] Step 2: Add Hypothesis tests for export-name validation and schema-required fields.
- [x] Step 3: Ensure generated tests remain deterministic and readable when failures occur.
- [x] BDD Verification: `N/A` because this task strengthens implementation invariants below the acceptance layer.
- [x] Verification: `uv run pytest -q tests/test_shellflow.py -k hypothesis`
- [x] Advanced Test Verification: `uv run pytest -q tests/test_shellflow.py -k hypothesis`
- [x] Runtime Verification (if applicable): `N/A` because this task adds test coverage only.

## Definition of Done

1. All accepted agent-native behaviors from the design are covered by root Behave scenarios.
2. Human mode remains backward compatible for existing scripts.
3. Structured modes emit stable parseable output with documented fields.
4. Exit codes cleanly distinguish parse, runtime, SSH-config, and timeout failures.
5. No internal conditional DSL, heuristic destructive detection, or checkpoint/resume work is introduced by accident.
6. `uv run pytest -q`, `uv run behave features`, `uv run ruff check .`, and `uv run ty check src tests` all pass after implementation.
