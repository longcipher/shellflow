# Design Document: Shellflow Runner

| Metadata | Details |
| :--- | :--- |
| **Author** | pb-plan agent |
| **Status** | Revised v3 (Simplified) |
| **Created** | 2026-03-13 |
| **Revised** | 2026-03-13 |
| **Revised v2** | 2026-03-14 |
| **Revised v3** | 2026-03-14 |
| **Reviewers** | N/A |
| **Related Issues** | N/A |

## 1. Executive Summary

**Problem:** DevOps engineers frequently need to execute bash scripts across multiple environments (local and remote SSH servers) in a specific sequence. Existing solutions either require separate script files for each environment or lack proper error handling and execution ordering.

**Solution:** Shellflow is a lightweight Python tool that interprets a single `.sh` file containing special comment markers (`# @LOCAL`, `# @REMOTE <host>`) to execute code blocks sequentially on the appropriate target. It provides fail-fast behavior with comprehensive error reporting, supports local and remote SSH execution, and maintains full IDE compatibility through standard bash syntax.

**Design Philosophy:** Simple and direct. No complex abstraction layers, no over-engineering. A single-file implementation that does one thing well: execute bash blocks on local or remote hosts in sequence.

---

## 2. Requirements & Goals

### 2.1 Problem Statement

Current pain points in DevOps script management:
- Fragmented script files: Separate scripts for local and remote operations
- Manual sequencing: No built-in way to define execution order across environments
- Poor error handling: Scripts continue executing after failures or provide minimal error context
- IDE friction: Custom DSLs break syntax highlighting and IDE features

### 2.2 Functional Goals

1. **Unified Script Format:** Single `.sh` file with special comment markers to distinguish execution targets
2. **Local Execution:** Execute code blocks on the local machine via subprocess
3. **Remote Execution:** Execute code blocks on remote hosts via SSH
4. **Sequential Execution:** Process code blocks in file order, respecting dependencies
5. **Fail-Fast Behavior:** Stop execution immediately on any block failure with full error details
6. **Environment Context:** Support variable passing between blocks (local output -> remote input)
7. **SSH Configuration Reuse:** Leverage existing `~/.ssh/config` for host definitions (no separate host configuration)

### 2.2.1 Out of Scope (Current Version)

The following features are explicitly deferred to future versions to maintain simplicity:

- **Multi-Machine Concurrent Execution:** No host groups, no Fan-Out/Fan-In
- **Project-Level Configuration:** No `shellflow.toml`, reuse `~/.ssh/config` instead
- **Partial Success Semantics:** No `fail_threshold`, fail-fast only
- **Structured JSON Logging:** Human-readable terminal output only
- **Complex Abstraction Layers:** No Strategy/Factory/Template patterns - simple if/match

### 2.3 Non-Functional Goals

- **Performance:** Minimal overhead compared to direct script execution (< 100ms per block for local, < 200ms for remote)
- **Reliability:** Graceful handling of SSH disconnections, timeouts, and failures
- **Security:** No hardcoded credentials; support for SSH keys, agents, and environment variables via `~/.ssh/config`
- **Observability:** Human-readable terminal output with execution context, timing, and color-coded status
- **Compatibility:** Works with standard bash; no custom DSL or syntax modifications
- **Simplicity:** Single-file implementation with minimal dependencies, no complex abstraction layers

### 2.4 Out of Scope (v1)

- Interactive shell sessions (REPL mode)
- Multi-machine concurrent execution (Fan-Out/Fan-In, host groups)
- Heterogeneous concurrent execution (different scripts on different hosts simultaneously)
- Built-in file synchronization (use rsync/scp in script blocks)
- GUI or web interface (CLI only)
- Multi-step rollback/undo functionality
- Cloud-specific integrations (AWS SSM, Azure Run Command, etc.)
- Project-level `shellflow.toml` configuration (use `~/.ssh/config` instead)
- Structured JSON logging (human-readable terminal output only)
- Complex design patterns (Strategy, Factory, Template Method) - simple if/match is sufficient

### 2.5 Assumptions

- Target systems have bash or compatible shell available
- SSH access is pre-configured (keys, known_hosts) for remote hosts
- Python 3.12+ is available on the local machine
- Users have basic familiarity with bash scripting
- Network connectivity exists between local and remote hosts during execution
- **Stateless Blocks**: Each block executes in an isolated environment. Changes to working directory (`cd`), shell variables (`export`), or other shell state in one block do NOT persist to subsequent blocks. Variables must be explicitly passed via the context mechanism.

### 2.6 Code Simplification Constraints

- **Behavioral Contract:** Preserve existing behavior unless a scenario or requirement explicitly changes it
- **Repo Standards:** Follow Python type annotations (`from __future__ import annotations`), use modern union syntax (`X | None`), prefer `ty` for type checking
- **Readability Priorities:** Explicit control flow, clear naming, reduced nesting, removal of redundant abstractions
- **Refactor Scope:** Limit cleanup to touched modules unless design explicitly broadens scope
- **Clarity Guardrails:** Avoid nested ternary operators; prefer clear branching

---

## 3. Architecture Overview

### 3.1 System Context

Shellflow operates as a CLI tool that processes user script files and coordinates execution across local and remote environments.

```
┌─────────────────────────────────────────────────────────────────────┐
│                        User Workflow                                  │
│                                                                     │
│  ┌─────────────┐    ┌─────────────────┐    ┌─────────────────────┐   │
│  │ Write .sh   │───>│ shellflow run   │───>│ Execution Results   │   │
│  │ with marks  │    │ script.sh       │    │ (local + remote)    │   │
│  └─────────────┘    └─────────────────┘    └─────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

System Components (Simplified):

```
┌─────────────────────────────────────────────────────────────┐
│              Shellflow Architecture (Simplified)            │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              shellflow.py (Single Module)          │   │
│  │                                                     │   │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────────────┐  │   │
│  │  │   CLI    │  │  Parser  │  │  Runner/Executor │  │   │
│  │  │  Entry   │──>│  Script  │──>│  Orchestration │  │   │
│  │  │  Point   │  │  Parser  │  │  + SSH via CLI   │  │   │
│  │  └──────────┘  └──────────┘  └──────────────────┘  │   │
│  │                                                     │   │
│  └─────────────────────────────────────────────────────┘   │
│                            │                                │
│                            v                                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              ~/.ssh/config (Standard SSH)            │   │
│  │          (No custom shellflow.toml needed)         │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Key Simplification Decisions:**

1. **Single-File Implementation**: Instead of 8+ modules (`cli.py`, `parser.py`, `runner.py`, `blocks/`, `executors/`, `config.py`), the entire functionality fits in a single `shellflow.py` file (~500 lines).

2. **No Complex Design Patterns**: No Strategy, Factory, Template Method, or Protocol abstractions. Simple `if/match` statements handle the two execution targets (local/remote).

3. **No Fan-Out/Fan-In**: No multi-host concurrent execution, no host groups, no `GroupResult`, no `AsyncRunner`. Single-machine sequential execution only.

4. **SSH Config Reuse**: No custom `shellflow.toml`. Reuse existing `~/.ssh/config` for host definitions.

5. **Human-Readable Output**: No JSON logging. Colored terminal output for humans.

### 3.2 Key Design Principles

1. **Single File, Multiple Targets:** One `.sh` file contains all logic with comments marking execution targets
2. **Fail Fast, Fail Loud:** Any error stops execution immediately with full context
3. **IDE Native:** No custom DSL - pure bash with comment annotations
4. **Context Flow:** Output from one block can be captured and passed to subsequent blocks
5. **Extensible Executors:** Clean abstraction for adding new execution targets (docker, k8s, etc.)

### 3.3 Existing Components to Reuse

No existing components identified for reuse. The current codebase contains a template uv-app with shopping cart example code that will be replaced entirely by the shellflow implementation.

### 3.4 Architecture Decisions (Simplified)

| Decision ID | Status | Decision | Rationale |
| :--- | :--- | :--- | :--- |
| AD-01 | Simplified | **Single-file implementation** | Instead of 8+ modules (cli.py, parser.py, runner.py, blocks/, executors/, config.py), the entire functionality fits in a single `shellflow.py` (~500 lines). No complex import graph to navigate. |
| AD-02 | Simplified | **Direct execution, no Strategy Pattern** | Only two execution targets (local, remote). Simple `if host:` check instead of Strategy + Factory + Protocol overhead. |
| AD-03 | Removed | **No Template Method** | No base class inheritance chain. Each block type is a simple dataclass; execution logic lives in the runner's single `execute_block()` method. |
| AD-04 | Simplified | **No DI Container** | Dependencies passed directly as function arguments. No registry, no service locator pattern. |
| AD-05 | Simplified | **No Fan-Out/Fan-In** | Single-machine sequential execution only. No async runner, no TaskGroup, no host groups, no GroupResult. |
| AD-06 | Simplified | **No Custom Config** | Reuse existing `~/.ssh/config` for host definitions. No `shellflow.toml`, no ConfigManager class. |
| AD-07 | Simplified | **No Protocol Classes** | No `typing.Protocol` for Block or Executor. Simple dataclasses and functions. |

**Key Principles:**
1. **YAGNI**: If a feature isn't needed for v1, it's out
2. **Explicit over Implicit**: No magic registries or dependency injection
3. **Flat over Nested**: Single file over deep module hierarchy
4. **Readability over Flexibility**: Simple `if/else` over Strategy Pattern

### 3.5 Project Identity Alignment

| Current Identifier | Location | Why It Is Generic or Misaligned | Planned Name / Action |
| :--- | :--- | :--- | :--- |
| `uv-app` | `pyproject.toml`, `src/uv_app/` | Generic template name from scaffold | Rename to `shellflow` / `src/shellflow/` |
| `uv_app` | `src/uv_app/__init__.py`, `src/uv_app/cli.py`, `src/uv_app/core.py` | Template module names | Rename to `shellflow` modules |
| `uv-app` | `pyproject.toml:project.scripts` | Template CLI name | Rename to `shellflow` |

**Identity Alignment Task:** Task 1.1 in tasks.md will handle the renaming before feature implementation begins.

---

## Revision History

| Date | Change | Reason |
| :--- | :--- | :--- |
| 2026-03-13 | Initial design created | Original planning for Shellflow Runner |
| 2026-03-13 | Added multi-machine concurrent execution (Fan-Out/Fan-In) | User feedback: need to execute same script on multiple hosts concurrently for batch operations |
| 2026-03-13 | Added project-level `shellflow.toml` configuration | User feedback: need project-local host and group definitions alongside global config |
| 2026-03-13 | Added `ExecutionTarget.REMOTE_GROUP` and `GroupResult` types | Architecture change: distinguish single-host vs group execution patterns |
| 2026-03-13 | Added `AsyncRunnerInterface` with `execute_group_concurrently` | Architecture change: async/await pattern for concurrent SSH operations |
| 2026-03-13 | Updated `ExecutionResult` to include optional `host` field | Context passing: identify which host produced result in group execution |
| 2026-03-13 | Added `HostGroup`, `ProjectConfig` TypedDict definitions | Configuration: support group definitions and project-level settings |
| 2026-03-13 | Changed "Parallel execution of independent blocks" from Out of Scope to "Heterogeneous parallel execution" | Clarification: same-block group concurrency is now in scope, only heterogeneous is out |
| 2026-03-14 | Changed SSH implementation from Paramiko to System SSH CLI | Critical fix: Use `ssh` command with asyncio.subprocess for full OpenSSH compatibility (ControlMaster, ~/.ssh/config) |
| 2026-03-14 | Updated ExecutionContext with group_variables and group_outputs | Architecture fix: Support Fan-In context aggregation from concurrent group execution |
| 2026-03-14 | Added stateless block assumption to Assumptions | Documentation fix: Clarify that working directory and environment variables don't persist between blocks |
| 2026-03-14 | Updated Security section: Variable injection via environment variables with shlex.quote | Security fix: Prevent shell injection by passing variables via env, not string templating |
| 2026-03-14 | **MAJOR SIMPLIFICATION** | **User feedback: Design was over-engineered. Removed: multi-machine concurrent execution, host groups, Fan-Out/Fan-In, Protocol classes, Strategy/Factory/Template patterns, 8+ module structure, shellflow.toml, JSON logging. Changed to single-file (~500 lines) implementation with simple if/match logic.** |
| 2026-03-13 | Added multi-machine concurrent execution (Fan-Out/Fan-In) | User feedback: need to execute same script on multiple hosts concurrently for batch operations |
| 2026-03-13 | Added project-level `shellflow.toml` configuration | User feedback: need project-local host and group definitions alongside global config |
| 2026-03-13 | Added `ExecutionTarget.REMOTE_GROUP` and `GroupResult` types | Architecture change: distinguish single-host vs group execution patterns |
| 2026-03-13 | Added `AsyncRunnerInterface` with `execute_group_concurrently` | Architecture change: async/await pattern for concurrent SSH operations |
| 2026-03-13 | Updated `ExecutionResult` to include optional `host` field | Context passing: identify which host produced result in group execution |
| 2026-03-13 | Added `HostGroup`, `ProjectConfig` TypedDict definitions | Configuration: support group definitions and project-level settings |
| 2026-03-13 | Changed "Parallel execution of independent blocks" from Out of Scope to "Heterogeneous parallel execution" | Clarification: same-block group concurrency is now in scope, only heterogeneous is out |

### 3.6 BDD/TDD Strategy

- **BDD Runner:** `behave`
- **BDD Command:** `uv run behave`
- **Unit Test Command:** `uv run pytest tests/ -v`
- **Property Test Tool:** `Hypothesis` - for parser and configuration property testing
- **Fuzz Test Tool:** `N/A` - no parser/protocol/unsafe boundaries in this release
- **Benchmark Tool:** `pytest-benchmark` - for SSH connection pooling benchmarks
- **Outer Loop:** `features/runner.feature` scenarios prove end-to-end execution works
- **Inner Loop:** Unit tests for `parser.py`, `runner.py`, `executors/`, `blocks/` drive implementation
- **Step Definition Location:** `features/steps/shellflow_steps.py`

**Property Testing Strategy:**
- Parser property tests: Generate random script content with markers, verify valid parsing
- Configuration property tests: Generate random config structures, verify validation

**Benchmark Strategy:**
- SSH connection establishment benchmark (when connection pooling implemented)
- Script parsing benchmark for large files

### 3.7 BDD Scenario Inventory

| Feature File | Scenario | Business Outcome | Primary Verification | Supporting TDD Focus |
| :--- | :--- | :--- | :--- | :--- |
| `features/runner.feature` | `Execute local-only script` | User runs script with only local blocks successfully | `behave` scenario passes | `LocalExecutor` unit tests |
| `features/runner.feature` | `Execute remote-only script` | User runs script with only remote blocks successfully | `behave` scenario passes | `SSHExecutor` unit tests |
| `features/runner.feature` | `Execute mixed local and remote script` | User runs script with interleaved local/remote blocks | `behave` scenario passes | `Runner` orchestration tests |
| `features/runner.feature` | `Fail fast on local block failure` | Execution stops immediately when local block fails | `behave` scenario passes | Error handling unit tests |
| `features/runner.feature` | `Fail fast on remote block failure` | Execution stops immediately when remote block fails | `behave` scenario passes | SSH error handling tests |
| `features/runner.feature` | `Capture output and pass to next block` | Block output is available to subsequent blocks | `behave` scenario passes | Context passing unit tests |
| `features/runner.feature` | `Execute concurrent group block on multiple hosts` | User runs script with group marker, executes on all hosts concurrently | `behave` scenario passes | `AsyncRunner` group execution tests |
| `features/runner.feature` | `Fail fast cancels all concurrent tasks on group failure` | When one host fails in group, others are cancelled | `behave` scenario passes | `AsyncRunner` cancellation tests |
| `features/runner.feature` | `Group results are available to subsequent blocks` | Group execution results aggregated for next block | `behave` scenario passes | Context aggregation tests |
| `features/parser.feature` | `Parse local marker` | Parser correctly identifies `# @LOCAL` blocks | `behave` scenario passes | `Parser` tokenization tests |
| `features/parser.feature` | `Parse remote marker with host` | Parser correctly identifies `# @REMOTE host` blocks | `behave` scenario passes | `Parser` block creation tests |
| `features/parser.feature` | `Parse remote group marker` | Parser correctly identifies `# @REMOTE @group` blocks | `behave` scenario passes | `RemoteGroupBlock` tests |
| `features/config.feature` | `Load SSH configuration` | User can define hosts in config file | `behave` scenario passes | `Config` loading tests |
| `features/config.feature` | `Load project-level configuration` | Project `shellflow.toml` is loaded | `behave` scenario passes | Project config tests |
| `features/config.feature` | `Project config overrides user config` | Project settings take precedence | `behave` scenario passes | Config merge tests |
| `features/config.feature` | `Host groups resolve to host list` | Groups expand to member hosts | `behave` scenario passes | Group resolution tests |

### 3.8 Simplification Opportunities in Touched Code

No existing code to simplify - this is a new feature implementation that replaces the template code.

---

## 4. Detailed Design

### 4.1 Module Structure (Simplified)

**Single-file implementation:**

```text
src/
└── shellflow.py           # Complete implementation (~500 lines)
```

**Alternative minimal structure (if single file becomes unwieldy):**

```text
src/
├── shellflow.py           # CLI, Runner, main logic
├── parser.py              # Script parsing (~50 lines)
└── ssh.py                 # SSH execution helper (~30 lines)
```

**Design rationale:**
- A single Python file can comfortably hold ~500 lines of well-organized code
- Fewer files = less cognitive load when navigating the codebase
- No import cycles or complex dependency graphs to manage
- Easier to distribute (single file can be copied/shared easily)

### 4.2 Data Structures (Simplified)

```python
"""Simplified data structures for shellflow.

Instead of complex Protocol classes, TypedDicts, and deep hierarchies,
we use simple dataclasses and enums.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path


class BlockType(Enum):
    """Type of execution block."""
    LOCAL = auto()
    REMOTE = auto()


@dataclass(frozen=True)
class Block:
    """A single executable block parsed from the script.

    Simplified: no Protocol, no complex inheritance.
    """
    type: BlockType
    content: str
    host: str | None = None  # Only set for REMOTE blocks
    line_start: int = 0  # For error reporting


@dataclass
class ExecutionContext:
    """Context passed between block executions.

    Simplified: no group_variables/group_outputs (no Fan-Out/Fan-In).
    """
    variables: dict[str, str] = field(default_factory=dict)
    last_output: str = ""


@dataclass(frozen=True)
class ExecutionResult:
    """Result of executing a single block."""
    success: bool
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int


@dataclass(frozen=True)
class RunResult:
    """Final result of running a script."""
    success: bool
    block_results: list[ExecutionResult]
    total_duration_ms: int


@dataclass
class SSHConfig:
    """SSH configuration for a remote host.

    Read from ~/.ssh/config (not from shellflow.toml).
    """
    host: str  # The hostname/alias from SSH config
    hostname: str | None = None  # The actual host to connect to
    port: int = 22
    user: str | None = None
    identity_file: str | None = None

    @classmethod
    def from_ssh_config(cls, host: str, ssh_config_path: Path | None = None) -> SSHConfig | None:
        """Parse SSH config file to get configuration for a host."""
        # Implementation using paramiko.SSHConfig or manual parsing
        ...


# Simple exception hierarchy (no complex inheritance)
class ShellflowError(Exception):
    """Base exception for all shellflow errors."""
    pass


class ParseError(ShellflowError):
    """Script parsing error with line context."""
    def __init__(self, message: str, line: int, content: str):
        super().__init__(f"{message} at line {line}: {content}")
        self.line = line
        self.content = content


class ExecutionError(ShellflowError):
    """Block execution failure."""
    def __init__(self, message: str, block_index: int, exit_code: int, stderr: str):
        super().__init__(f"{message} (block {block_index}, exit {exit_code}): {stderr}")
        self.block_index = block_index
        self.exit_code = exit_code
        self.stderr = stderr
```

### 4.3 Interface Design

```python
# Public API interfaces

from __future__ import annotations

from pathlib import Path
from typing import Protocol


class ParserInterface(Protocol):
    """Script parser interface."""

    def parse(self, script_path: Path) -> list[Block]: ...

    def parse_string(self, content: str) -> list[Block]: ...


class RunnerInterface(Protocol):
    """Script runner interface."""

    def run(self, script_path: Path) -> RunResult: ...

    def run_blocks(self, blocks: list[Block]) -> RunResult: ...


class AsyncRunnerInterface(Protocol):
    """Async script runner interface for concurrent execution."""

    async def run(self, script_path: Path) -> RunResult: ...

    async def run_blocks(self, blocks: list[Block]) -> RunResult: ...

    async def execute_group_concurrently(
        self, block: Block, hosts: list[str]
    ) -> GroupResult: ...


class ConfigManagerInterface(Protocol):
    """Configuration manager interface."""

    def load(self, path: Path | None = None) -> RunnerConfig: ...

    def get_ssh_config(self, host: str) -> SSHConfig | None: ...


# CLI Interface
# $ shellflow run <script.sh> [--config <path>] [--verbose] [--dry-run]
# $ shellflow validate <script.sh>  # Check syntax without executing
# $ shellflow config init  # Create default config file
```

### 4.4 Logic Flow

**Main Execution Flow:**

```
1. CLI receives command with script path
   |
   v
2. Load configuration (optional config file)
   |
   v
3. Parser reads .sh file and tokenizes into blocks
   - Each # @LOCAL starts a local block
   - Each # @REMOTE <host> starts a remote block
   - Lines without markers extend current block
   |
   v
4. Runner initializes executors (local, SSH per host)
   |
   v
5. For each block in sequence:
   |
   +---> Select appropriate executor
   |
   +---> Execute block with context from previous blocks
   |
   +---> Capture output, update context
   |
   +---> If failed and fail_fast: STOP, report error
   |
   +---> If failed and not fail_fast: log error, continue
   |
   v
6. Report final status (success/failure, summary)
```

**Parser Logic:**

```
Input: .sh file content
Output: List of Block objects

Algorithm:
1. Split content into lines
2. Initialize empty block list, current_block = None
3. For each line:
   a. If line matches `# @LOCAL`:
      - If current_block exists, append to list
      - Create new LocalBlock
   b. If line matches `# @REMOTE <host>`:
      - If current_block exists, append to list
      - Extract host from comment
      - Create new RemoteBlock with host
   c. Else:
      - If current_block exists, append line to its content
      - Else: treat as prelude (before first marker) - may warn or include in first block
4. If current_block exists, append to list
5. Validate blocks (no empty blocks, hosts exist in config)
6. Return block list
```

**Execution Logic (Local):**

```python
def execute_local(block: Block, context: ExecutionContext) -> ExecutionResult:
    """Execute a block locally via subprocess."""
    # Prepare environment with context variables
    env = os.environ.copy()
    env.update(context.variables)

    # Execute via subprocess
    start = time.monotonic()
    result = subprocess.run(
        block.content,
        shell=True,  # Required for bash syntax
        capture_output=True,
        text=True,
        timeout=DEFAULT_TIMEOUT,
        env=env,
    )
    duration_ms = int((time.monotonic() - start) * 1000)

    return ExecutionResult(
        success=result.returncode == 0,
        exit_code=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
        duration_ms=duration_ms,
    )
```

**Execution Logic (Remote via SSH CLI):**

```python
def execute_remote(
    block: Block, context: ExecutionContext, ssh_config: SSHConfig
) -> ExecutionResult:
    """Execute a block on a remote host via system SSH."""
    # Build SSH command
    cmd = ["ssh"]

    # Add SSH options
    if ssh_config.port:
        cmd.extend(["-p", str(ssh_config.port)])
    if ssh_config.user:
        cmd.extend(["-l", ssh_config.user])
    if ssh_config.identity_file:
        cmd.extend(["-i", ssh_config.identity_file])

    # Add host
    cmd.append(ssh_config.host)

    # Prepare remote script with environment variables
    script_lines = ["#!/bin/bash", "set -e"]
    for key, value in context.variables.items():
        script_lines.append(f'export {key}={shlex.quote(value)}')
    script_lines.append(block.content)
    script = "\n".join(script_lines)

    # Execute via subprocess
    start = time.monotonic()
    result = subprocess.run(
        cmd,
        input=script,
        capture_output=True,
        text=True,
        timeout=DEFAULT_TIMEOUT,
    )
    duration_ms = int((time.monotonic() - start) * 1000)

    return ExecutionResult(
        success=result.returncode == 0,
        exit_code=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
        duration_ms=duration_ms,
    )
```

**SSH Configuration:**

```python
def read_ssh_config(host: str) -> SSHConfig | None:
    """Read SSH configuration for a host from ~/.ssh/config.

    Uses paramiko.SSHConfig or simple configparser to parse
    the standard SSH config file format.
    """
    ssh_config_path = Path.home() / ".ssh" / "config"
    if not ssh_config_path.exists():
        return None

    # Use paramiko.SSHConfig if available
    try:
        import paramiko
        config = paramiko.SSHConfig()
        config.parse(ssh_config_path.read_text())
        host_config = config.lookup(host)
        return SSHConfig(
            host=host,
            hostname=host_config.get("hostname"),
            port=int(host_config.get("port", 22)),
            user=host_config.get("user"),
            identity_file=host_config.get("identityfile", [None])[0] if isinstance(host_config.get("identityfile"), list) else host_config.get("identityfile"),
        )
    except ImportError:
        # Fallback: basic config without paramiko
        return SSHConfig(host=host, hostname=host, port=22)
```

**Important Design Decision: System SSH CLI vs Python SSH Libraries:**

Shellflow **uses the system's SSH client directly** (via `ssh` command) rather than Python libraries like `paramiko` or `asyncssh`. This decision provides:

1. **Full SSH config compatibility**: Automatically respects `~/.ssh/config`, `IdentityFile`, `ProxyJump`, etc.
2. **Key agent support**: Seamless integration with `ssh-agent` and hardware security keys
3. **Standard authentication**: Uses OpenSSH's mature authentication stack
4. **Connection multiplexing**: Leverages OpenSSH's `ControlMaster`/`ControlPath` for efficient connection reuse

**Concurrency Model with System SSH:**

While system SSH is synchronous, Shellflow achieves concurrent execution at the **process level** using `asyncio.subprocess`:

```python
# Multiple SSH processes run concurrently via asyncio
tasks = [
    asyncio.create_task(run_ssh_process(host, script))
    for host in group_hosts
]
# Fan-In: Wait for all with TaskGroup
results = await asyncio.gather(*tasks, return_exceptions=True)
```

This approach:
- Spawns separate `ssh` processes for each concurrent operation
- Uses `asyncio` to manage multiple subprocesses without blocking
- Naturally handles I/O streaming from multiple hosts in parallel
- Simplifies signal handling and process lifecycle management

**SSH Connection Multiplexing (ControlMaster):**

With system SSH, connection multiplexing is handled natively by OpenSSH's `ControlMaster` feature:

```
1. SSH Executor initialization:
   a. Create temp directory for ControlPath sockets
   b. Set SSH_OPTIONS: ControlMaster=auto, ControlPath=/tmp/shellflow-xxx/%h-%p-%r
   c. Set ControlPersist=300 (keep master alive 5 min after last client)

2. First connection to host (e.g., web01):
   a. ssh -o ControlMaster=yes -o ControlPath=/tmp/shellflow-xxx/web01-22-deploy web01 ...
   b. OpenSSH creates master connection + socket file
   c. Execute command, keep master running in background

3. Subsequent concurrent connections to same host:
   a. Multiple concurrent: ssh -o ControlMaster=auto -o ControlPath=... web01 ...
   b. All connect to existing master via socket
   c. No new auth, minimal latency, share single TCP connection

4. Cleanup:
   a. On Shellflow exit: SSH master persists briefly (ControlPersist)
   b. Socket files cleaned up automatically by OS on process exit
   c. Optional: explicit -O exit to close master if needed
```

**Key Benefits:**
- **Zero code complexity**: OpenSSH handles all multiplexing logic
- **Transparent**: Works with any SSH config in ~/.ssh/config
- **Efficient**: Single TCP connection per host regardless of concurrency
- **Automatic**: No connection management code needed

**Concurrent Group Execution (Fan-Out/Fan-In):**

```
1. Parse # @REMOTE @groupname marker
2. Resolve group to list of hosts via ConfigManager
3. Create RemoteGroupBlock with group reference
4. In AsyncRunner:
   a. Create asyncio.Task for each host
   b. Use asyncio.TaskGroup for structured concurrency
   c. Display progress via Rich Live
5. Execute all tasks concurrently:
   a. Each task uses SSHExecutor with connection pooling
   b. stdout/stderr captured per host
   c. Exit code captured per host
6. Fan-In (TaskGroup completion):
   a. All tasks succeed: aggregate into GroupResult
   b. Any task fails with fail_fast:
      - TaskGroup automatically cancels other tasks
      - Partial results captured
7. Return GroupResult with per-host ExecutionResults
8. Pass aggregated results to next block via context
```

### 4.5 Configuration

Shellflow supports two levels of configuration:

1. **User-level** (`~/.config/shellflow/config.toml`): Global defaults and shared host definitions
2. **Project-level** (`./shellflow.toml`): Project-specific hosts, groups, and execution settings

**Configuration File (`~/.config/shellflow/config.toml`):**

```toml
[runner]
fail_fast = true
verbose = false
capture_output = true
timeout = 300  # seconds

[ssh.defaults]
port = 22
user = "deploy"
timeout = 30
use_agent = true

[ssh.hosts.production-web]
host = "web1.example.com"
user = "ubuntu"
key_file = "~/.ssh/production.pem"
port = 2222

[ssh.hosts.production-db]
host = "db1.internal"
user = "postgres"
use_agent = true

[logging]
level = "info"  # debug, info, warn, error
format = "json"  # json, text
```

**Project-Level Configuration (`./shellflow.toml`):**

```toml
[project]
name = "my-web-deploy"
fail_fast = true
verbose = false

# Define individual hosts (inherits from and overrides ~/.ssh/config)
[hosts.web01]
host = "192.168.1.10"
user = "deploy"

[hosts.web02]
host = "192.168.1.11"
user = "deploy"

[hosts.web03]
host = "192.168.1.12"
user = "deploy"
port = 2222

# Define host groups for concurrent execution
[groups.web_cluster]
members = ["web01", "web02", "web03"]
# fail_threshold = 2  # Optional: require at least 2 successes

[groups.all]
members = ["web01", "web02", "web03"]
```

**Script with Concurrent Group Execution:**

```bash
# @LOCAL
echo "Starting deployment..."
tar -czf app.tar.gz ./dist
echo "::set-var name=PACKAGE::app.tar.gz"

# @REMOTE @web_cluster
# This block executes CONCURRENTLY on web01, web02, and web03
echo "Deploying to $(hostname)"
tar -xzf $PACKAGE -C /var/www/html/
systemctl restart nginx

# @LOCAL
echo "Deployment complete on all hosts!"
```

**Environment Variables:**
- `SHELLFLOW_CONFIG`: Path to config file (default: `~/.config/shellflow/config.toml`)
- `SHELLFLOW_SSH_KEY`: Default SSH key path
- `SHELLFLOW_LOG_LEVEL`: Override log level

### 4.6 Error Handling

**Exception Hierarchy:**

```python
class ShellflowError(Exception):
    """Base exception for all shellflow errors."""
    pass

class ConfigError(ShellflowError):
    """Configuration loading or validation error."""
    pass

class ParseError(ShellflowError):
    """Script parsing error with line number context."""
    def __init__(self, message: str, line: int, content: str):
        super().__init__(message)
        self.line = line
        self.content = content

class ExecutionError(ShellflowError):
    """Block execution failure."""
    def __init__(
        self,
        message: str,
        block_index: int,
        exit_code: int,
        stdout: str,
        stderr: str,
    ):
        super().__init__(message)
        self.block_index = block_index
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr

class SSHError(ExecutionError):
    """SSH-specific execution error."""
    def __init__(self, message: str, host: str, original_error: Exception | None = None):
        super().__init__(message, -1, -1, "", str(original_error) if original_error else "")
        self.host = host
        self.original_error = original_error
```

**Error Reporting Format:**

```
ERROR: Execution failed at block 3 (remote:production-web)

Command:
  systemctl restart nginx

Exit Code: 1

STDERR:
  Failed to restart nginx.service: Unit nginx.service not found.

Context:
  Script: deploy.sh
  Block: 3 of 7
  Host: production-web (web1.example.com)
  Duration: 0.45s

Previous Blocks:
  [✓] Block 1 (local): echo "Starting deployment"
  [✓] Block 2 (remote:production-web): cd /opt/app
  [✗] Block 3 (remote:production-web): systemctl restart nginx  <-- FAILED
  [ ] Block 4 (local): echo "Deployment complete"
  ...
```

### 4.7 Maintainability Notes

- **Focused Helpers:** Split large functions into focused helpers with descriptive names
- **Consistent Patterns:** Use the same error handling pattern throughout (custom exceptions)
- **Type Safety:** All public functions fully typed; use `ty check` validation
- **Documentation:** Docstrings for all public APIs following Google style
- **Logging:** Structured logging throughout for debugging execution flow

---

## 5. Verification & Testing Strategy

### 5.1 Unit Testing

Unit tests focus on individual components with mocked dependencies:

| Component | Test File | Coverage |
| :--- | :--- | :--- |
| Parser | `tests/test_parser.py` | Tokenization, block creation, error handling |
| Runner | `tests/test_runner.py` | Orchestration, context passing, error handling |
| Local Executor | `tests/executors/test_local.py` | Subprocess execution, output capture |
| SSH Executor | `tests/executors/test_ssh.py` | Connection management, remote execution |
| Config | `tests/test_config.py` | Loading, validation, defaults |
| Blocks | `tests/blocks/test_blocks.py` | Block behavior, context handling |

### 5.2 Property Testing

| Target Behavior | Why Property Testing Helps | Tool / Command | Planned Invariants |
| :--- | :--- | :--- | :--- |
| Script parser | Large combinatorial input space (various comment patterns, edge cases) | `uv run pytest tests/test_parser_properties.py -q` | Round-trip: parse → serialize → parse produces equivalent blocks; Idempotence: parsing same input twice yields same result |
| Configuration validation | Various config structures and defaults | `uv run pytest tests/test_config_properties.py -q` | Validation: invalid configs always raise ConfigError; Defaults: missing values filled with defaults |

### 5.3 Integration Testing

Integration tests verify component interactions:

| Scenario | Test File | Description |
| :--- | :--- | :--- |
| Parser + Runner | `tests/integration/test_parse_run.py` | Parse script and execute with local executor |
| Runner + SSH Executor | `tests/integration/test_ssh_run.py` | Execute remote blocks against test SSH server (mock or containerized) |
| CLI end-to-end | `tests/integration/test_cli.py` | Full CLI invocation with various arguments |

Mock Strategy:
- SSH connections mocked using `paramiko` mocks or test containers
- Filesystem operations use temporary directories
- Subprocess calls mocked to capture commands without execution

### 5.4 BDD Acceptance Testing

| Scenario ID | Feature File | Command | Success Criteria |
| :--- | :--- | :--- | :--- |
| BDD-01 | `features/runner.feature` | `uv run behave features/runner.feature` | Scenario "Execute local-only script" passes |
| BDD-02 | `features/runner.feature` | `uv run behave features/runner.feature` | Scenario "Execute remote-only script" passes |
| BDD-03 | `features/runner.feature` | `uv run behave features/runner.feature` | Scenario "Execute mixed local and remote script" passes |
| BDD-04 | `features/runner.feature` | `uv run behave features/runner.feature` | Scenario "Fail fast on local block failure" passes |
| BDD-05 | `features/runner.feature` | `uv run behave features/runner.feature` | Scenario "Fail fast on remote block failure" passes |
| BDD-06 | `features/runner.feature` | `uv run behave features/runner.feature` | Scenario "Capture output and pass to next block" passes |
| BDD-07 | `features/parser.feature` | `uv run behave features/parser.feature` | Scenario "Parse local marker" passes |
| BDD-08 | `features/parser.feature` | `uv run behave features/parser.feature` | Scenario "Parse remote marker with host" passes |
| BDD-09 | `features/config.feature` | `uv run behave features/config.feature` | Scenario "Load SSH configuration" passes |

### 5.5 Robustness & Performance Testing

| Test Type | When It Is Required | Tool / Command | Planned Coverage or Reason Not Needed |
| :--- | :--- | :--- | :--- |
| Fuzz | Parser/protocol/unsafe/untrusted-input paths only | `Atheris` | N/A - no parser for hostile binary input; script parser operates on text files from trusted sources |
| Benchmark | Explicit latency/throughput/hot-path requirements only | `pytest-benchmark` | SSH connection pooling benchmark for remote-heavy workloads; script parsing benchmark for large files |

### 5.6 Critical Path Verification (The "Harness")

| Verification Step | Command | Success Criteria |
| :--- | :--- | :--- |
| VP-01 | `uv run shellflow --version` | Output contains version number |
| VP-02 | `uv run shellflow run tests/fixtures/local_only.sh` | Script executes successfully, exit code 0 |
| VP-03 | `uv run pytest tests/ -v --tb=short` | All unit tests pass, 0 failures |
| VP-04 | `uv run behave features/` | All BDD scenarios pass |
| VP-05 | `uv run ruff check src/` | No lint errors |
| VP-06 | `uv run ty check src/` | No type errors |

### 5.7 Validation Rules

| Test Case ID | Action | Expected Outcome | Verification Method |
| :--- | :--- | :--- | :--- |
| TC-01 | Parse script with `# @LOCAL` marker | LocalBlock created with correct content | Unit test + BDD |
| TC-02 | Parse script with `# @REMOTE host` marker | RemoteBlock created with correct host | Unit test + BDD |
| TC-03 | Execute LocalBlock with `echo hello` | stdout contains "hello", exit code 0 | Unit test + BDD |
| TC-04 | Execute RemoteBlock with failing command | ExecutionError raised with exit code != 0 | Unit test + BDD |
| TC-05 | Run script with fail_fast=true and error | Execution stops at first error | BDD scenario |
| TC-06 | Run script with variable capture | Output from block 1 available in block 2 | Unit test + BDD |

---

## 6. Implementation Plan

- [ ] **Phase 1: Foundation** — Project rename, scaffolding, core types, BDD harness
- [ ] **Phase 2: Core Logic** — Parser, blocks (Local, Remote, RemoteGroup), local executor
- [ ] **Phase 2.5: Async & Concurrency** — AsyncRunner foundation, SSH connection pooling
- [ ] **Phase 3: SSH & Runner** — SSH executor, runner orchestration, group execution
- [ ] **Phase 4: Integration** — CLI, config (project-level), end-to-end flow
- [ ] **Phase 5: Polish** — Tests, docs, error messages, Rich UI for concurrent execution

**Note:** Phase 2.5 is a new addition supporting the multi-machine concurrent execution (Fan-Out/Fan-In) architecture.

---

## 7. Cross-Functional Concerns

### Security
- No hardcoded credentials; SSH keys and agent-only authentication
- Config files should have restrictive permissions (0o600) checked at load
- **Variable Injection via Environment Variables**: Context variables are passed to blocks via environment variables using `subprocess.run(env=...)` for local and dynamically generated `export VAR=value` (with `shlex.quote()`) for remote. This prevents shell injection attacks that could occur with string templating.
- SSH host key verification enabled by default (no StrictHostKeyChecking=no)
- Note: Since bash scripts with pipes/redirections must be executed as strings via shell interpreter, the security boundary is at the variable injection layer, not the command structure itself

### Backward Compatibility
- Initial release - no backward compatibility concerns
- Future versions: maintain comment marker compatibility

### Documentation
- README with quickstart guide
- Example scripts in `examples/` directory
- Full CLI help text
- Configuration reference

### Monitoring/Logging
- Structured logging (JSON) for machine parsing
- Human-readable text format option
- Execution timing per block
- Connection metrics for SSH

### Rollback Strategy
- Fail-fast by default ensures partial deployments don't continue
- No automatic rollback (user handles via script logic)
- Dry-run mode available for testing
