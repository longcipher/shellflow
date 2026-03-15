# Shellflow Design Refinement Summary

## Date: 2026-03-14

---

## Overview

This document summarizes the refinements made to the Shellflow design based on technical review feedback. The refinements address critical architecture decisions, security considerations, and implementation details.

---

## 1. SSH Implementation: System SSH CLI vs Python Libraries

### Decision: Use System SSH CLI (Direct `ssh` Command)

**Rationale:**

- **Full SSH config compatibility**: Automatically respects `~/.ssh/config`, `IdentityFile`, `ProxyJump`, etc.
- **Key agent support**: Seamless integration with `ssh-agent` and hardware security keys
- **Standard authentication**: Uses OpenSSH's mature authentication stack
- **Connection multiplexing**: Leverages OpenSSH's `ControlMaster`/`ControlPath` for efficient connection reuse

**Implementation Approach:**

- Use `asyncio.subprocess` to spawn `ssh` processes
- Concurrent execution at the process level
- Multiple subprocesses managed via asyncio for non-blocking I/O

---

## 2. ExecutionContext: Enhanced for Group Execution

### Updated Data Structure

```python
@dataclass(frozen=True, slots=True)
class ExecutionContext:
    """Context passed between block executions."""
    # Single-block context (local or single remote)
    variables: dict[str, str] = field(default_factory=dict)
    last_output: str = ""
    exit_code: int = 0
    # Group context (for concurrent multi-host execution)
    # Maps host -> {var_name -> value}
    group_variables: dict[str, dict[str, str]] = field(default_factory=dict)
    # Maps host -> output string
    group_outputs: dict[str, str] = field(default_factory=dict)
```

**Key Changes:**

- Added `group_variables`: Maps host -> {variable_name -> value} for per-host variable tracking
- Added `group_outputs`: Maps host -> output string for per-host output collection

---

## 3. Assumptions: Stateless Blocks

### New Assumption Added

**Stateless Blocks**: Each block executes in an isolated environment. Changes to working directory (`cd`), shell variables (`export`), or other shell state in one block do NOT persist to subsequent blocks. Variables must be explicitly passed via the context mechanism.

**Implications:**

- Blocks are isolated execution units
- No implicit state sharing between blocks
- Users must use context variables for data flow between blocks

---

## 4. Security: Variable Injection via Environment Variables

### Updated Security Approach

**Variable Injection Mechanism:**

- **Environment Variables**: Context variables are passed to blocks via environment variables
- **Local Execution**: Use `subprocess.run(env=...)` to set environment variables
- **Remote Execution**: Dynamically generate `export VAR="value"` commands prepended to the script
- **Escaping**: Use `shlex.quote()` for proper escaping of variable values

**Security Benefits:**

- Prevents shell injection attacks that could occur with string templating
- Variables are passed out-of-band from script content
- Proper escaping ensures special characters are handled safely

---

## 5. GroupResult: Enhanced Status Tracking

### Updated Data Structure

```python
@dataclass(frozen=True, slots=True)
class GroupResult:
    """Result of concurrent execution across multiple hosts (Fan-Out/Fan-In)."""
    success: bool
    results: dict[str, ExecutionResult]  # host -> Result
    failed_hosts: list[str]
    successful_hosts: list[str]
    duration_ms: int
    status: str  # "success", "partial", "failed" - for fail_fast=false scenarios
```

**Key Changes:**

- Added `successful_hosts`: Explicit tracking of which hosts succeeded
- Added `status`: Explicit status string for clarity (especially for partial success scenarios)

---

## 6. Parser: Marker Detection Rules

### Updated Parser Logic

**Marker Detection:**

- Markers **must be at the start of a line** (after optional whitespace)
- Regex pattern: `^\s*#\s*@(LOCAL|REMOTE).*`
- This prevents false positives from content like `echo "# @LOCAL"`

**Prelude Handling:**

- Lines before the first marker constitute the "prelude"
- Prelude typically includes shebang (`#!/bin/bash`) and global settings (`set -e`)
- These should be prepended to each block's script to ensure consistent execution environment

---

## 7. Tasks: Updated for System SSH

### Task 2.4: Implement SSH Executor (System SSH)

**Key Implementation Steps:**

1. Build SSH command with options (`-p`, `-l`, `-i`, `-o`)
2. Add ControlMaster options for connection multiplexing
3. Prepare remote script with environment variable exports (using `shlex.quote()`)
4. Execute via `asyncio.subprocess.create_subprocess_exec()`
5. Stream stdout/stderr and capture exit code
6. Handle SSH-specific errors (connection refused, auth failure, timeout)

**Testing Strategy:**

- Mock `asyncio.subprocess` to test command building
- Test environment variable injection with `shlex.quote`
- Test ControlMaster path generation
- Mock SSH failures to test error handling
- Integration tests against local SSH server (if available)

---

## Summary of Critical Decisions

1. **SSH Implementation**: Use system SSH CLI (`ssh` command) with `asyncio.subprocess` instead of Python libraries (paramiko/asyncssh). This provides full compatibility with OpenSSH configuration.

2. **Variable Injection**: Pass variables via environment variables (local: `subprocess.run(env=...)`, remote: `export VAR=value` with `shlex.quote()`). This prevents shell injection attacks.

3. **State Isolation**: Blocks are stateless - no persistence of working directory or shell variables between blocks. Users must use context variables.

4. **Connection Multiplexing**: Leverage OpenSSH's `ControlMaster`/`ControlPath` for efficient connection reuse. Managed at the OpenSSH level, not in application code.

5. **Async Concurrency**: Use `asyncio.subprocess` to manage multiple SSH processes concurrently without blocking the event loop.
