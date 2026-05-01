# Absorbing Scotty Features into Shellflow Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Integrate 8 advanced features from Scotty (server definitions, task annotations, macro groups, variable system, helper functions, hook system, doctor command, and advanced execution modes) into Shellflow while maintaining full backward compatibility with existing scripts.

**Architecture:** Extend Shellflow's parser to recognize new comment markers and configurations, enhance the execution context to support variables and hooks, add new CLI commands, and modify the runner to handle advanced execution modes without breaking existing # @LOCAL and # @REMOTE <host> syntax.

**Tech Stack:** Python 3.8+, paramiko for SSH, pytest for unit tests, behave for BDD tests, ruff for linting.

---

## File Structure

### Existing Files (Modified)

- `src/shellflow.py`: Main module - extend Block, ExecutionContext, ExecutionResult, RunResult, SSHConfig classes and CLI commands.
- `tests/`: Add new unit tests for each feature.
- `features/`: Add new BDD scenarios.
- `pyproject.toml`: Update dependencies if needed.

### New Files (Created)

- `src/config.py`: Handle server definitions and configurations.
- `src/variables.py`: Variable system implementation.
- `src/hooks.py`: Hook system implementation.
- `src/macros.py`: Macro groups implementation.
- `src/helpers.py`: Helper functions.
- `src/doctor.py`: Doctor command implementation.
- `src/advanced_modes.py`: Advanced execution modes.
- `tests/test_config.py`, `tests/test_variables.py`, etc.: Unit tests for new modules.
- `features/config.feature`, `features/variables.feature`, etc.: BDD tests.

---

### Task 1: Server Definitions

**Files:**

- Create: `src/config.py`
- Modify: `src/shellflow.py` (SSHConfig class and parser)
- Test: `tests/test_config.py`, `features/config.feature`
- [ ] **Step 1: Write the failing test for server definitions parsing**

```python
# tests/test_config.py
def test_parse_server_definition():
    script = """
# @SERVER web-server
#   host: example.com
#   user: deploy
#   port: 22
#   key: ~/.ssh/id_rsa
"""
    config = parse_server_config(script)
    assert config['web-server']['host'] == 'example.com'
    assert config['web-server']['user'] == 'deploy'
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_config.py::test_parse_server_definition -v`
Expected: FAIL with "parse_server_config not defined"

- [ ] **Step 3: Write minimal implementation in src/config.py**

```python
# src/config.py
def parse_server_config(script):
    # Minimal implementation
    return {}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_config.py::test_parse_server_definition -v`
Expected: PASS

- [ ] **Step 5: Extend implementation for full server parsing**

```python
# src/config.py
import re

def parse_server_config(script):
    servers = {}
    lines = script.split('\n')
    current_server = None
    for line in lines:
        if line.startswith('# @SERVER '):
            current_server = line.split('# @SERVER ')[1].strip()
            servers[current_server] = {}
        elif current_server and line.strip().startswith('#   '):
            key, value = line.strip()[4:].split(': ', 1)
            servers[current_server][key.strip()] = value.strip()
    return servers
```

- [ ] **Step 6: Run test and add to BDD**

Run: `pytest tests/test_config.py -v`
Add to `features/config.feature`:

```text
Feature: Server Definitions
  Scenario: Parse server config
    Given a script with server definitions
    When parsed
    Then servers are extracted correctly
```

- [ ] **Step 7: Integrate into main parser**

Modify `src/shellflow.py` to call `parse_server_config` and extend SSHConfig.

- [ ] **Step 8: Commit**

```bash
git add src/config.py tests/test_config.py features/config.feature
git commit -m "feat: add server definitions parsing"
```

### Task 2: Task Annotations

**Files:**

- Modify: `src/shellflow.py` (Block class)
- Test: `tests/test_annotations.py`, `features/annotations.feature`
- [ ] **Step 1: Write the failing test for task annotations**

```python
# tests/test_annotations.py
def test_parse_task_annotations():
    script = """
# @ANNOTATE task1
#   description: Deploy web app
#   timeout: 300
# @LOCAL
echo "deploying"
"""
    blocks = parse_blocks(script)
    assert blocks[0].annotations['description'] == 'Deploy web app'
    assert blocks[0].annotations['timeout'] == '300'
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_annotations.py::test_parse_task_annotations -v`
Expected: FAIL

- [ ] **Step 3: Extend Block class for annotations**

```python
# src/shellflow.py
@dataclasses.dataclass
class Block:
    type: str
    host: Optional[str] = None
    commands: List[str] = dataclasses.field(default_factory=list)
    annotations: Dict[str, str] = dataclasses.field(default_factory=dict)
```

- [ ] **Step 4: Update parser to capture annotations**

Modify parser in `src/shellflow.py` to parse # @ANNOTATE markers.

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/test_annotations.py -v`

- [ ] **Step 6: Add BDD test**

Similar to Task 1.

- [ ] **Step 7: Commit**

```bash
git add src/shellflow.py tests/test_annotations.py features/annotations.feature
git commit -m "feat: add task annotations"
```

### Task 3: Macro Groups

**Files:**

- Create: `src/macros.py`
- Modify: `src/shellflow.py`
- Test: `tests/test_macros.py`, `features/macros.feature`
- [ ] **Step 1: Write failing test for macro groups**

```python
def test_parse_macro_groups():
    script = """
# @MACRO deploy
#   echo "deploy step 1"
#   echo "deploy step 2"
# @ENDMACRO
"""
    macros = parse_macros(script)
    assert 'deploy' in macros
    assert len(macros['deploy']) == 2
```

- [ ] **Step 2: Implement minimal macro parsing**

In `src/macros.py`

- [ ] **Step 3: Integrate into parser**

- [ ] **Step 4: Run tests**

- [ ] **Step 5: Commit**

### Task 4: Variable System

**Files:**

- Create: `src/variables.py`
- Modify: `src/shellflow.py` (ExecutionContext)
- Test: `tests/test_variables.py`, `features/variables.feature`
- [ ] **Step 1: Failing test for variable substitution**

```python
def test_variable_substitution():
    script = """
# @VAR APP_NAME=myapp
# @LOCAL
echo $APP_NAME
"""
    result = run_script(script)
    assert 'myapp' in result.output
```

- [ ] **Step 2: Implement variable parsing and substitution**

- [ ] **Step 3: Run test**

- [ ] **Step 4: Commit**

### Task 5: Helper Functions

**Files:**

- Create: `src/helpers.py`
- Modify: `src/shellflow.py`
- Test: `tests/test_helpers.py`, `features/helpers.feature`
- [ ] **Step 1: Failing test for helper functions**

```python
def test_helper_functions():
    script = """
# @HELPER backup_db
#   mysqldump db > backup.sql
# @ENDHELPER
# @LOCAL
backup_db
"""
    result = run_script(script)
    assert result.success
```

- [ ] **Step 2: Implement helper parsing and execution**

- [ ] **Step 3: Run test**

- [ ] **Step 4: Commit**

### Task 6: Hook System

**Files:**

- Create: `src/hooks.py`
- Modify: `src/shellflow.py` (ExecutionContext)
- Test: `tests/test_hooks.py`, `features/hooks.feature`
- [ ] **Step 1: Failing test for hooks**

```python
def test_pre_execution_hook():
    script = """
# @HOOK PRE
#   echo "preparing"
# @LOCAL
echo "main task"
"""
    result = run_script(script)
    assert 'preparing' in result.output
```

- [ ] **Step 2: Implement hook system**

- [ ] **Step 3: Run test**

- [ ] **Step 4: Commit**

### Task 7: Doctor Command

**Files:**

- Create: `src/doctor.py`
- Modify: `src/shellflow.py` (CLI)
- Test: `tests/test_doctor.py`, `features/doctor.feature`
- [ ] **Step 1: Failing test for doctor command**

```python
def test_doctor_command():
    result = run_doctor()
    assert 'SSH connections' in result
    assert 'Configuration' in result
```

- [ ] **Step 2: Implement doctor diagnostics**

- [ ] **Step 3: Run test**

- [ ] **Step 4: Commit**

### Task 8: Advanced Execution Modes

**Files:**

- Create: `src/advanced_modes.py`
- Modify: `src/shellflow.py` (RunResult, runner)
- Test: `tests/test_modes.py`, `features/modes.feature`
- [ ] **Step 1: Failing test for parallel execution**

```python
def test_parallel_execution():
    script = """
# @PARALLEL
# @LOCAL
echo "task1"
# @LOCAL
echo "task2"
"""
    result = run_script(script, mode='parallel')
    assert result.success
    assert 'task1' in result.output
    assert 'task2' in result.output
```

- [ ] **Step 2: Implement advanced modes**

- [ ] **Step 3: Run test**

- [ ] **Step 4: Commit**

---

**Plan complete and saved to `docs/superpowers/plans/2026-04-30-absorbing-scotty-features.md`. Two execution options:**

**1. Subagent-Driven (recommended)** - I dispatch a fresh subagent per task, review between tasks, fast iteration

**2. Inline Execution** - Execute tasks in this session using executing-plans, batch execution with checkpoints

**Which approach?**
