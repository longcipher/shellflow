# Shellflow Scotty Feature Absorption Design

## Overview

This design specification outlines the absorption of 8 key features from Scotty into Shellflow, enabling richer orchestration capabilities while maintaining full backward compatibility. The implementation follows Shellflow's existing patterns and extends the system incrementally.

## Core Principles

- **Zero Breaking Changes**: All existing Shellflow scripts continue to work unchanged
- **Opt-in Adoption**: New features are additive and don't affect existing workflows  
- **Incremental Implementation**: Features can be adopted gradually by users
- **Hybrid Syntax Support**: Both original and Scotty-style syntax are supported

## Feature Specifications

### 1. Server Definitions (`@servers`)

**Current State**: Shellflow uses raw hostnames in `@REMOTE host` directives.

**Proposed Enhancement**:

```bash
# @servers web=web1.example.com,web2.example.com db=db.example.com
# @REMOTE web
echo "Deploy to web servers"
```

**Implementation**:

- Add `ServerRegistry` class to manage named server aliases
- Extend parser to recognize `@servers` directive
- Allow both `@REMOTE server_alias` and `@REMOTE hostname` syntax
- Support comma-separated host lists for load balancing

**Migration Path**: Existing scripts continue working; new scripts can adopt aliases.

### 2. Task Annotations (`@task`)

**Current State**: Commands are grouped in anonymous blocks.

**Proposed Enhancement**:

```bash
# @task deploy on:web
git pull origin main
npm run build
systemctl restart app

# @task migrate on:db  
php artisan migrate
```

**Implementation**:

- Add `TaskRegistry` class for named task storage
- Extend parser to recognize `@task name on:servers` syntax
- Tasks become callable units that can be referenced by macros
- Support task inheritance and composition

**Migration Path**: Anonymous blocks remain default; tasks are opt-in.

### 3. Macro Groups (`@macro`)

**Current State**: Scripts execute linearly from top to bottom.

**Proposed Enhancement**:

```bash
# @macro full-deploy deploy migrate cleanup
# @macro quick-deploy deploy

# Execute: shellflow run script.sh full-deploy
```

**Implementation**:

- Add `MacroRegistry` class for workflow composition
- CLI accepts macro names as targets: `shellflow run script.sh macro_name`
- Macros resolve to ordered task execution sequences
- Support nested macro definitions

**Migration Path**: Default behavior unchanged; macros provide new execution modes.

### 4. Variable System

**Current State**: Variables set via environment or `@EXPORT`.

**Proposed Enhancement**:

```bash
# Variables at script top-level
BRANCH="main" 
ENVIRONMENT="production"

# @task deploy on:web
git checkout $BRANCH
# Variables automatically available in tasks
```

**Implementation**:

- Extend preamble evaluation to capture top-level variable assignments
- Variables become available in all task execution contexts
- Support both static values and dynamic expressions
- Integration with existing `@EXPORT` mechanisms

**Migration Path**: No changes required; variables work as before.

### 5. Helper Functions

**Current State**: Functions can be defined but aren't reusable across tasks.

**Proposed Enhancement**:

```bash
notify_slack() {
  curl -X POST -H 'Content-type: application/json' \
    --data '{"text":"Deployment complete"}' $SLACK_WEBHOOK
}

# @task deploy on:web
deploy_app
notify_slack
```

**Implementation**:

- Functions defined at script level become available in all tasks
- Function registry tracks available helpers
- Support for function libraries and imports

**Migration Path**: Existing function definitions continue working.

### 6. Hook System (`@before`, `@after`, `@error`)

**Current State**: No lifecycle hooks.

**Proposed Enhancement**:

```bash
# @before
setup_environment() {
  echo "Preparing deployment environment..."
}

# @after  
cleanup_temp_files() {
  rm -rf /tmp/deploy_cache
}

# @error
rollback_on_failure() {
  echo "Deployment failed, rolling back..."
}
```

**Implementation**:

- Add `HookRegistry` class for lifecycle event management
- Hooks execute at appropriate points in run lifecycle
- Support `@before`, `@after`, `@error`, `@success`, `@finished` events
- Hooks run locally by default (can be extended to remote)

**Migration Path**: Purely additive feature with no impact on existing scripts.

### 7. Doctor Command (`shellflow doctor`)

**Current State**: No configuration validation.

**Proposed Enhancement**:

```bash
$ shellflow doctor script.sh
✓ SSH connectivity to all defined servers
✓ Required tools available on remote hosts  
✓ Script syntax validation
✓ Variable definitions complete
```

**Implementation**:

- New `doctor` subcommand in CLI
- Validates SSH connections to all referenced hosts
- Checks tool availability on remote systems
- Performs syntax validation and dependency analysis
- Provides actionable remediation suggestions

**Migration Path**: New command with no impact on existing functionality.

### 8. Advanced Execution Modes

**Current State**: Basic run with verbose output.

**Proposed Enhancement**:

```bash
# Dry run mode
shellflow run script.sh --pretend

# Continue on errors  
shellflow run script.sh --continue-on-error

# Summary output only
shellflow run script.sh --summary
```

**Implementation**:

- `--pretend`: Show commands that would execute without running them
- `--continue-on-error`: Don't stop execution on first failure
- `--summary`: Condensed output showing only key results
- Integration with existing verbose mode

**Migration Path**: New options are opt-in; default behavior unchanged.

## Architecture Changes

### New Registry Classes

```python
class ServerRegistry:
    """Manages named server aliases and host resolution."""

class TaskRegistry:  
    """Stores named tasks with their server assignments."""

class MacroRegistry:
    """Manages macro definitions and task composition."""

class HookRegistry:
    """Handles lifecycle hook registration and execution."""
```

### Parser Extensions

- Extend `parse_script()` to recognize new directive types
- Maintain backward compatibility with existing block parsing
- Add validation for new syntax elements

### Execution Engine Updates

- Task-based execution alongside existing block-based execution
- Hook integration points in execution lifecycle
- Enhanced error handling and recovery modes

## Testing Strategy

### Unit Tests

- Registry classes: CRUD operations, validation logic
- Parser extensions: New directive recognition and parsing
- CLI commands: Option parsing and execution paths

### Integration Tests  

- End-to-end script execution with new features
- SSH connectivity and remote execution validation
- Hook execution and error handling scenarios

### BDD Scenarios (behave)

```gherkin
Given a script with server definitions
When I run shellflow doctor
Then all servers should be validated

Given a script with tasks and macros  
When I execute a macro by name
Then tasks should run in the defined order
```

### Backward Compatibility Tests

- All existing test suites must continue passing
- Regression testing for edge cases
- Performance benchmarking to ensure no degradation

## Implementation Phases

### Phase 1: Core Infrastructure (High Priority)

1. Server and Task registries
2. Parser extensions for basic directives
3. Doctor command skeleton

### Phase 2: Execution Features (Medium Priority)  

1. Task execution engine
2. Macro resolution and execution
3. Hook system integration

### Phase 3: Advanced Features (Lower Priority)

1. Complete doctor command with SSH validation
2. Advanced execution modes (--pretend, --continue-on-error)
3. Performance optimizations and refinements

## Migration Guide

### For Existing Users

- No changes required; existing scripts work unchanged
- New features are opt-in through new syntax
- Can gradually adopt features in existing scripts

### For New Users

- Start with familiar block syntax
- Adopt server aliases and tasks as complexity grows
- Use macros for reusable deployment workflows
- Leverage hooks for robust automation

## Success Criteria

- All existing Shellflow scripts execute identically
- All 8 Scotty features implemented with full functionality
- Comprehensive test coverage including backward compatibility
- Documentation updated with new feature examples
- Performance meets or exceeds current benchmarks
