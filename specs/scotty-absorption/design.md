# Scotty Feature Absorption Design Specification

## Overview

This specification outlines the absorption of 8 key features from Scotty (a popular SSH task runner) into Shellflow, enhancing its capabilities while maintaining backward compatibility and Shellflow's design philosophy.

## Analysis Summary

Scotty is a Laravel Envoy-inspired SSH task runner that uses plain bash scripts with annotation comments. Key features to absorb:

1. **Server Definitions** - Named server configurations with shorthand aliases
2. **Task Annotations** - `@task` markers for reusable, named command blocks
3. **Macro Groups** - `@macro` for composing multiple tasks into workflows
4. **Variable System** - Runtime variable passing and environment management
5. **Helper Functions** - Reusable bash functions across tasks
6. **Hook System** - Pre/post execution hooks for setup and cleanup
7. **Doctor Command** - Configuration and connectivity validation
8. **Advanced Execution Modes** - Pretend, summary, continue-on-error modes

## Feature Specifications

### Feature 1: Server Definitions

#### Current State

Shellflow uses raw SSH hostnames in `@REMOTE <host>` markers, requiring full host resolution through SSH config.

#### Proposed Enhancement

Add `@servers` directive for defining named server aliases within scripts.

```bash
#!/bin/bash
# @servers production=deployer@prod.example.com staging=test@staging.example.com
# @servers db=db-admin@db.internal.com

# @REMOTE production
# Deploy to production server

# @REMOTE staging
# Deploy to staging server
```

#### Implementation Approach

- Extend parser to recognize `# @servers` comments
- Create `ServerRegistry` class for managing server aliases
- Maintain backward compatibility with raw hostnames
- Resolve aliases before SSH execution

#### Breaking Changes

None - existing `@REMOTE hostname` syntax continues to work.

#### Migration Path

- No migration needed for existing scripts
- Users can gradually adopt `@servers` for better readability

---

### Feature 2: Task Annotations

#### Current State

Shellflow uses anonymous blocks separated by `@LOCAL` and `@REMOTE` markers.

#### Proposed Enhancement

Add `@task` annotations for named, reusable task definitions.

```bash
#!/bin/bash
# @servers production=deployer@prod.example.com

# @task deploy-app on:production
deploy_app() {
    cd /var/www/my-app
    git pull origin main
    composer install
    php artisan migrate
}

# @task restart-services on:production
restart_services() {
    sudo systemctl restart nginx
    sudo systemctl restart php-fpm
}

# @REMOTE production
# Run deployment tasks
deploy_app
restart_services
```

#### Implementation Approach

- Add `@task <name> on:<server>` syntax
- Create `TaskRegistry` for storing named tasks
- Allow tasks to be called as functions within execution blocks
- Support task composition and reuse

#### Breaking Changes

None - tasks are opt-in enhancement.

#### Migration Path

- Convert existing blocks to named tasks incrementally
- Tasks can reference existing execution blocks

---

### Feature 3: Macro Groups

#### Current State

Shellflow executes blocks sequentially without named composition.

#### Proposed Enhancement

Add `@macro` directives for grouping tasks into reusable workflows.

```bash
#!/bin/bash
# @servers production=deployer@prod.example.com

# @macro full-deploy
#   pull-code
#   install-deps
#   migrate-db
#   restart-services
# @endmacro

# @task pull-code on:production
pull_code() {
    cd /var/www/my-app
    git pull origin main
}

# @task install-deps on:production
install_deps() {
    composer install --no-dev
    npm run build
}

# @task migrate-db on:production
migrate_db() {
    php artisan migrate --force
}

# @task restart-services on:production
restart_services() {
    sudo systemctl restart nginx php-fpm
}

# @REMOTE production
# Run full deployment
full-deploy
```

#### Implementation Approach

- Parse `@macro` ... `@endmacro` blocks
- Create `MacroRegistry` for storing macro definitions
- Expand macros into task sequences during execution
- Support nested macro calls

#### Breaking Changes

None - macros are additive feature.

#### Migration Path

- Extract common deployment patterns into macros
- Maintain existing sequential block execution

---

### Feature 4: Variable System

#### Current State

Shellflow supports basic export propagation with `@EXPORT` directives.

#### Proposed Enhancement

Add Scotty-style variable definitions and command-line variable injection.

```bash
#!/bin/bash
# @servers production=deployer@prod.example.com
# @vars BRANCH=main REPO=my-app

# @task deploy on:production
deploy() {
    cd /var/www/$REPO
    git checkout $BRANCH
    git pull origin $BRANCH
}

# Usage: shellflow run deploy.sh --var BRANCH=feature-x --var REPO=new-app
```

#### Implementation Approach

- Add `# @vars` directive for default variables
- Support `--var KEY=VALUE` CLI arguments
- Integrate with existing export system
- Allow variable interpolation in task bodies

#### Breaking Changes

None - extends existing export functionality.

#### Migration Path

- Convert hardcoded values to variables
- Use CLI variables for environment-specific deployments

---

### Feature 5: Helper Functions

#### Current State

Shellflow has no concept of reusable functions across blocks.

#### Proposed Enhancement

Allow function definitions that can be called from any task or block.

```bash
#!/bin/bash
# @servers production=deployer@prod.example.com

# Helper function available to all tasks
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

notify_slack() {
    curl -X POST -H 'Content-type: application/json' \
         --data "{\"text\":\"$1\"}" $SLACK_WEBHOOK
}

# @task deploy on:production
deploy() {
    log "Starting deployment"
    # deployment logic
    notify_slack "Deployment completed successfully"
}
```

#### Implementation Approach

- Parse function definitions before task/macro parsing
- Make helper functions available in execution environment
- Support function calls from tasks and macros

#### Breaking Changes

None - functions are opt-in.

#### Migration Path

- Extract common utilities into helper functions
- Functions work alongside existing blocks

---

### Feature 6: Hook System

#### Current State

Shellflow has no pre/post execution hooks.

#### Proposed Enhancement

Add `@before` and `@after` hooks for setup and cleanup.

```bash
#!/bin/bash
# @servers production=deployer@prod.example.com

# @before deploy
prepare_deployment() {
    log "Preparing deployment environment"
    # backup current state
    # set maintenance mode
}

# @after deploy
cleanup_deployment() {
    log "Cleaning up after deployment"
    # clear caches
    # unset maintenance mode
}

# @task deploy on:production
deploy() {
    # main deployment logic
    git pull
    composer install
    php artisan migrate
}
```

#### Implementation Approach

- Add `@before <task>` and `@after <task>` syntax
- Execute hooks automatically around task execution
- Support multiple hooks per task (executed in definition order)

#### Breaking Changes

None - hooks are opt-in.

#### Migration Path

- Add hooks for existing deployment tasks
- Use hooks for logging, notifications, cleanup

---

### Feature 7: Doctor Command

#### Current State

Shellflow has basic validation but no comprehensive health checks.

#### Proposed Enhancement

Add `shellflow doctor` command for configuration and connectivity validation.

```bash
$ shellflow doctor deploy.sh
✓ SSH config valid for production server
✓ SSH connectivity to production server
✓ Required tools (git, composer) available on production server
✓ Script syntax valid
✓ All referenced servers defined
✓ All tasks referenced in macros exist

Doctor Summary:
- 6 checks passed
- 0 warnings
- 0 errors
```

#### Implementation Approach

- Create `DoctorCommand` class
- Implement connectivity checks, syntax validation, dependency verification
- Provide detailed error messages and suggestions

#### Breaking Changes

None - new command.

#### Migration Path

- Run doctor before deployments
- Use doctor output to debug configuration issues

---

### Feature 8: Advanced Execution Modes

#### Current State

Shellflow supports basic `--dry-run` and `--json` modes.

#### Proposed Enhancement

Add Scotty-style execution modes: pretend, summary, continue-on-error.

```bash
# Dry run (show what would execute)
shellflow run deploy.sh --pretend

# Continue execution even if tasks fail
shellflow run deploy.sh --continue-on-error

# Summary mode (reduced output)
shellflow run deploy.sh --summary

# List available tasks and macros
shellflow tasks deploy.sh
```

#### Implementation Approach

- Add `--pretend`, `--continue-on-error`, `--summary` flags
- Add `shellflow tasks` subcommand
- Modify execution logic to support non-stop mode

#### Breaking Changes

None - extends existing CLI options.

#### Migration Path

- Use pretend mode for validation
- Use continue-on-error for multi-stage deployments
- Use summary mode for CI/CD integration

## Architecture Changes

### Core Module Extensions

#### Parser Module

- Extend to recognize new directives: `@servers`, `@task`, `@macro`, `@vars`, `@before`, `@after`
- Add registries for servers, tasks, macros, hooks
- Maintain backward compatibility with existing syntax

#### Execution Module

- Add `TaskExecutor` for named task execution
- Add `MacroExecutor` for macro expansion and execution
- Add hook execution integration
- Support advanced execution modes

#### Registry Classes

```python
class ServerRegistry:
    def add_server(self, alias: str, host: str) -> None
    def resolve_host(self, alias_or_host: str) -> str

class TaskRegistry:
    def add_task(self, name: str, server: str, function_body: str) -> None
    def get_task(self, name: str) -> Task

class MacroRegistry:
    def add_macro(self, name: str, tasks: List[str]) -> None
    def expand_macro(self, name: str) -> List[str]
```

### CLI Extensions

#### New Commands

- `shellflow doctor <script>` - Validate configuration and connectivity
- `shellflow tasks <script>` - List available tasks and macros

#### New Options

- `--pretend` - Show execution plan without running
- `--continue-on-error` - Continue execution on task failures
- `--summary` - Reduced output mode
- `--var KEY=VALUE` - Inject runtime variables

## Testing Strategy

### Unit Tests

- Test each registry class independently
- Test parser extensions for new directives
- Test macro expansion logic
- Test hook execution order

### Integration Tests

- Test end-to-end task execution
- Test macro expansion and execution
- Test hook firing in correct order
- Test variable injection and propagation

### BDD Tests

Add scenarios to `features/` directory:

- `features/scotty_compatibility.feature` - Server definitions, tasks, macros
- `features/advanced_execution.feature` - Pretend mode, continue-on-error, summary
- `features/hooks_and_variables.feature` - Hook execution, variable system
- `features/doctor_command.feature` - Configuration validation

### Compatibility Tests

- Ensure existing Shellflow scripts continue to work unchanged
- Test mixed usage (old blocks + new tasks/macros)
- Validate that new features don't break existing functionality

## Migration Strategy

### Phase 1: Core Infrastructure

1. Implement parser extensions for new directives
2. Add registry classes
3. Implement task and macro execution
4. Add basic CLI options

### Phase 2: Advanced Features

1. Implement hook system
2. Add variable system
3. Implement doctor command
4. Add advanced execution modes

### Phase 3: Polish and Documentation

1. Update README with new features
2. Add comprehensive examples
3. Create migration guides
4. Add skill integration

### Backward Compatibility Guarantee

- All existing scripts continue to work without modification
- New features are opt-in
- No breaking changes to existing CLI interface
- Existing block-based execution remains default

## Implementation Priority

1. **High Priority**: Server definitions, tasks, macros (core Scotty features)
2. **Medium Priority**: Variables, helper functions, hooks
3. **Low Priority**: Doctor command, advanced execution modes

## Risk Assessment

### Technical Risks

- Parser complexity increase with new directives
- Execution state management with hooks and variables
- SSH connection pooling for task reuse

### Compatibility Risks

- Ensuring zero breaking changes
- Maintaining performance with additional registries
- CLI option conflicts

### Mitigation Strategies

- Comprehensive test coverage including backward compatibility
- Incremental implementation with feature flags
- Extensive manual testing with existing scripts</content>
<parameter name="filePath">design.md
