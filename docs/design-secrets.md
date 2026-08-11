# Design: Secrets-aware Deployment (`age` integration, `@secrets`, `deploy` subcommand)

## 1. Motivation & Goals

Today `shellflow` is a deployment engine, but it has no first-class story for
**encrypted configuration**. Projects that need it end up with ad-hoc glue:

- an external `age`/`rage` CLI to generate identities and encrypt/decrypt files;
- a render script that decrypts secrets, base64-encodes them, and injects them
  as literal `# @env KEY=<value>` lines so they are masked by shellflow;
- a template renderer (`sed`) to substitute paths into `@copy` directives;
- hand-maintained systemd unit `ImportCredential=` lists that must stay in
  sync with the encrypted env files.

All of this knowledge lives in per-project scripts and READMEs instead of in
the tool. The result is a fragmented, hard-to-audit workflow where the
controller needs several external binaries and every project reinvents the
same pipeline.

### Goals

1. **Single controller tool.** After this change the controller needs only
   `shellflow` (plus the `ssh`/`rsync`/`bash` it already wraps). No `age`,
   `rage`, `base64`, or render scripts.
2. **Static playbooks.** Playbooks reference encrypted files directly
   (`# @secrets conf/prod.env.age`) instead of generated ones containing
   base64 literals.
3. **Uniform secret hygiene.** Secrets are masked in previews, traces, and
   audit logs; never appear in any argv; never touch disk on the controller or
   the targets.
4. **Standardized service deployment.** A `deploy` subcommand turns a
   conventional repository layout into a real, idempotent multi-host
   deployment — including per-key systemd credentials — with no custom script.
5. **Zero target-side crypto.** Targets only need `bash` and systemd ≥ 254.

### Non-goals

- **Not a replacement for systemd.** Credential storage on targets stays
  systemd-native (`systemd-creds`, `LoadCredentialEncrypted=` /
  `ImportCredential=`). `shellflow` decrypts on the controller and lets the
  target's systemd re-seal per host.
- **Not a Vault/KMS.** Single-operator asymmetric encryption of whole files,
  consistent with the existing shell-native, minimal-toolchain philosophy.
- **No new deployment language.** `@secrets` and `deploy` build on the
  existing directive DSL and `ExecutionPlan`; playbooks remain 100% valid
  Bash.

## 2. Design Overview

```text
controller (only shellflow + ssh/rsync/bash)              targets (bash + systemd >= 254)
┌───────────────────────────────────────────────┐        ┌──────────────────────────────────┐
│ keys generate / public          identity      │        │                                  │
│ secret encrypt / decrypt / edit               │        │                                  │
│ @secrets file.env.age  ──decrypt──> env vars │        │                                  │
│   (masked everywhere, never in argv)         │ ssh    │                                  │
│ deploy <svc> ──compose plan──> Copy+Remote ──┼───────>│ install binary/units/configs     │
│                                              │        │ per-key systemd-creds encrypt    │
│                                              │        │ daemon-reload + restart          │
└───────────────────────────────────────────────┘        └──────────────────────────────────┘
```

Key pieces:

1. **`crates/shellflow-secrets`** — a new library crate wrapping the Rust
   `age` crate (the reference Rust implementation that `rage` itself wraps).
   Handles identity loading, file encrypt/decrypt, recipient read-back, and
   `KEY=VALUE` env parsing. No I/O leaks into `shellflow-core`.
2. **CLI subcommands** — `keys`, `secret`, `deploy`; the bare positional form
   (`shellflow deploy.sh`) keeps working as `run`.
3. **`@secrets` directive** — decrypts an age file at execution time, injects
   the keys as environment variables into subsequent blocks, exports a
   `LT_SECRET_KEYS` list, and registers every value for masking.
4. **`deploy` subcommand** — composes a standard `ExecutionPlan` in memory
   from a conventional repository layout and reuses the existing executor,
   fan-out, dry-run/diff, and UI.

## 3. `age` Integration

`shellflow` embeds the Rust `age` crate. `rage` is itself a thin CLI over
this crate, so encrypted files are interoperable: files created by
`shellflow secret encrypt` decrypt with `rage`, and vice versa.

### 3.1 Identity resolution

Identity (private key) is resolved in this order:

1. `-i` / `--identity` flag (any subcommand that needs it);
2. `$SHELLFLOW_AGE_IDENTITY`;
3. `~/.config/age/keys.txt` (the age convention).

Identity files are the standard age format (X25519 private key). Existing
`rage`/`age` identities work unchanged.

### 3.2 Recipients

Recipients (public keys) are passed as repeatable `-r age1…` arguments or
read from a directory of `*.pub` files via `--recipients-dir` (one key per
file). This mirrors how projects conventionally store operator public keys.

> The age format is **anonymous**: the header stores the ephemeral share, not
> the recipients, so recipients cannot be recovered from an encrypted file.
> `secret edit` therefore **requires** `-r`/`--recipients-dir` and fails
> fast if none are given — re-encrypting without them would silently drop
> operators.

## 4. CLI Surface

```text
shellflow run [SCRIPT] [flags]        # current behavior; also the default
shellflow keys generate [-o PATH]     # write a new identity
shellflow keys public [-i PATH]       # print the public key
shellflow secret encrypt [-r age1…]... [-o OUT] FILE
shellflow secret decrypt [-i KEY] [FILE]
shellflow secret edit [-i KEY] FILE   # decrypt -> $EDITOR -> re-encrypt
shellflow secret creds FILE           # print ImportCredential=KEY lines
shellflow deploy <service> [flags]    # standardized multi-host deployment
```

`run` keeps accepting the positional script so `shellflow deploy.sh` remains
backward compatible; all existing flags (`-v/-n/-d/-t/-o/-s/-p/-c/-k`, etc.)
apply to `run` and to `deploy`.

## 5. `@secrets` Directive

### 5.1 Syntax & semantics

```bash
#!/usr/bin/env shellflow

# @server web-1 deploy@10.0.0.11
# @server web-2 deploy@10.0.0.12
# @group  web  web-1,web-2

# @secrets services/myapp/env/prod.env.age
# @remote web
set -eu
# LT_SECRET_KEYS is exported automatically; `${!key}` reads each value.
for key in $LT_SECRET_KEYS; do
  printf '%s' "${!key}" | sudo systemd-creds encrypt \
    --with-key=host --name="$key" - "/etc/credstore.encrypted/${key}"
done
```

> Credential filenames equal the key names (no `.cred` suffix):
> `systemd-creds` embeds the output filename into the ciphertext, and
> `ImportCredential=KEY` looks up the store by exact name — mismatches are
> refused. With `--local`, this block runs on the controller instead of over
> SSH, which is useful for debugging.

- `@secrets <file.age>` behaves like a batch of `@env KEY=VALUE` entries
  applied to all **subsequent** blocks, but the values are resolved at
  execution time from the encrypted file.
- The directive is a comment, so the playbook remains 100% valid Bash.
- Repeatable: multiple `@secrets` lines merge in order; later files win on
  key conflicts (matching shell `source` semantics).
- The decrypted keys are **also** exported as the space-separated list
  variable `LT_SECRET_KEYS`, so remote blocks can iterate them without
  knowing the key names ahead of time.

### 5.2 Execution-time resolution

The parser records only the file path (keeping `shellflow-core` pure and
I/O-free):

```rust
pub struct SecretEntry {
    pub file: String,
    pub identity: Option<String>,
}
// ExecutionPlan gains: pub secrets: Vec<SecretEntry>
```

The executor resolves all `SecretEntry` values once, before the first step:

1. load the identity (fail fast with a clear message if missing);
2. decrypt the file;
3. parse `KEY=VALUE` lines (blank lines and `#` comments ignored; the first
   `=` splits the key);
4. insert every key into run-state env (same layer as `@export`, so explicit
   `@env` still wins on conflicts);
5. register every value in the `Ui` mask set (see §5.3);
6. export `LT_SECRET_KEYS` into run-state env.

### 5.3 Masking

`Ui::mask_line` currently performs a global `str::replace` for every known
secret. Short values (e.g. `1`, `on`) would corrupt output, so `@secrets`
masking applies only to values of length ≥ a threshold. The threshold
defaults to `6` and is configurable via `$SHELLFLOW_MASK_MIN_LEN` (or
`--mask-min-len` on `run`/`deploy`). Explicit `@env KEY=value` literals keep
their current unconditional masking.

Masking covers host lines, payload previews, and `--log-file` output through
the existing `Ui` path; secrets never appear in any spawned argv.

### 5.4 Precedence & errors

- Precedence for a key present in several sources:
  `@env KEY=value` (step) > `@secrets`/`@export` (run state) > passthrough.
- Missing identity, undecryptable file, or malformed env content is a hard
  error before any step runs (never a silent skip).

## 6. `deploy` Subcommand

### 6.1 Conventional layout

`deploy <service>` works against a conventional repository layout (all paths
overridable by flags):

```text
deploy-repo/
├── hosts/
│   └── inventory.sh            # # @server / # @group lines (single source)
├── keys/
│   └── recipients/             # *.pub files for `secret encrypt`
└── services/
    └── <service>/
        ├── env/                # encrypted env files, merged in order
        │   ├── common.env.age  # shared keys (all services must agree)
        │   └── prod.env.age    # service-specific keys
        ├── units/              # *.service templates for the target
        └── configs/            # non-secret configuration shipped verbatim
```

Defaults: `hosts/inventory.sh`; env files `services/<svc>/env/*.env.age`
merged lexically; units from `services/<svc>/units/`; configs from
`services/<svc>/configs/`; binary `target/release/<service>`.

### 6.2 Composed plan

`deploy` builds an `ExecutionPlan` in memory (the step structs are already
public in `shellflow-core`), then runs it through the existing executor:

1. **ship** — `@copy` the binary, unit files, and configs to each host
   (`rsync` delta, or `scp` fallback; dry-run/diff supported).
2. **install** — one `@remote` block per group:
   - install binary, units (`/etc/systemd/system/`), configs;
   - install the **`cred-wrap`** helper once per host
     (`/usr/local/libexec/shellflow/cred-wrap`): a credential→env wrapper that
     exports every file in `$CREDENTIALS_DIRECTORY` and `exec`s the real
     binary — third-party/closed-source apps that only read env vars need
     **zero code changes** (the in-app loader is only for self-owned code);
   - create `/etc/credstore.encrypted` (0700 root);
   - for each key from the merged env: `printf '%s' "${!key}" | systemd-creds
     encrypt --with-key=host --name="$key" - /etc/credstore.encrypted/<KEY>`;
     credential filenames equal the key names so `ImportCredential=<KEY>`
     resolves in the store;
   - `daemon-reload` + `enable` + `restart` + `is-active` check.
3. **verify** — exit non-zero if any host failed or any unit is inactive.

`deploy` reuses `resolve_hosts`, `--target`, `--parallel`, `--only/--skip`,
`--dry-run/--diff`, `--timeout`, and the `Ui` masking/audit path unchanged.

### 6.3 Consistency validation

Because systemd credential stores are global per host, two services must not
publish different values for the same key name. `deploy` decrypts every
referenced service's env files at plan-build time and **fails** if a shared
key has conflicting values, with a message naming the key and both files.
`shellflow secret creds FILE` prints the matching `ImportCredential=` lines so
unit files can be generated from the same source of truth instead of being
hand-maintained.

### 6.4 Target requirements

Targets need `bash` (for remote blocks) and systemd ≥ 254 (for
`systemd-creds` / `ImportCredential=`). No `age`/`rage`/`shellflow` install on
targets. Remote `systemd-creds` runs as the ssh user via passwordless `sudo`.

## 7. Crate & Module Impact

| Area | Change |
|---|---|
| `crates/shellflow-secrets` (new) | `age` wrapper: identity load, encrypt/decrypt, recipient read-back, env-file parser. Library-only; unit + proptest. |
| `crates/shellflow-core` | `ExecutionPlan.secrets: Vec<SecretEntry>`; parser recognizes `@secrets` (path only, no I/O). |
| `bin/shellflow` | clap subcommands (`run` default); executor resolves secrets into run-state env + mask list; `deploy` composes the plan; `Ui` gains a min-length mask threshold. |
| `bin/shellflow/src/preflight.rs` | unchanged (`age` is embedded; `bash`/`ssh`/`rsync` remain the only required tools). |

Dependency additions (via `cargo add`, workspace-managed): `age`,
`age-core`, `clap` (already present), `tempfile` (dev). `shellflow-core`
stays free of async, I/O, and crypto.

## 8. Security Properties

- **Controller-only secrets**: encrypted files travel to the controller,
  decrypted in memory, injected into remote payloads over the (already
  encrypted) SSH channel. Targets never hold the age identity.
- **No argv / no disk**: secret values never appear in process argv; the
  temporary plaintext lives only in shellflow's memory and is dropped after
  the run.
- **Masked everywhere**: previews, `-vv/-vvv` traces, and `--log-file` redact
  every `@secrets` value (subject to the min-length guard).
- **Fail fast**: missing identity, decrypt failure, or malformed env aborts
  before any step executes.
- **Recipient safety**: `secret edit` requires explicit `-r`/`--recipients-dir`
  and fails fast otherwise — age is anonymous, so re-encrypting without the
  full recipient list would silently drop operators.

## 9. Testing Strategy

- **Unit (TDD)** — `shellflow-secrets`: identity load/paths, encrypt→decrypt
  round-trip with an ephemeral generated identity, recipient read-back,
  env-file parsing (blank/comment/`=`-in-value edge cases).
- **Property** — env-file parser invariants via `proptest` (e.g. parse
  round-trip stability), masking threshold behavior.
- **Parser** — `@secrets` directive recognition, ordering, and
  `LT_SECRET_KEYS` export using the existing `shellflow-core` test style.
- **Integration** — extend `bin/shellflow/tests/` with mock `ssh`/`rsync`
  shims (existing pattern): a playbook with `@secrets` must (a) not leak the
  value into captured argv or payload previews, (b) run the remote block with
  the env injected, (c) fail fast without an identity.
- **Mutation** — `just mutation` over the new crate and parser changes.
- **Fuzz** — conditional: the env-file parser is the only parser-like surface;
  add `cargo-fuzz` only if it grows into a general config format.

## 10. Milestones

1. **M1 — `shellflow-secrets` crate.** `age` wrapper + env parser + tests.
2. **M2 — `keys` / `secret` subcommands.** `generate`, `public`, `encrypt`,
   `decrypt`, `edit`, `creds`.
3. **M3 — `@secrets` directive.** Parser entry, executor resolution, masking
   threshold, `LT_SECRET_KEYS`.
4. **M4 — `deploy` subcommand.** Plan composition, consistency validation,
   systemd-creds install step.
5. **M5 — Docs & examples.** Update `README.md`, `docs/design.md`, add an
   end-to-end example playbook and a `deploy` reference.

Each milestone ends with `just format && just lint && just test &&
just mutation` green.

## 11. Decision Records

### D-1. Embed the Rust `age` crate instead of shelling out to `rage`

`rage` is a CLI wrapper over the same crate; embedding it removes a PATH
dependency, keeps behavior identical, and matches the tool's zero-runtime
philosophy. The Go `age` implementation is not used.

### D-2. `@secrets` directive instead of generated base64 `@env` glue

The directive keeps playbooks static and valid Bash, moves decryption into
the tool (where masking already lives), and eliminates render scripts and
temporary files.

### D-3. `deploy` composes the plan in memory instead of rendering a playbook

The step model is already public; composing `ExecutionPlan` reuses the entire
executor/UI path with no new execution machinery and no generated artifacts.

### D-4. Masking with a min-length threshold

`mask_line` does global replacement; protecting short values from being
over-masked requires a threshold, which is exposed as configuration rather
than hard-coded.
