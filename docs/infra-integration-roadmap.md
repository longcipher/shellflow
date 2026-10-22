# ShellFlow in Production: Adoption Analysis and Improvement Roadmap

> Status: proposal (not yet implemented).
> Date: 2026-10-22.
> Scope: how the `infra` repository (a private multi-host deployment repo) actually
> uses ShellFlow today, what that usage exposes in the tool, and which changes to
> ShellFlow would let the playbooks shrink, the deploys get faster, and the
> services stay up.
>
> Evidence base: `infra` at commit `c54cd94` (62 playbooks, 10,720 lines; 86
> systemd unit files) and this repository at `32cdbd4` (v0.3.1).

---

## 0. Implementation status

The roadmap is being implemented phase by phase. **All four gates are green**
(`just format`, `just lint`, `just test`, `just mutation` — 535 mutants, 0
missed).

| Area | State | Notes |
|---|---|---|
| **DSL** | done | `@service`, `@install`, `@backup`, `@credstore`, `@assert_no_leak`, `@assert_digest`, `@assert_credstore`, `@unit_inventory`, `@helper`, `@workdir` all parse, plan, and validate. New plan types: `ServiceStep`, `InstallStep`, `BackupStep`, `CredstoreStep`, `UnitInventoryStep`, `HelperStep`, `Workdir`; new assertions: `NoLeak`, `Digest`, `Credstore`. |
| **Target-side helper** | done | `shellflow host <verb>`: `service`, `install`, `backup`, `credstore`, `assert-no-leak`, `assert-digest`, `assert-credstore`, `inventory`. `shellflow systemd exec` (the readiness supervisor) and `shellflow systemd watchdog` (the keepalive). |
| **Executor** | done | The new steps run through the helper in **one** SSH round trip per host, with the `@secrets` values in the command's environment. `@helper` builds the target binary, caches it by source revision and target triple, ships it, and installs it atomically. `@workdir` publishes the **remote** staging directory; the controller creates nothing, and the target's copy is removed when the run ends. |
| **Guard folding** | done | `@only_if` runs *inside* the payload: one SSH round trip per guarded step instead of two. A failing guard still skips the block (exit code 42). |
| **`--ssh-reuse`** | done | On by default (`--no-ssh-reuse` turns it off). `ControlMaster=auto` is safe by construction: OpenSSH replaces a dead control socket. |
| **Parallel fleet queries** | done | `service status` queries every host concurrently instead of one handshake after another. |
| **`service check` invariants** | done | The audit now flags a **shared `RuntimeDirectory=`** (a live cross-unit data-loss bug), a notify unit without `TimeoutStartSec=`, a restart policy without `StartLimitBurst=`, a unit with no hardening, and a `ProtectHome=`/`ReadWritePaths=` conflict. |
| **Service manifest** | done | `services/<svc>/<unit>.service.toml` states the host, the unit, the binary, the credential store and keys, the render templates, the ports, the health URL, the user and the runtime directory. `service status --all` reads the fleet map from the manifests instead of parsing playbook text. |
| **Unit generator** | done | `shellflow unit render <svc> <unit>` generates the unit's drop-in: the `LoadCredentialEncrypted=` wiring, the `ExecStartPre=… cred-env render …` line and the `ExecStartPost=… systemd-notify --status=…` line. The **shared hardening** stays one file in the repository and the playbook installs it into every unit's drop-in directory, so it is a default without 78 copies of the same 33 lines. A unit that cannot take it says `hardening = false` in its manifest. `--check` fails when a drop-in is stale. |
| **Repository consistency check** | done | `shellflow unit verify` answers statically: is every generated drop-in up to date, does every `@install` name a file the playbook stages, is every drop-in installed, and does the shared hardening reach every service that takes it. The install steps are read out of the playbook with the tool's own parser, so the check sees exactly what a deploy would do. |
| **`service check --all`** | done | Every service of a host is audited in **one** SSH round trip (the questions of every unit travel in one batch). |
| **`infra` migration** | done | All 62 playbooks run on the new primitives: 10,720 → 8,976 lines, `sudo` 1,312 → 631, `systemctl` 350 → 272, cross-compiles 65 → 9. The unit files lost 340 hand-written lines (now generated), and the five live bugs are fixed. |
| **rbatch streaming** | done | The batch answers are parsed **as they arrive**: the response is never held twice, and the connection is closed as soon as the last expected answer is in rather than after a trailing slow query. |

---

## 1. Executive summary

ShellFlow has already done the hard part: the DSL, the secret pipeline
(`age` → `systemd-creds` → per-service credstore → tmpfs → `cred-env`), the
target-side helper, and the first generation of assertion primitives
(`@assert*`, `service check|diff|manifest|verify|status`) all work and are in
daily use.

What has *not* happened is the second half of the migration. The `infra`
playbooks are still ~70% duplicated Bash, and the parts that were migrated were
migrated **ad hoc** — 15 playbooks use `@assert_rendered` correctly, 5 more
hand-roll the same check and get it wrong, and 50 playbooks still hand-roll
`systemctl restart` + `sleep` + `is-active`. Meanwhile the tooling gaps that
the duplication exposes (no atomic install, no rollback, no real drift gate, a
sequential `service status`, a 3-minute cross-compile on every deploy) are all
in ShellFlow, not in the playbooks.

Three structural facts drive every recommendation below.

1. **The targets run `zsh`; the controller runs `bash`.** `infra`'s own
   `AGENTS.md` §3 documents four concrete divergences (`for x in $VAR` does
   not word-split under zsh; `status=` is a read-only special variable; `local`
   outside a function is an error in bash; a manifest without a trailing
   newline loses its last line to `read`). ShellFlow's `-k` linter detects
   three syntactic classes of this — `for x in $VAR`, `${!name}`, `${}` — and
   finds **one** occurrence in the current tree, so the repo is not paying for
   this today. The argument is structural rather than statistical: the
   playbooks currently carry **1,312 `sudo` invocations and 350 `systemctl`
   calls** written in a dialect that is *not* the dialect of the shell they
   will run under, and the linter can only cover the classes someone thought
   to encode. **Every line of Bash removed from a remote block is a portability
   bug class removed.** This is the strongest argument for pushing behaviour
   down into Rust, independent of any other consideration.

2. **Every generic operation in a playbook is a fail-open Bash pipeline.**
   The dominant security assertion in the repo — "no plaintext file left in the
   backup directory" — is `sudo find … -print | grep -q .` under `set -eu`
   with no `pipefail`. If `find` fails (bad path, `sudo` failure, permission),
   `grep` sees zero lines, the `if` is false, and **the assertion passes**. The
   same shape appears in 51 playbooks. It is a security control that cannot
   fail.

3. **70% of the playbooks are one template.** 4,006 of 5,739 code lines
   (69.8%) across `infra/playbooks/` are textual near-duplicates of lines in
   other playbooks. The median per-playbook duplicate ratio is ~76%; the
   maximum is 93.3% (`deploy-rpxy.sh`). The 57 `deploy-*.sh` files are one
   script with the service name swapped.

The recommendation is therefore not "add more features". It is:

- **Promote the repeated blocks into typed DSL primitives** (`@service`,
  `@backup`, `@install`, `@credstore`, `@assert_no_leak`, …) so that the
  primitive's Rust implementation, not the Bash, owns the correctness of the
  operation.
- **Give those primitives the guarantees the Bash never had**: atomic installs,
  automatic rollback, real drift gates, fail-closed semantics, no `sudo` in
  user scripts.
- **Close the performance gaps in the engine**: connection reuse, guard
  round-trip elimination, parallel fleet queries, and a cached target helper.
- **Go one level deeper on systemd**: a target-side supervisor that turns
  `Type=simple` into a real readiness contract, so "the unit is active" stops
  meaning "the process was started" and starts meaning "the service can serve
  traffic".

---

## 2. How `infra` actually uses ShellFlow today

### 2.1 Adoption map

62 playbooks; the DSL directives in use and their adoption:

| Directive | Playbooks using it | Notes |
|---|---:|---|
| `@server` | 60 | `api` / `trade` / `ai` |
| `@secrets` | 56 | the core of the credential chain |
| `@copy` | 59 | |
| `@local` / `@remote` | 62 / 62 | |
| `@export` | 57 | run-state plumbing |
| `@timeout` | 55 | |
| `@name` | 57 | |
| `@assert_port` | 23 | primitive exists, 10 more hand-roll it |
| `@assert_health` | 15 | primitive exists, 10 more hand-roll `curl` |
| `@assert_rendered` | 15 | primitive exists, 5 more hand-roll it **wrongly** |
| `@wait_active` | 9 | primitive exists, 3 more hand-roll poll loops |
| `@assert` (unit state) | 1 | primitive exists, 38 more hand-roll `is-active` |
| `@reload` | 0 | |
| `@only_if` | 0 | implemented in the DSL, never used here |

The shape is clear: the primitives that were introduced in 0.3.x are being
adopted **one playbook at a time, opportunistically**, and the migration has no
definition of "done". Every remaining hand-rolled instance is a place where
the Bash version is weaker than the primitive.

### 2.2 The unit layer

`infra/services/` holds 78 `.service`, 5 `.timer`, 3 `.container` files:

| Property | Count |
|---|---:|
| `Type=simple` (or unspecified) | 66 |
| `Type=oneshot` | 11 |
| `Type=notify` | **1** (`cloudflared-main`) |
| `LoadCredentialEncrypted=` directives | **287** across 52 files |
| `ExecStartPre=… cred-env render` | **43** across 40 files (near-identical) |
| `ExecStartPost=… systemd-notify --status` | 16 (14 byte-identical) |
| Units with **no** inline hardening | 27 / 86 |
| Units using the shared `_common/10-hardening.conf` drop-in | **2** (of 62 playbooks) |
| `WatchdogSec=` | **0** |
| `TimeoutStartSec=` | 6 / 86 (75 rely on the 90 s default) |
| `RestartSec=` unit-style inconsistencies | `5s` ×28 vs `5` ×20 |

Two things stand out.

- **The credential wiring is already excellent** — 287 `LoadCredentialEncrypted=`
  directives, zero plaintext `LoadCredential=`. That part of the design works.
- **The unit layer is where the duplication has not been touched at all.** The
  43 identical `ExecStartPre=` render lines and 14 identical `ExecStartPost=`
  status lines are unit-file equivalents of the playbook duplication, and they
  have no primitive at all.

### 2.3 What the execution engine actually costs

Per step, per host, from `bin/shellflow/src/executor/`:

| Step | SSH round trips |
|---|---|
| Remote block | 1 (+1 probe, cached per host per run) |
| Remote block with `@only_if` | **2** (guard is a separate SSH) |
| Copy | 1 probe + 1 rsync per transfer group |
| `@assert` group | 1 (one framed batch) |
| `@wait_active` | 1 (the whole poll loop runs on the target) |
| `service check` | 1 (8 queries batched) |
| `service status` | **1 per host, strictly sequential** |

Steps themselves are strictly sequential (`execute_plan` awaits each step
before starting the next), so a 10-step playbook against 3 hosts costs ~30
sequential SSH handshakes plus 3 probes.

---

## 3. Structural problems, with evidence

### P-1 — Security assertions that cannot fail (51 playbooks)

`infra/playbooks/deploy-*.sh`, the "no plaintext in the backup directory"
assertion, e.g. `deploy-aihub.sh:68-76`:

```bash
if sudo find "${BACKUP_DIR}" -type f \
     ! -name '*.enc' ! -name '*.service' ... \
     -print | grep -q .; then
  echo "!! plaintext file left under ${BACKUP_DIR}" >&2
  exit 1
fi
```

`set -o pipefail` appears in **0 of 62** playbooks. There are **61** `… | grep -q`
pipelines across the playbooks; the 51 that implement a security assertion are
the subset that matters. Verified behaviour:
```
$ bash -c 'set -eu; if find /nonexistent-dir-xyz -type f -print 2>/dev/null | grep -q .; then echo FAIL-CLOSED; else echo "FAIL-OPEN"; fi'
FAIL-OPEN
```

If `find` fails for any reason the assertion passes. The same shape appears in
the backup-prune pipeline (55 playbooks) — a failing `find` means **old
credential-bearing snapshots are never shredded**, and the deploy still reports
success.

This is the clearest case for a Rust primitive: Rust knows exactly which files
it wrote, so it can assert on its own writes instead of re-globbing the
directory through a fail-open pipeline.

### P-2 — Placeholder checks that pass on a missing file (5 playbooks)

`infra`'s own migration plan (`docs/shellflow-migration-plan.md` §22.4) records
the discovery of this class of bug via `deploy-dufs.sh`. It was fixed there and
**left unfixed in five other playbooks**:

```
playbooks/deploy-cidx.sh:145                /run/cidx/solana-mainnet.toml
playbooks/deploy-cloudflared-main.sh:139     /run/${SVC}/tunnel.json
playbooks/deploy-cloudflared-mevlog.sh:130   /run/${SVC}/tunnel.json
playbooks/deploy-dragonfly.sh:170            /run/${SVC}/dragonfly.conf
playbooks/deploy-lt-equity-reconcile.sh:108  /run/longtrader/htx_host.toml
```

All five use `if sudo grep -E '\$\{[A-Z_]+\}' <path> 2>/dev/null; then`.
`grep` on a missing file exits 2 with no output, so the branch is not taken and
the check **passes**. These cover tunnel credentials, a KV password, and live
exchange credentials. `@assert_rendered` already reports "file missing or
placeholders remain" correctly.

### P-3 — Deploys that start units that were deliberately stopped (50 playbooks)

`infra/AGENTS.md` §1 red line #4: *"do not stop a running service — `systemctl
restart` on an inactive unit **starts it**."* 50 playbooks run an unconditional
`sudo systemctl restart "<unit>"` with no pre-check.
`deploy-smg.sh:132` restarts `smg`, a unit that `AGENTS.md` §9 explicitly
lists as intentionally stopped. `update-binary.sh:471-475` gets this right:

```bash
was_active="$(sudo systemctl is-active "${unit}" 2>/dev/null || true)"
if [ "${was_active}" != "active" ]; then
  echo "    (${unit} 当前是 ${was_active:-unknown} —— 只换二进制, 不启动它)"
  continue
fi
```

The rule exists and is implemented in exactly one place.

### P-4 — Non-atomic installs of live unit files (62 sites)

`deploy-dufs.sh:86`:

```bash
sudo install -m 0644 "${WORKDIR}/svc/dufs.service" /etc/systemd/system/dufs.service
```

`install` truncates in place. The unit file being rewritten is the live unit
file; a reader (systemd, `systemctl cat`, a concurrent `daemon-reload`) can
observe a partially written unit. `update-binary.sh:448-456` does this
correctly for binaries (write `.new`, then `mv -f`), and **nothing in the repo
does it for units or configs**. There is no `ln -sf` release-swap anywhere.

### P-5 — Backups with no rollback (57 playbooks)

51 playbooks create `/root/<svc>-backup-<ts>/`. `grep -rniE 'rollback|restore'
playbooks/deploy-*.sh` returns backup *creation* only. If the verify step
finds a broken service after a successful restart, the operator hand-restores
from a directory whose layout is defined by shell code inside the playbook.

### P-6 — The controller's `/tmp` accumulates credentials and binaries (58 playbooks)

`deploy-dufs.sh:26-32` creates `/tmp/dufs-<epoch>` on the **controller** and
never removes it; the `rm -rf "${WORKDIR}/svc" "${WORKDIR}/shellflow"` at
line 91 is inside the **remote** block and cleans the *target*. Every deploy
therefore leaves on the controller:

- a full cross-compiled `shellflow` binary (~10–20 MB), and
- `${WORKDIR}/svc`, a plain local copy of `services/<svc>/` — which for the 33
  credentialed services contains `api.env.age` (age ciphertext, but still
  credential material outside the repo), because `--exclude *.age` applies to
  the transfer to the target, not to the local staging.

### P-7 — Cross-unit data loss through a shared `RuntimeDirectory`

`services/cidx/cidx-{bsc,sol,sui,explorer}.service` all declare
`RuntimeDirectory=cidx` (line 10 in each). systemd **removes and recreates**
`RuntimeDirectory=` on every unit start, so starting `cidx-bsc` wipes
`/run/cidx/` — including the rendered config of the other three running units.
This is a live bug in the repo today, and it is exactly the class of thing a
unit-level linter should catch.

### P-8 — A security audit that reports OK unconditionally

`playbooks/ops-security-audit.sh:145` writes `FAIL\tC\t…`; line 156 counts
with the wrong item letter:

```bash
ccount="$(grep -c '^FAIL<D>	' "${FINDINGS}" 2>/dev/null || true)"
if [ "${ccount}" -eq 0 ]; then
  ok C "unit 里没有硬编码的秘密"
fi
```

Verified: `grep -c '^FAIL<TAB>C<TAB>'` → 1, `grep -c '^FAIL<TAB>D<TAB>'` → 0.
Section C's failures are never counted, so the "OK" line is printed
unconditionally. The overall exit code is still correct (line 248 counts
`^FAIL` globally), but the per-section verdict — the part a human reads — is
wrong.

### P-9 — `service status` is sequential across hosts

`bin/shellflow/src/service_status.rs:57`:

```rust
for (alias, dest) in &hosts {
    ...
    match batch.run_dest(dest) { ... }
}
```

No `JoinSet`, no semaphore, no `--parallel`. Every other multi-host operation
in the tool uses `JoinSet` + a semaphore; this one does not. A fleet query
costs one full SSH handshake after another.

### P-10 — The `@only_if` guard costs a second full round trip

`bin/shellflow/src/executor/remote.rs:1464` runs the guard as a **separate
SSH invocation** before the payload. The guard and the payload have identical
preconditions (same host, same shell, same env) and could be a single
invocation whose script begins `if ! (<guard>); then exit 42; fi`. That is a
50% reduction in round trips for guarded steps, with identical semantics.

### P-11 — `--ssh-reuse` exists but is off by default

`bin/shellflow/src/cli.rs:120` / `executor/remote.rs:1211`. The rationale
recorded in the code — *"a stale master socket can never break a deploy
silently"* — is a misreading of OpenSSH semantics: with
`ControlMaster=auto`, a dead socket is detected and a new master is created.
The flag is safe; it is just off by default, so every step pays a full TCP +
auth handshake.

### P-12 — The target helper is cross-compiled on every deploy

57 playbooks run `cargo zigbuild --release -p shellflow --target
x86_64-unknown-linux-musl` in their `@local` block. That is minutes of wall
clock per deploy, and it happens again for every service. 56 of the 57
hard-code the controller path `/Volumes/akext/src/github.com/longcipher/shellflow`
into the playbook — a machine-specific absolute path baked into a versioned
deployment script.

---

## 4. Proposal: new DSL primitives

Every primitive below is a directive in `shellflow-dsl`, with the semantics
implemented in Rust and executed on the target by the existing helper binary
(`/usr/local/bin/shellflow`). The design rule is the same one the existing
primitives follow: **the primitive owns the correctness of the operation**, so
the failure mode is a Rust error, not a Bash pipeline that happens to look
right.

### 4.1 `@service <unit> @<target> [--enable] [--restart] [--reload] [--wait] [--verify] [--force-start]`

Replaces the `systemd-analyze verify` → `daemon-reload` → `enable` →
`restart` → `is-active` quintet (57 / 57 / 51 / 50 / 38 playbooks).

```
# @name enable-start
# @service dufs.service @api --enable --restart --wait --verify
```

Rust semantics:

- `systemd-analyze verify` first, **fail closed**.
- Capture the unit's pre-state before touching it.
- `daemon-reload`, then `enable` if requested.
- `--restart` restarts **only if the unit was active before**; `--force-start`
  overrides. This encodes red line #4 in the tool instead of in 57 copies of
  Bash.
- `--wait` reuses the existing notify-aware wait in
  `bin/shellflow/src/systemd.rs` (`verdict()` already models `Type=notify`,
  `Type=oneshot` and failure `Result=` correctly).
- `--verify` runs `systemd-analyze verify` against the *installed* unit.

Removes ~8 lines from every playbook and the `sudo systemctl` surface entirely.

### 4.2 `@backup <path>… @<target> [--keep N] [--seal] [--dir <path>]`

Replaces the 35-line backup → assert → prune block (55 playbooks).

```
# @backup /etc/systemd/system/dufs.service /home/akagi201/data/.dufs/config.yaml @api --keep 5 --seal
```

- Copies each existing path into `/root/<svc>-backup-<ts>/`.
- `--seal` encrypts non-unit files with `systemd-creds encrypt --with-key=host`
  so plaintext never lands in the snapshot.
- **Asserts on its own writes**: the implementation knows which files it
  created, so the "no plaintext left behind" guarantee is structural, not a
  `find | grep` over a directory it does not control.
- Prunes old snapshots and `shred`s them — using checked exit codes, so a
  failed `find` is an error rather than a silent skip.

### 4.3 `@install <src> -> <dst> @<target> [--mode 0644] [--owner root:root]`

Replaces the 62 `sudo install -m …` call sites and fixes P-4.

- Writes to a temp file **in the destination directory**, `fsync`s, then
  `rename()`s — atomic on the same filesystem, so a reader never sees a
  half-written unit.
- `--owner` / `--mode` are applied by the helper under controlled elevation.
- The destination directory is created if missing (four playbooks shipped
  config into a directory they never created — `docs/shellflow-migration-plan.md`
  §15.5).

### 4.4 `@credstore <svc> @<target> [--require <key>…]`

Replaces the hand-written `shellflow cred-env credstore-install "${SVC}"`
(33 playbooks) and adds the check that does not exist today:

- Seals the store (already implemented in `bin/shellflow/src/cred_env.rs`).
- **Compares the unit's `LoadCredentialEncrypted=` key set against the store's
  actual key set.** Today `service check` only *counts* the import lines; a
  unit declaring `LoadCredentialEncrypted=FOO` against a store containing `BAR`
  fails at service start with a cryptic systemd error. This check makes it a
  deployment-time failure with a clear message.
- Asserts `0700` on the store directory and `0600` on each key.

### 4.5 `@assert_no_leak <unit> @<target> [--lines N]`

Replaces the 29 per-service journal leak greps.

The current pattern is a **regex** per service:

```bash
if sudo journalctl -u dufs.service --no-pager -n 30 | grep -E 'WALLET_JWT_SECRET=.{8}|basic-auth password.{0,3}[":=].{20}'; then
```

The Rust version is strictly stronger and needs no per-service regex: it
decrypts the credential on the target, holds the plaintext in memory, and
checks the journal — and `/proc/<pid>/environ` and `systemctl show
ExecStart` — for occurrences of the **actual value**. The plaintext never
enters the playbook, never enters the command line, and never leaves the
target.

This also fixes `ops-security-audit.sh:172`, which currently pipes the
plaintext credential into `grep`'s **argv**, where it is visible in `ps` to
any user on the host for the duration of the grep.

### 4.6 `@assert_digest <path> @<target> [--sha256 <hex>]`

Real drift detection. `deploy-rpxy.sh:202` prints an md5 that nothing
compares against:

```bash
echo "==> config on disk matches the repo (md5):"
sudo md5sum /opt/rpxy/etc/config.toml
```

`service manifest` / `service verify` already compute sha256 manifests, but
they are not reachable from a playbook step, so the check is advisory. This
makes the comparison a gate, and can compare the target against the
**controller's** copy of the repo file, which is what "drift" actually means.

### 4.7 `@unit_inventory @<target>` / `@assert_managed @<target>`

`ops-healthcheck.sh:106` computes "unmanaged units" by scanning
`/etc/systemd/system/*.service` and subtracting the repo list. It misses
`.timer`, `.socket`, `.mount`, `.path`, `.target`, and every drop-in directory,
because `find -maxdepth 1 -name '*.service'` is the only pattern used. The
repo list itself is built by `find services -type f -name '*.service'` on the
controller and shipped down as a text file.

Rust can do this correctly in one query per host, in both directions, and
report drop-ins.

### 4.8 `@workdir` — a managed temporary directory

Replaces `STAMP="$(date +%s)"; WORKDIR="/tmp/${STAMP}"; mkdir -p "${WORKDIR}"`
(58 playbooks) with a directory that is:

- created by the engine, with a collision-resistant name,
- **cleaned up on every exit path** — success, failure, `SIGINT` — on **both**
  the controller and the target,
- excluded from the credential material by default.

The `shellflow-core` crate already has a `CaptureFile` drop-guard
(`executor/local.rs:125`) for exactly this pattern; the workdir needs the same
discipline.

### 4.9 `@helper` — build once, cache, ship

Replaces the 57 cross-compile blocks.

```
# @helper @api
```

- Resolves the source tree from a repository-level config file instead of a
  hard-coded `/Volumes/akext/...` path.
- Caches the built binary under `~/.cache/shellflow/helper-<git-sha>-<arch>/`
  and rebuilds only when the source HEAD or the target triple changes.
- Builds **once** and shares the artifact across all services and all
  playbooks in a run.
- Stages and installs it to `/usr/local/bin/shellflow` on the target.

This removes the single largest wall-clock cost in the current deploy loop
(minutes per deploy) and the 56 hard-coded controller paths.

### 4.10 `@rollback @<target> [--from <backup-dir>]`

The missing half of P-5. Because `@backup` is implemented in Rust, it knows
the manifest of what it snapshotted, so restoring is a first-class operation
rather than a set of shell incantations copied 51 times.

A natural follow-on: a `--rollback-on-failure` mode on `@service`, so that a
deploy that fails verification restores the previous unit/binary automatically
and reports the rollback.

### 4.11 `@assert_rendered` — already exists; use it everywhere

No new primitive. It is a **migration** item: replace the five hand-rolled
placeholder checks in §3/P-2. The playbook already documents the rule
(`docs/shellflow-migration-plan.md` §22.4: *"use `@assert_rendered`; do not
write `grep … 2>/dev/null`"*) — it was just never applied to the other five
playbooks.

### 4.12 `shellflow systemd exec` — a target-side supervisor

This is the systemd-integration answer, and it is the one with the largest
stability impact.

Today 66 of 86 units are `Type=simple`. For a `Type=simple` unit, `active`
means *"the process was forked and has not exited"* — it says nothing about
whether the service can serve traffic. That is why the playbooks need
`restart` + `sleep 5` + `is-active`, and why `deploy-cidx.sh:130-134` uses a
fixed 5 s sleep for four indexers:

```bash
for u in cidx-bsc cidx-sol cidx-sui cidx-explorer; do
  sudo systemctl restart "${u}.service"
  sleep 5
  sudo systemctl is-active "${u}.service"
done
```

`infra`'s own `AGENTS.md` §6 already records the lesson: *"a unit that reports
`active` first and dies later — a single `is-active` tells you nothing."*

**Proposal**: a target-side supervisor in the helper binary.

```
ExecStart=/usr/local/bin/shellflow systemd exec \
  --ready-port 5000 --ready-url http://127.0.0.1:5000/ \
  -- /opt/dufs/bin/dufs --serve ...
```

with `Type=notify` on the unit. The supervisor:

- starts the real binary as a child,
- waits for the declared readiness condition (port open, health URL 2xx, or a
  file to appear) with a bounded budget,
- sends `READY=1` and `STATUS=…` on success, or fails the unit on timeout,
- forwards `SIGTERM`/`SIGINT` to the child and exits with the child's code,
- optionally pings `WatchdogSec=` on the child's behalf (`NotifyAccess=all`),
- reaps the child and never leaves a zombie.

This turns "active" into "ready", makes `@wait_active` meaningful for 66
units instead of 1, and removes the `sleep`-based guesswork from every
playbook. It is the single change that most directly serves "make the service
run more reliably".

It also unlocks `WatchdogSec=`: today **0 of 86** units use it, and there is no
keepalive emitter, so a hung-but-alive process is invisible. With the
supervisor, `WatchdogSec=30` becomes usable for any service.

### 4.13 A unit generator: `shellflow unit render`

43 near-identical `ExecStartPre=/usr/local/bin/shellflow cred-env render
<tmpl> /run/<svc>/<file>` lines and 14 near-identical
`ExecStartPost=/bin/sh -c 'systemd-notify --status="Version: $(… -V)"'`
lines live in the unit files today. A generator that emits the credential
wiring and the hardening drop-in from a per-service manifest would remove all
57 of them, and — more importantly — would make the *shared* hardening drop-in
(`services/_common/10-hardening.conf`, which is excellent but installed by
only 2 of 62 playbooks) a default rather than an opt-in.

---

## 5. The data-driven alternative: a service manifest

The 57 `deploy-*.sh` files are one template with the service name swapped.
The reason is structural: a playbook is the only place where the facts about a
service (host, unit name, ports, health URL, credential keys, deploy target)
can currently live, and a playbook can only hold those facts as *code*.

The end state should be a declaration per service — e.g.
`services/<svc>/service.toml`:

```toml
host        = "api"
unit        = "dufs.service"
binary      = "/opt/dufs/bin/dufs"
ports       = [5000]
health      = "http://127.0.0.1:5000/"
credentials = ["WALLET_JWT_SECRET"]
secret_file = "services/dufs/{host}.env.age"
readiness   = { port = 5000 }
```

From that single file the tooling can derive:

- the fleet map for `service status --all` — today derived by *parsing
  playbooks* (`service_status.rs:283-343`), which is fragile and reads the
  wrong file when a service moves;
- a per-host `service check` batch covering **all** services on that host in
  one SSH round trip;
- the generated playbook (a thin wrapper, or none at all);
- the credential key-set check (§4.4);
- the hardening drop-in wiring (§4.13).

This is the answer to "integrate generic functionality into Rust, minimize
shell code": the generic functionality is not a directive per operation, it is
a **data model** that drives every operation. The playbook shrinks to the
service-specific parts — which is where it belongs.

---

## 6. Performance plan

Ordered by measured impact on the `infra` deploy loop.

| # | Change | Where | Expected effect |
|---|---|---|---|
| 1 | Cache the cross-compiled target helper keyed by source SHA + target triple | new `~/.cache/shellflow/` builder | removes minutes from **every** deploy |
| 2 | Fold `@only_if` into the payload invocation | `executor/remote.rs:1464` | −1 SSH round trip per guarded step per host |
| 3 | Default `--ssh-reuse` on | `cli.rs:120`, `executor/remote.rs:1211` | −1 TCP+auth handshake per step; ~30 → ~3 handshakes for a 10-step playbook |
| 4 | Parallelise `service status` across hosts | `service_status.rs:57` | fleet query: N sequential SSH → 1 parallel batch |
| 5 | Parallelise `service check` across hosts and services | `service.rs` | one round trip per host instead of one per service |
| 6 | Stream `rbatch` output instead of buffering it whole | `rbatch.rs` | bounded memory for large `journalctl` / `sha256sum` results |
| 7 | Merge the environment probe into the first payload | `executor/remote.rs:1328` | −1 SSH round trip per host per run |
| 8 | Replace `shellflow service check` shell-out with a native Rust path | `service_check/` | removes a local process spawn + output reformat per audit |

Note that (2), (3) and (7) are **round-trip eliminations**, not micro-optimizations:
each one removes a full SSH handshake (TCP connect + key exchange + auth) from
the critical path of every step.

On concurrency: the tool already models this correctly for plan execution —
`JoinSet` plus a shared `Semaphore` sized by `--parallel` (default 16),
acquired per host, with a closed semaphore failing the host rather than
silently running unthrottled (`executor/mod.rs:248`). `service status` is the
one place that bypasses this model and should be brought in line.

---

## 7. systemd integration: where the depth is missing

The existing systemd work is genuinely good and already landed: the target-side
helper (`shellflow systemd notify|wait|reload|status|watch|transient`), the
notify-aware `@wait_active`, the `@reload` directive, the `service check`
notify/readiness rules, and the optional D-Bus feature. The migration plan's
§15 lists these as phases 1–6 and they are all present.

What is missing is on the **unit** side and in the **fleet** side.

| Gap | Evidence | Consequence |
|---|---|---|
| Only 1 of 86 units is `Type=notify` | `services/**` | "active" ≠ "ready" for 65 units |
| No supervisor / readiness contract | — | playbooks resort to `sleep 5` + `is-active` |
| `WatchdogSec=` used by 0 units, no keepalive emitter | `services/**` | hung-but-alive processes are invisible |
| `TimeoutStartSec=` on 6 of 86 | `services/**` | 75 units get a 90 s default; `cidx` loading a 2 TB index is a coin flip |
| `RestartSec=` style inconsistent (`5s` vs `5`) | 28 + 20 units | cosmetic, but drifts |
| `StartLimitInterval`/`Burst` on 14 of 86 | — | `Restart=always` + `RestartSec=5` + default burst = killed after 5 restarts in 25 s |
| Shared hardening drop-in installed by 2 of 62 playbooks | `services/_common/10-hardening.conf` | 27 units have no hardening at all |
| 4 units share `RuntimeDirectory=cidx` | `services/cidx/*.service:10` | one unit's restart wipes the others' rendered config |
| `ReadWritePaths=/home/akagi201/...` under `ProtectHome=read-only` | 24 lines across 13 units | the 226/NAMESPACE failure mode the migration plan §18.5 already documents |
| 10 units run as root with no `User=` | `services/**` | |
| `Type=notify` + `TimeoutStartSec=15` | `cloudflared-main` | killed if it takes >15 s to become ready |
| 4 identical `ExecStartPre` render lines per unit family | 43 total | no unit-level abstraction |

Two of these are **tool** problems rather than repo problems, and belong in
ShellFlow:

- **`service check` should unit-test unit invariants.** It already audits
  credentials, notify wiring and path existence. It should also flag: a
  `RuntimeDirectory=` shared by more than one unit; a `ReadWritePaths=` under
  `ProtectHome=read-only`; `Type=notify` with a short `TimeoutStartSec`; a
  missing `TimeoutStartSec` on a unit whose `Type=` implies slow start; a
  `Restart=` without `StartLimitBurst=`; `ExecStart=` pointing at a path
  outside the declared layout.
- **A unit-level diff/verify should be a playbook step, not a manual
  `service diff` invocation.** `service diff` exists and is good; it is simply
  not reachable from the deploy loop.

---

## 8. Migration sequence

The `infra` side has a working convention already: *"the assertion primitives
landed in 0.3.1"* and *"use `@assert_rendered`; do not write `grep … 2>/dev/null`"*
(`docs/shellflow-migration-plan.md` §22). The problem is that the convention
has no enforcement and no definition of done.

**Phase 0 — the live bugs in `infra` (done; each one fixed where it was
found).**

1. `ops-security-audit.sh:156` — count `FAIL<TAB>C<TAB>`, not `FAIL<TAB>D<TAB>`.
   There is no `fail D` in the script (section D records `LEAK`, not `FAIL`), so
   the count was always zero and section C reported *"no hardcoded secrets"*
   even when it had just found some.
2. The five hand-rolled placeholder checks (§3/P-2) are now `@assert_rendered`
   — in `deploy-cidx.sh`, `deploy-cloudflared-main.sh`,
   `deploy-cloudflared-mevlog.sh`, `deploy-dragonfly.sh` and
   `deploy-lt-equity-reconcile.sh`. The old spelling passed on a file that was
   never rendered; the primitive fails on a missing file *and* on a leftover
   placeholder.
3. The shared `RuntimeDirectory=cidx` is gone: the four indexer units each own
   one now (`cidx-bsc`, `cidx-sol`, `cidx-sui`, `cidx-explorer`), and their
   rendered configuration lives under `/run/<unit>/`. systemd recreates a
   runtime directory on every start, so a shared one meant that one unit's
   restart wiped the others' rendered files.
4. The security assertions in the remote blocks became `@assert*` primitives,
   which fail closed — the `set -o pipefail` variant was not needed.
5. The unconditional `systemctl restart` in the 50 affected playbooks is gone:
   the `@service` primitive restarts a unit **only when it was running**
   (`host.rs`: `was_active`), and leaves a unit the operator keeps stopped
   stopped.

**Phase 1 — the primitives with the highest duplication payoff.**
`@service`, `@install`, `@backup`, `@credstore`. These four remove the bulk of
the 51-playbook backup block and the 57-playbook lifecycle block, and they
carry the atomicity, rollback and fail-closed properties with them.

**Phase 2 — the assertion primitives.** `@assert_no_leak`, `@assert_digest`,
`@assert_credstore`, `@unit_inventory`. These replace 29 regex-based leak
greps and the hand-rolled inventory logic, and they strengthen the checks
(value-based rather than shape-based).

**Phase 3 — the engine work.** Guard folding, `--ssh-reuse` default,
parallel `service status`/`check`, `rbatch` streaming, the helper cache,
`@workdir`.

**Phase 4 — systemd depth.** `shellflow systemd exec` (the supervisor), the
watchdog keepalive, the unit generator, and the `service check` unit-invariant
rules.

**Phase 5 — the manifest.** `services/<svc>/service.toml` and everything it
enables; the playbooks become thin.

Each phase is independently shippable and independently valuable, which matters
because the `infra` repo's convention requires a green verification loop after
every change.

---

## 9. What this would look like

`infra/playbooks/deploy-dufs.sh` today is 143 lines: 19 lines of local
build-and-stage, 4 of copy, 49 of backup/assert/prune/install, 9 of lifecycle
(`systemd-analyze verify` → `daemon-reload` → `enable` → `restart`), 25 of
verify, 10 of audit. With the primitives above it becomes:

```bash
#!/usr/bin/env shellflow
# @server api    api
# @secrets services/dufs/{host}.env.age

# @name fetch
# @local
set -eu
SVC=dufs
# @helper @api
# @export STAMP,WORKDIR,SVC

# @name ship
# @copy services/$SVC -> $WORKDIR/svc @api --exclude *.age

# @name install
# @remote api
# @timeout 180
# @backup /etc/systemd/system/dufs.service /home/akagi201/data/.dufs/config.yaml @api --keep 5 --seal
# @install $WORKDIR/svc/config.yaml.tmpl -> /opt/dufs/etc/config.yaml.tmpl @api --mode 0644
# @install $WORKDIR/svc/dufs.service -> /etc/systemd/system/dufs.service @api --mode 0644
# @credstore dufs @api

# @name enable-start
# @service dufs.service @api --enable --restart --wait --verify

# @name verify
# @assert dufs.service @api active
# @assert_health http://127.0.0.1:5000/ @api --expect 2xx,3xx,4xx
# @assert_port 5000 @api
# @assert_rendered /run/dufs/config.yaml @api
# @assert_no_leak dufs.service @api
# @assert_credstore dufs @api

# @name audit
# @local
shellflow service check dufs --host api
```

Roughly 143 → 35 lines. More importantly, the resulting playbook contains **no
`sudo`, no `zsh`-sensitive construct, no fail-open pipeline, and no
hand-rolled backup layout** — because none of those decisions belong in a
deployment script.

---

## 10. Metrics

How to tell whether this worked:

| Metric | Today | Target |
|---|---:|---:|
| Non-comment playbook lines | 5,739 | < 2,000 |
| Playbook lines that are exact duplicates of another playbook | 4,006 (69.8%) | < 10% |
| `sudo` invocations in playbooks | 1,312 | 0 |
| `systemctl` invocations in playbooks | 350 | 0 |
| Remote blocks containing zsh-sensitive constructs | 1 (lint-detectable class) | 0 |
| Fail-open `… \| grep -q` pipelines | 61 | 0 |
| Security assertions implemented as fail-open pipelines | 51 | 0 |
| Deploys that cross-compile the helper | 57 per service | 0 (cached) |
| SSH round trips for a 10-step, 3-host playbook | ~33 | ~6 |
| Wall clock for one service deploy | minutes (helper build) | seconds |
| Units with a real readiness contract (`Type=notify`) | 1 / 86 | > 40 / 86 |
| Units with `WatchdogSec=` | 0 | > 0, with a keepalive |
| Units with the shared hardening drop-in | 2 | all |
| Deploys with an automatic rollback path | 0 / 57 | 57 / 57 |
| Plaintext credentials in the controller's `/tmp` after a deploy | 33 services | 0 |

---

## 11. Explicit non-goals

- **Do not add a YAML/TOML script format.** The DSL is Bash with `# @`
  directives; that is the product. The manifest in §5 is *data about services*,
  not a replacement for the playbook language.
- **Do not add an SSH client crate.** Remote execution stays on the system
  `ssh`/`rsync`/`scp`.
- **Do not turn on the D-Bus feature by default.** The standard build stays a
  single static binary with no D-Bus dependency; the polling path must keep
  producing byte-identical output.
- **Do not make `service check` a deployment gate.** It is a report: a
  pre-existing finding must not block an unrelated deploy. That convention is
  correct and should be preserved.
- **Do not enable socket activation for existing services.** Third-party
  binaries do not read `LISTEN_FDS`; forcing it would prevent them from
  starting. The scaffolding stays available for services that opt in.
