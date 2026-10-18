# Example Applications: `secret-app` (encrypted) & `env-app` (plain env)

Two complete, deployable examples of managing an application with shellflow.
They configure the same *shape* of app (a binary reading env vars) through the
two workflows this tool supports:

| | `examples/secret-app` | `examples/env-app` |
|---|---|---|
| Configuration transport | age-encrypted env file → systemd host-key-bound credentials | plaintext `@env` literals → 0600 `EnvironmentFile` on the target |
| Values on target disk | host-key-bound ciphertext only | **plaintext** (readable by root) |
| Target-side helper | `/usr/local/bin/shellflow` (`cred-env exec`) | none |
| Controller identity needed | yes (age key, `@secrets`) | no (`@env` literals) |
| Use for | anything actually sensitive | non-sensitive config / quick demos |

Both are workspace members (`cargo build -p secret-app -p env-app`) and both
deploy through a shellflow playbook committed next to the app.

```text
examples/
├── secret-app/
│   ├── src/, Cargo.toml     app: reads API_KEY / API_SECRET / DB_PASSWORD
│   ├── .env.example         local-dev placeholder values (.env is gitignored)
│   ├── secret-app.service   systemd unit (LoadCredentialEncrypted= + cred-env exec)
│   └── deploy.sh            shellflow playbook (api + trade)
└── env-app/
    ├── src/, Cargo.toml     app: reads APP_GREETING / APP_TOKEN
    ├── env-app.service      systemd unit (EnvironmentFile=, plaintext)
    └── deploy.sh            shellflow playbook (api only)
```

---

## 1. `secret-app` — the encrypted workflow

### 1.1 The app

A typical third-party / closed-source pattern: it only reads environment
variables and cannot be changed to use systemd's credential API. The unit
therefore delegates to the shared helper installed on the target:

```ini
[Service]
DynamicUser=yes
ExecStart=/usr/local/bin/shellflow cred-env exec /opt/secret-app/bin/secret-app
LoadCredentialEncrypted=API_KEY:/etc/credstore.encrypted/secret-app/API_KEY
LoadCredentialEncrypted=API_SECRET:/etc/credstore.encrypted/secret-app/API_SECRET
LoadCredentialEncrypted=DB_PASSWORD:/etc/credstore.encrypted/secret-app/DB_PASSWORD
```

`cred-env exec` exports every file in `$CREDENTIALS_DIRECTORY` as an env var
(filename = variable name) and execs the real binary (process replacement, so
systemd supervision applies to the app). Generate the
`LoadCredentialEncrypted=` lines with:

```bash
shellflow secret creds --store-dir /etc/credstore.encrypted/secret-app <host>.env.age
```

### 1.2 The playbook chain

```text
Controller (macOS)
  1. cargo zigbuild secret-app (x86_64-linux) + shellflow (x86_64-linux-musl)
  2. shellflow parses examples/secret-app/deploy.sh (@env demo values, masked in output)
  3. @copy app binary + unit + shellflow helper -> remote /tmp/<stamp>/
  4. @remote sudo install -> /opt/secret-app/bin/, /usr/local/bin/shellflow,
     /etc/systemd/system/secret-app.service
  5. @remote shellflow cred-env credstore-install secret-app
        -> /etc/credstore.encrypted/secret-app/<KEY>   (host-key-bound ciphertext, 0600 root)
  6. @remote systemctl daemon-reload + enable + restart
  7. @remote journalctl verification
```

The example playbook carries its demo values as `@env` literals so it runs
without an identity file; a real deployment replaces that block with
`# @secrets <host>.env.age` (see SKILL.md §4). The key list and value mapping
that `@secrets` would normally inject are constructed explicitly in the
install block:

```bash
LT_SECRET_KEYS="API_KEY API_SECRET DB_PASSWORD" \
API_KEY="${API_KEY}" API_SECRET="${API_SECRET}" DB_PASSWORD="${DB_PASSWORD}" \
  /usr/local/bin/shellflow cred-env credstore-install secret-app
```

`credstore-install` clears the per-service store and re-seals every key via
`sudo systemd-creds encrypt --with-key=host --name=<KEY>` (value on stdin,
never argv). Unset keys, empty values, invalid key names, and unsafe service
names all fail closed.

### 1.3 Local development

```bash
cp examples/secret-app/.env.example examples/secret-app/.env   # placeholders
cargo run -p secret-app                                        # reads .env via your shell
```

### 1.4 Deploy & verify

```bash
shellflow -k examples/secret-app/deploy.sh                      # syntax + env resolution
shellflow --dry-run --diff examples/secret-app/deploy.sh        # full preflight
shellflow examples/secret-app/deploy.sh                         # real deploy
shellflow -t trade examples/secret-app/deploy.sh                # canary one host
```

On a target:

```bash
ssh api "sudo ls -l /etc/credstore.encrypted/secret-app/"   # one 0600 ciphertext per key
ssh api "sudo journalctl -u secret-app.service -n 10"       # app output (values masked)
```

### 1.5 Security properties

| Location | Content | Protection |
|---|---|---|
| Repository | age ciphertext (`*.env.age`) + public key | age private key (controller) |
| Controller memory | plaintext during deploy | output masking (`***`), values never in argv |
| ssh transport | plaintext inside the encrypted channel | ssh |
| Target disk | `/etc/credstore.encrypted/secret-app/<KEY>` | host-key-bound (`/var/lib/systemd/credential.secret`), 0600 root |
| Runtime | `$CREDENTIALS_DIRECTORY` (tmpfs) | unit lifetime, destroyed on exit |

Changing a value: `shellflow secret edit -r "$(cat keys/recipients/…)" <host>.env.age`
then re-run the playbook — the credstore is re-sealed idempotently.

---

## 2. `env-app` — the plain env baseline

The same shape of app with **no encryption anywhere**: configuration ships as
`@env` literals in the playbook and lands as a plaintext
`/etc/env-app/env-app.env` (0600 root) read via `EnvironmentFile=`. No age
identity, no credstore, no target-side helper.

```ini
[Service]
DynamicUser=yes
EnvironmentFile=/etc/env-app/env-app.env
ExecStart=/opt/env-app/bin/env-app
```

```bash
# deploy
shellflow -k examples/env-app/deploy.sh
shellflow examples/env-app/deploy.sh
```

The install block writes the file from the values shellflow injected into the
remote block (masked in output, never in argv):

```bash
for key in APP_GREETING APP_TOKEN; do
  val=$(printenv "$key")                       # set -eu: unset aborts the block
  [ -n "$val" ] || { echo "!! ${key} empty" >&2; exit 1; }
  printf '%s=%s\n' "$key" "$val" >> /tmp/env-app.env
done
sudo install -m 0600 /tmp/env-app.env /etc/env-app/env-app.env
```

**The trade-off this example exists to show**: the values are 0600-on-disk and
in the process environment, readable by root and anything the process talks
to. Fine for greetings and non-sensitive tuning; use the `secret-app` workflow
for anything you would not print in a README.

---

## 3. Choosing between the two

- **Values you would not commit in plaintext** → `secret-app` (encrypted).
  Costs: an age identity on controllers, one `<host>.env.age` per host, and a
  per-service `LoadCredentialEncrypted=` block.
- **Values that are merely configuration** → `env-app` (plain). Costs: none;
  values live on the target disk and inside the unit's environment.
- Both deploy through the same engine, so migrating an app from `env-app` to
  `secret-app` is: add `<host>.env.age`, swap the unit's `EnvironmentFile=`
  for `LoadCredentialEncrypted=` + `cred-env exec`, and point the playbook's
  `@env` block at `@secrets`.
