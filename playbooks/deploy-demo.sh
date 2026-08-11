#!/usr/bin/env shellflow

# shellflow playbook: deploy demo-secret-app to trade and api servers.
#
# Uses the cred-wrap approach: systemd host-key-bound credentials are exported
# as environment variables by the cred-wrap wrapper before exec'ing the app.
# No application code changes needed — works with any third-party or
# closed-source project that reads env vars.
#
# Workflow:
#   1. Build the release binary locally.
#   2. Copy binary + unit file to a temp dir on each host.
#   3. Remote: install binary, unit, cred-wrap helper, and systemd credentials.
#   4. Enable + start the service.
#   5. Verify the service ran successfully.
#
# Usage:
#   shellflow playbooks/deploy-demo.sh
#   shellflow -v playbooks/deploy-demo.sh
#   shellflow --dry-run --diff playbooks/deploy-demo.sh
#   shellflow -t trade playbooks/deploy-demo.sh

# @server trade     trade
# @server api       api
# @group  all       trade,api

# === Demo secrets (masked by shellflow in output) ===
# @env DEMO_API_KEY=sk-prod-abcdef1234567890
# @env DEMO_API_SECRET=ss-prod-xyz7890123456789
# @env DEMO_DB_PASSWORD=db-pass-s3cur3-2024!

# === 1. Local: build release binary and create temp dir ===
# @name build
# @local
set -eu
STAMP="demo-$(date +%s)"
echo "==> STAMP=${STAMP}"
WORKDIR="/tmp/${STAMP}"
mkdir -p "${WORKDIR}"
echo "==> Building demo-secret-app (release, x86_64-linux)..."
cargo zigbuild --release -p demo-secret-app --target x86_64-unknown-linux-gnu 2>&1
cp target/x86_64-unknown-linux-gnu/release/demo-secret-app "${WORKDIR}/"
cp services/demo-secret-app/demo-secret-app.service "${WORKDIR}/"
echo "==> Build complete: $(ls -lh "${WORKDIR}/demo-secret-app" | awk '{print $5}')"
# @export STAMP,WORKDIR

# === 2. Copy: ship binary + unit to remote temp dir ===
# @name ship-artifacts
# @copy $WORKDIR/demo-secret-app -> $WORKDIR/demo-secret-app @all
# @copy $WORKDIR/demo-secret-app.service -> $WORKDIR/demo-secret-app.service @all

# === 3. Remote: install binary, unit, cred-wrap, and systemd credentials ===
# @name install
# @remote all
# @timeout 120
set -eu
echo "==> Installing on $(hostname)..."

# Install binary
sudo install -m 0755 "${WORKDIR}/demo-secret-app" /usr/local/bin/demo-secret-app
echo "==> binary installed"

# Install systemd unit
sudo install -m 0644 "${WORKDIR}/demo-secret-app.service" /etc/systemd/system/demo-secret-app.service
echo "==> unit installed"

# Install cred-wrap helper (exports systemd credentials as env vars, then exec)
sudo install -d -m 0755 /usr/local/libexec/shellflow
cat > /tmp/cred-wrap <<'CRED_WRAP_EOF'
#!/usr/bin/env bash
set -eu
if [ -n "${CREDENTIALS_DIRECTORY:-}" ]; then
  for f in "$CREDENTIALS_DIRECTORY"/*; do
    [ -f "$f" ] || continue
    key="$(basename "$f")"
    case "$key" in
      [A-Za-z_][A-Za-z0-9_]*) ;;
      *) continue ;;
    esac
    export "$key=$(cat "$f")"
  done
fi
exec "$@"
CRED_WRAP_EOF
sudo install -m 0755 /tmp/cred-wrap /usr/local/libexec/shellflow/cred-wrap
echo "==> cred-wrap installed"

# Create systemd credential store and encrypt each secret as a host-key-bound credential
sudo install -d -m 0700 /etc/credstore.encrypted
for key in API_KEY API_SECRET DB_PASSWORD; do
  val=$(eval "echo \"\${DEMO_${key}:-}\"")
  if [ -n "$val" ]; then
    printf '%s' "$val" | sudo systemd-creds encrypt --with-key=host --name="$key" - "/etc/credstore.encrypted/${key}" 2>/dev/null
    sudo chmod 0600 "/etc/credstore.encrypted/${key}"
    echo "==> credential written: ${key}"
  fi
done
echo "==> credential store ready"

# Clean up temp files
rm -f "${WORKDIR}/demo-secret-app" "${WORKDIR}/demo-secret-app.service"
echo "==> temp files cleaned"

# === 4. Remote: enable and start the service ===
# @name enable-start
# @remote all
set -eu
sudo systemctl daemon-reload
sudo systemctl enable demo-secret-app.service
sudo systemctl restart demo-secret-app.service
echo "==> service restarted (exit=$?)"

# === 5. Remote: verify the service ===
# @name verify
# @remote all
set -eu
echo "Status: $(sudo systemctl is-active demo-secret-app.service)"
echo "Last 20 log lines:"
sudo journalctl -u demo-secret-app.service --no-pager -n 20
echo "==> Verify complete"