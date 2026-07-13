#!/usr/bin/env bash
set -euo pipefail

echo "[wg-access-reconcile] start $(date -Is)"
echo "[wg-access-reconcile] source=systemd-reconcile-service"

# The agent service is the existing idempotent runtime sync engine.
# It syncs desired enabled peers from VM121 DB to VM100 wg_paid runtime,
# then processes pending provisioning jobs if any.
if systemctl start --help 2>/dev/null | grep -q -- '--wait'; then
  systemctl start --wait wg-access-agent.service
else
  systemctl start wg-access-agent.service
  for i in $(seq 1 120); do
    state="$(systemctl is-active wg-access-agent.service || true)"
    [ "$state" != "active" ] && break
    sleep 1
  done
fi

systemctl show wg-access-agent.service   -p Result   -p ExecMainStatus   -p ExecMainStartTimestamp   -p ExecMainExitTimestamp   --no-pager || true

echo "[wg-access-reconcile] done $(date -Is)"
