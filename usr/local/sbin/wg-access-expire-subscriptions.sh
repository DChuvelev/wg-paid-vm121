#!/usr/bin/env bash
set -euo pipefail

LOG_DIR="/opt/wg-access/maintenance-logs"
LOCK="/run/wg-access-expire-subscriptions.lock"

mkdir -p "$LOG_DIR"

ts="$(date -Is)"
out="$LOG_DIR/expire-subscriptions.$(date +%Y%m%d).log"

{
  echo "== $ts expire-subscriptions =="
  flock -n 9 || {
    echo "another expire-subscriptions run is already active"
    exit 0
  }
  echo "legacy Domain V1 subscription-expiry maintenance is retired"
  echo "RESULT=NOOP_DOMAIN_V1_MAINTENANCE_RETIRED"
} 9>"$LOCK" | tee -a "$out"
