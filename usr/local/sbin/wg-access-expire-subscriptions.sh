#!/usr/bin/env bash
set -euo pipefail

URL="${WG_ACCESS_EXPIRE_URL:-http://127.0.0.1:18080/admin/maintenance/expire-subscriptions}"
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

  rm -f /tmp/wg-access-expire-subscriptions.out /tmp/wg-access-expire-subscriptions.err

  code="$(
    curl -fsS \
      -m 30 \
      -X POST \
      -o /tmp/wg-access-expire-subscriptions.out \
      -w "%{http_code}" \
      "$URL" 2>/tmp/wg-access-expire-subscriptions.err || true
  )"

  echo "http_code=$code"

  if [ -s /tmp/wg-access-expire-subscriptions.out ]; then
    cat /tmp/wg-access-expire-subscriptions.out
    echo
  fi

  if [ -s /tmp/wg-access-expire-subscriptions.err ]; then
    echo "stderr:"
    cat /tmp/wg-access-expire-subscriptions.err
  fi

  rm -f /tmp/wg-access-expire-subscriptions.out /tmp/wg-access-expire-subscriptions.err

  case "$code" in
    2*) exit 0 ;;
    *) echo "ERROR: expire-subscriptions failed"; exit 1 ;;
  esac
} 9>"$LOCK" | tee -a "$out"
