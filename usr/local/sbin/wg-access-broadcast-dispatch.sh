#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
MODE="${1:-run}"
case "$MODE" in run|--check-only) ;; *) echo INVALID_MODE >&2;exit 64;; esac
exec 9>/run/lock/wg-access-broadcast-dispatch.lock
if ! flock -n 9; then echo RESULT=NOOP_BROADCAST_DISPATCH_LOCKED;exit 0;fi
cd /opt/wg-access
test -r docker-compose.yml
if [[ "$MODE" == '--check-only' ]]; then
  docker compose exec -T backend python - <<'INNER_PY_B7B'
from app.services.admin_broadcast_worker import rate_limit
assert 1 <= rate_limit() <= 10
print('RESULT=PASS_BROADCAST_DISPATCH_IMPORT_ONLY')
INNER_PY_B7B
  exit 0
fi
exec docker compose exec -T backend python -m app.services.admin_broadcast_worker </dev/null
