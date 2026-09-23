#!/usr/bin/env python3
# Host-side event watcher for WG Access agent.
#
# Backend/container writes unique files into:
#   /opt/wg-access/runtime/agent-trigger/events/
#
# Event files are only best-effort wake signals. provisioning_jobs in the DB
# remain the durable source of truth. A successfully consumed wake file is
# removed, keeping the spool bounded instead of retaining an ever-growing
# historical seen-ID set.

import subprocess
import time
from pathlib import Path

EVENT_DIR = Path("/opt/wg-access/runtime/agent-trigger/events")
LEGACY_STATE_FILE = Path("/var/lib/wg-access-trigger-watch/seen-events.json")
LOG_PREFIX = "wg-access-trigger-watch"

POLL_INTERVAL = 1.0
COOLDOWN_SEC = 1.0
FAILURE_BACKOFF_SEC = 5.0


def log(msg: str) -> None:
    print(
        f"[{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}] "
        f"{LOG_PREFIX}: {msg}",
        flush=True,
    )


def list_events() -> list[Path]:
    try:
        return sorted(
            [p for p in EVENT_DIR.iterdir() if p.is_file()],
            key=lambda p: p.name,
        )
    except FileNotFoundError:
        EVENT_DIR.mkdir(parents=True, exist_ok=True)
        return []


def agent_is_active() -> bool:
    p = subprocess.run(
        ["systemctl", "is-active", "--quiet", "wg-access-agent.service"],
        check=False,
    )
    return p.returncode == 0


def start_agent(reason: str) -> bool:
    log(f"starting wg-access-agent.service reason={reason}")
    p = subprocess.run(
        ["systemctl", "start", "wg-access-agent.service"],
        text=True,
        capture_output=True,
        timeout=60,
    )
    if p.returncode == 0:
        log("wg-access-agent.service start requested OK")
        return True
    log(
        "wg-access-agent.service start failed "
        f"rc={p.returncode} stdout={p.stdout!r} stderr={p.stderr!r}"
    )
    return False


def consume_events(events: list[Path]) -> tuple[int, int]:
    removed = 0
    failed = 0
    for path in events:
        try:
            path.unlink()
            removed += 1
        except FileNotFoundError:
            # Another successful consumer/removal is equivalent to consumed.
            removed += 1
        except Exception as exc:
            failed += 1
            log(
                f"event remove failed path={path.name} "
                f"error={type(exc).__name__}: {exc}"
            )
    return removed, failed


def main() -> int:
    EVENT_DIR.mkdir(parents=True, exist_ok=True)

    if LEGACY_STATE_FILE.exists():
        try:
            LEGACY_STATE_FILE.unlink()
            log("legacy seen-events state removed; file spool is consume-on-success")
        except Exception as exc:
            log(
                "legacy state remove failed "
                f"error={type(exc).__name__}: {exc}"
            )

    last_start = 0.0
    active_logged = False

    while True:
        events = list_events()
        if not events:
            active_logged = False
            time.sleep(POLL_INTERVAL)
            continue

        # Do not consume a wake while an existing oneshot agent invocation is
        # still running. systemctl start on an already-active oneshot can return
        # successfully without scheduling a second invocation, which would lose
        # the wake for a job committed during that run.
        if agent_is_active():
            if not active_logged:
                log(
                    f"pending_events={len(events)} agent_active=1; "
                    "deferring consumption"
                )
                active_logged = True
            time.sleep(POLL_INTERVAL)
            continue

        active_logged = False
        now = time.monotonic()
        if now - last_start < COOLDOWN_SEC:
            time.sleep(POLL_INTERVAL)
            continue

        snapshot = list(events)
        log(f"new_events={len(snapshot)} first={snapshot[0].name}")
        if start_agent(reason=f"new_events={len(snapshot)}"):
            last_start = time.monotonic()
            removed, failed = consume_events(snapshot)
            log(
                f"consumed_events={removed} remove_failed={failed} "
                f"remaining_events={len(list_events())}"
            )
        else:
            last_start = time.monotonic()
            time.sleep(FAILURE_BACKOFF_SEC)

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        log("stopped")
        raise SystemExit(0)
    except Exception as exc:
        log(f"fatal: {type(exc).__name__}: {exc}")
        raise
