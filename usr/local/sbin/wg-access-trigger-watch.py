#!/usr/bin/env python3
# STEP_042I host-side event watcher for WG Access agent
#
# Backend/container writes unique files into:
#   /opt/wg-access/runtime/agent-trigger/events/
#
# This host-side service polls that directory and starts wg-access-agent.service
# on new event files. DB provisioning_jobs remains the source of truth.

import json
import os
import subprocess
import sys
import time
from pathlib import Path

EVENT_DIR = Path("/opt/wg-access/runtime/agent-trigger/events")
STATE_DIR = Path("/var/lib/wg-access-trigger-watch")
STATE_FILE = STATE_DIR / "seen-events.json"
LOG_PREFIX = "wg-access-trigger-watch"

POLL_INTERVAL = 1.0
COOLDOWN_SEC = 1.0
MAX_SEEN = 5000

def log(msg: str) -> None:
    print(f"[{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}] {LOG_PREFIX}: {msg}", flush=True)

def load_seen() -> set[str]:
    try:
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return set(str(x) for x in data)
    except Exception:
        pass
    return set()

def save_seen(seen: set[str]) -> None:
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        items = sorted(seen)[-MAX_SEEN:]
        tmp = STATE_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(items, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        tmp.replace(STATE_FILE)
    except Exception as e:
        log(f"state save failed: {type(e).__name__}: {e}")

def event_id(path: Path) -> str:
    try:
        st = path.stat()
        return f"{path.name}:{st.st_ino}:{st.st_mtime_ns}:{st.st_size}"
    except FileNotFoundError:
        return path.name + ":missing"

def list_events() -> list[Path]:
    try:
        return sorted([p for p in EVENT_DIR.iterdir() if p.is_file()], key=lambda p: p.name)
    except FileNotFoundError:
        EVENT_DIR.mkdir(parents=True, exist_ok=True)
        return []

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
    log(f"wg-access-agent.service start failed rc={p.returncode} stdout={p.stdout!r} stderr={p.stderr!r}")
    return False

def main() -> int:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    EVENT_DIR.mkdir(parents=True, exist_ok=True)

    seen = load_seen()
    if not seen:
        # On first install, mark old files as seen so stale events do not replay.
        for p in list_events():
            seen.add(event_id(p))
        save_seen(seen)
        log(f"initialized seen set with existing_events={len(seen)}")
    else:
        log(f"loaded seen_events={len(seen)}")

    last_start = 0.0

    while True:
        new_ids = []
        for p in list_events():
            eid = event_id(p)
            if eid not in seen:
                seen.add(eid)
                new_ids.append(eid)

        if new_ids:
            log(f"new_events={len(new_ids)} first={new_ids[0]}")
            now = time.monotonic()
            if now - last_start >= COOLDOWN_SEC:
                if start_agent(reason=f"new_events={len(new_ids)}"):
                    last_start = now
            else:
                log("cooldown active, event recorded but start suppressed")
            save_seen(seen)

        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        log("stopped")
        raise SystemExit(0)
    except Exception as e:
        log(f"fatal: {type(e).__name__}: {e}")
        raise
