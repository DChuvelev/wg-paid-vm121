# STEP_042G_RELIABLE_EVENT_TRIGGER_DIR_SPOOL
from pathlib import Path
import os
import time
import uuid

def trigger_wg_access_agent_best_effort() -> None:
    """Best-effort host systemd.path trigger.

    The DB provisioning_jobs table remains the source of truth.
    This function creates a unique event file so systemd can observe a
    directory modification even if repeated writes to one file are coalesced.
    """
    try:
        trigger_dir = Path("/opt/wg-access/runtime/agent-trigger")
        event_dir = trigger_dir / "events"
        event_dir.mkdir(parents=True, exist_ok=True)

        now_ns = time.time_ns()
        event_path = event_dir / f"event-{now_ns}-{uuid.uuid4().hex}.trigger"
        event_path.write_text(str(now_ns) + "\n", encoding="utf-8")

        # Backward-compatible marker for human diagnostics.
        pending_path = trigger_dir / "pending.trigger"
        pending_path.write_text(str(now_ns) + "\n", encoding="utf-8")

        try:
            os.chmod(event_path, 0o664)
            os.chmod(pending_path, 0o664)
        except Exception:
            pass
    except Exception:
        # Provisioning job creation must not fail because the wakeup hint failed.
        pass
