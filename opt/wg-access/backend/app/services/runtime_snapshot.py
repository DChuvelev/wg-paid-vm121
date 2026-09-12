from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from threading import Lock
from typing import Any

_lock = Lock()
_latest: dict[str, Any] | None = None
_received_at: datetime | None = None


def replace_runtime_snapshot(snapshot: dict[str, Any]) -> datetime:
    global _latest, _received_at
    received_at = datetime.now(timezone.utc)
    with _lock:
        _latest = deepcopy(snapshot)
        _received_at = received_at
    return received_at


def get_runtime_snapshot() -> tuple[dict[str, Any] | None, datetime | None]:
    with _lock:
        return deepcopy(_latest), _received_at


def clear_runtime_snapshot_for_test() -> None:
    global _latest, _received_at
    with _lock:
        _latest = None
        _received_at = None
