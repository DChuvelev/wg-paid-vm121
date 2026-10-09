"""Best-effort, anonymous, minute-bucket runtime observability.

No identifiers, addresses or keys are written to the activity history. The
existing authenticated runtime snapshot remains authoritative and must never
fail because this optional recorder is unavailable.
"""
from __future__ import annotations

import logging
import math
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from threading import Lock, Thread
from queue import Empty, Full, Queue
from typing import Any
from uuid import UUID

from sqlalchemy import select, text

from app.db.session import SessionLocal
from app.models import ConnectionProfile, ConnectionSlot

LOGGER = logging.getLogger(__name__)
SCHEMA_VERSION = 1
KEEP_MINUTES = 48 * 60
MAX_AGE_SECONDS = 120
MAX_FUTURE_SECONDS = 60
SELECTORS = ("cs1", "cs2", "cs3", "cs4", "cs5")
_lock = Lock()
_current: MinuteBucket | None = None
_last_persisted: datetime | None = None
_last_warning_at = 0.0
_activity_queue: Queue[tuple[dict[str, Any], datetime]] = Queue(maxsize=1)
_worker_thread: Thread | None = None
_worker_start_lock = Lock()


@dataclass
class MinuteBucket:
    minute: datetime
    first_received_at: datetime
    last_received_at: datetime
    sample_count: int = 0
    valid_count: int = 0
    expected_count: int = 0
    observed_seconds: float = 0.0
    config_total: int = 0
    user_total: int = 0
    config_peak: int = 0
    user_peak: int = 0
    selector_total: Counter[str] = field(default_factory=Counter)
    selector_peak: Counter[str] = field(default_factory=Counter)
    unmatched_total: int = 0
    conflicted_total: int = 0
    seen_generated: set[datetime] = field(default_factory=set)


def minute_start(now: datetime) -> datetime:
    return now.astimezone(timezone.utc).replace(second=0, microsecond=0)


def summarize_rows(rows: list[dict[str, Any]], mappings: dict[UUID, tuple[UUID, UUID, str, UUID]]) -> dict[str, Any] | None:
    """map: profile_id -> (slot_id, user_id, protocol, profile_owner_id).

    The collector sends both WG and AWG siblings; one slot is counted once.
    A contradictory active slot is excluded from occupancy rather than guessed.
    """
    if not rows:
        return None  # An empty/failed collector snapshot is not confirmed zero.
    active_slots: dict[UUID, tuple[UUID, str]] = {}
    conflict_slots: set[UUID] = set()
    unmatched = 0
    for row in rows:
        mapped = mappings.get(row.get("profile_id"))
        if mapped is None:
            unmatched += 1
            continue
        slot_id, user_id, protocol, owner_id = mapped
        if protocol != row.get("protocol") or user_id != owner_id:
            unmatched += 1
            continue
        if not row.get("active_now"):
            continue
        selector = row.get("selector")
        if selector not in SELECTORS:
            unmatched += 1
            continue
        prev = active_slots.get(slot_id)
        if prev is not None and prev != (user_id, selector):
            conflict_slots.add(slot_id)
            continue
        active_slots[slot_id] = (user_id, selector)
    for slot_id in conflict_slots:
        active_slots.pop(slot_id, None)
    per_selector = Counter(s for _, s in active_slots.values())
    return {
        "configurations": len(active_slots),
        "users": len({u for u, _ in active_slots.values()}),
        "selector": {k: int(per_selector[k]) for k in SELECTORS},
        "unmatched": unmatched,
        "conflicts": len(conflict_slots),
        "partial": bool(unmatched or conflict_slots),
    }


def _read_mappings(rows: list[dict[str, Any]]) -> dict[UUID, tuple[UUID, UUID, str, UUID]]:
    profile_ids = {r.get("profile_id") for r in rows if isinstance(r.get("profile_id"), UUID)}
    if not profile_ids:
        return {}
    with SessionLocal() as db:
        query = (
            select(ConnectionProfile.id, ConnectionProfile.connection_slot_id,
                   ConnectionProfile.protocol, ConnectionProfile.user_id,
                   ConnectionSlot.user_id)
            .join(ConnectionSlot, ConnectionSlot.id == ConnectionProfile.connection_slot_id)
            .where(ConnectionProfile.id.in_(profile_ids))
            .where(ConnectionProfile.disabled_at.is_(None))
            .where(ConnectionSlot.disabled_at.is_(None))
        )
        return {profile_id: (slot_id, slot_owner, protocol, profile_owner)
                for profile_id, slot_id, protocol, profile_owner, slot_owner
                in db.execute(query).all()}


def _record(bucket: MinuteBucket, received_at: datetime, generated_at: datetime,
            interval: float, result: dict[str, Any] | None) -> None:
    if generated_at in bucket.seen_generated:
        return  # Agent retry/replay must not inflate coverage.
    bucket.seen_generated.add(generated_at)
    bucket.last_received_at = received_at
    bucket.sample_count += 1
    bucket.expected_count = max(bucket.expected_count, math.ceil(60 / interval))
    if result is None:
        return
    bucket.valid_count += 1
    bucket.observed_seconds = min(60.0, bucket.observed_seconds + min(interval, 60.0))
    bucket.config_total += result["configurations"]
    bucket.user_total += result["users"]
    bucket.config_peak = max(bucket.config_peak, result["configurations"])
    bucket.user_peak = max(bucket.user_peak, result["users"])
    bucket.unmatched_total += result["unmatched"]
    bucket.conflicted_total += result["conflicts"]
    for selector in SELECTORS:
        count = result["selector"][selector]
        bucket.selector_total[selector] += count
        bucket.selector_peak[selector] = max(bucket.selector_peak[selector], count)


def _persist(bucket: MinuteBucket) -> None:
    """Single upsert attempt per completed minute. DO NOTHING preserves a prior
    partial bucket after process restart, rather than fabricating full coverage.
    """
    valid = bucket.valid_count
    coverage = round(min(1.0, bucket.observed_seconds / 60.0), 6)
    status = "unknown" if valid == 0 else ("complete" if coverage >= 0.999999 and not bucket.unmatched_total and not bucket.conflicted_total else "partial")
    fields = {
        "minute": bucket.minute,
        "sample_count": bucket.sample_count,
        "valid": valid,
        "expected": bucket.expected_count,
        "coverage": coverage,
        "status": status,
        "config_peak": bucket.config_peak if valid else None,
        "config_mean": bucket.config_total / valid if valid else None,
        "user_peak": bucket.user_peak if valid else None,
        "user_mean": bucket.user_total / valid if valid else None,
        "selector_peak": {s: int(bucket.selector_peak[s]) for s in SELECTORS},
        "selector_mean": {s: round(bucket.selector_total[s] / valid, 4) if valid else None for s in SELECTORS},
        "unmatched": bucket.unmatched_total,
        "conflicted": bucket.conflicted_total,
        "first": bucket.first_received_at,
        "last": bucket.last_received_at,
        "version": SCHEMA_VERSION,
    }
    import json
    fields["selector_peak"] = json.dumps(fields["selector_peak"])
    fields["selector_mean"] = json.dumps(fields["selector_mean"])
    sql = text("""
        INSERT INTO public.runtime_activity_minute (
            minute_utc,sample_count,valid_sample_count,expected_sample_count,
            coverage_ratio,coverage_status,active_configurations_peak,
            active_configurations_mean,active_users_peak,active_users_mean,
            selector_peak,selector_mean,unmatched_rows_total,conflicted_slots_total,
            first_received_at,last_received_at,schema_version
        ) VALUES (
            :minute,:sample_count,:valid,:expected,:coverage,:status,:config_peak,
            :config_mean,:user_peak,:user_mean,CAST(:selector_peak AS jsonb),
            CAST(:selector_mean AS jsonb),:unmatched,:conflicted,:first,:last,:version
        ) ON CONFLICT (minute_utc) DO NOTHING
    """)
    fields["sample_count"] = bucket.sample_count
    with SessionLocal.begin() as db:
        db.execute(sql, fields)
        # Once-daily bounded retention, in the same minute-boundary transaction.
        if bucket.minute.hour == 0 and bucket.minute.minute == 0:
            db.execute(text("DELETE FROM public.runtime_activity_minute WHERE minute_utc < :cutoff"),
                       {"cutoff": bucket.minute - timedelta(minutes=KEEP_MINUTES)})


def _bounded_warning(message: str, exc: Exception) -> None:
    """Prevent an unavailable optional observer from filling backend journals."""
    global _last_warning_at
    now = time.monotonic()
    if now - _last_warning_at >= 300:
        _last_warning_at = now
        LOGGER.warning("%s: %s", message, type(exc).__name__)


def _process_runtime_activity(snapshot: dict[str, Any], received_at: datetime) -> None:
    """Background best-effort observer; one bounded database read per snapshot.

    Bad samples, slow PostgreSQL or a restart can lose observation coverage,
    never the accepted runtime snapshot. DB writes happen at minute rollover.
    """
    global _current, _last_persisted
    try:
        rows = snapshot.get("rows", [])
        generated = snapshot.get("generated_at")
        interval = float(snapshot.get("sample_interval_seconds", 5))
        if not isinstance(generated, datetime) or generated.tzinfo is None:
            return
        if not (0 < interval <= 60):
            return
        gap = (received_at - generated).total_seconds()
        result = None
        if -MAX_FUTURE_SECONDS <= gap <= MAX_AGE_SECONDS and isinstance(rows, list) and rows:
            result = summarize_rows(rows, _read_mappings(rows))
        bucket_minute = minute_start(received_at)
        with _lock:
            if _current is None:
                _current = MinuteBucket(bucket_minute, received_at, received_at)
            if bucket_minute < _current.minute:
                return  # Clock reversal cannot amend already-finalized buckets.
            if bucket_minute > _current.minute:
                previous = _current
                _current = MinuteBucket(bucket_minute, received_at, received_at)
                if previous.minute != _last_persisted:
                    # bounded one attempt, no unbounded retry queue
                    _last_persisted = previous.minute
                    try:
                        _persist(previous)
                    except Exception as exc:
                        _bounded_warning("runtime_activity minute persistence unavailable", exc)
            _record(_current, received_at, generated, interval, result)
    except Exception as exc:
        _bounded_warning("runtime_activity sampling unavailable", exc)


def _activity_worker() -> None:
    while True:
        # One daemon worker per backend process; bounded queue prevents backlog.
        snapshot, received_at = _activity_queue.get()
        try:
            _process_runtime_activity(snapshot, received_at)
        finally:
            _activity_queue.task_done()


def observe_runtime_activity(snapshot: dict[str, Any], received_at: datetime) -> None:
    """Non-blocking optional hook after accepted runtime snapshot replacement.

    No DB, locks or SSH operations execute on the Agent request path.
    A slow/failed observer is represented as missing coverage, not backpressure.
    """
    global _worker_thread
    try:
        if _worker_thread is None or not _worker_thread.is_alive():
            with _worker_start_lock:
                if _worker_thread is None or not _worker_thread.is_alive():
                    _worker_thread = Thread(target=_activity_worker, name="runtime-activity-observer", daemon=True)
                    _worker_thread.start()
        _activity_queue.put_nowait((snapshot, received_at))
    except Full:
        pass  # Drop optional monitoring sample rather than delay runtime ingest.
    except Exception as exc:
        _bounded_warning("runtime_activity enqueue unavailable", exc)
