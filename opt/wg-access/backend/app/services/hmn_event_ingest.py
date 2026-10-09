"""B1B private ingestion core. No public routes, credentials or raw event logs.

A future scoped SSH forced-command bridge invokes this module on VM121.
All input is a closed schema; stdout contains counts only. No HMN endpoints,
peer identities, provider names or freeform reasons can reach persistence.
"""
from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timedelta, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import text
from app.db.session import SessionLocal

MAX_STDIN_BYTES = 65536
MAX_EVENTS = 128
MAX_UNKNOWN_PER_BATCH = 10000
RETENTION_DAYS = 90

HEALTH_TYPES = frozenset({
    "health_fail_first", "health_fail_threshold", "health_recovered",
    "repair_success", "repair_failed", "repair_suppressed_cooldown",
})
RECOVERY_TYPES = frozenset({"local_repair", "full_pool_refresh", "daily_quality", "other"})


def utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("UTC offset is mandatory")
    return value.astimezone(timezone.utc)


def canonical_sha(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


class Event(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    source_record_index: int = Field(ge=1, le=1_000_000_000_000)
    event_at_utc: datetime
    observed_at_utc: datetime
    event_type: str = Field(min_length=1, max_length=40)
    result: Literal["pass", "failed", "other", "na"]
    egress_slot: int | None = Field(default=None, ge=1, le=5)
    provenance: Literal["forward_live", "historical_retained_only"]

    @field_validator("event_at_utc", "observed_at_utc")
    @classmethod
    def check_utc(cls, value: datetime) -> datetime:
        return utc(value)


class Batch(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema_version: Literal[1]
    batch_id: str = Field(pattern=r"^[a-f0-9]{64}$")
    source_stream: Literal["health", "recovery"]
    source_generation: str = Field(pattern=r"^[a-f0-9]{32}$")
    source_coverage_epoch: str = Field(pattern=r"^[a-f0-9]{32}$")
    collected_at_utc: datetime
    continuity: Literal["continuous", "gap_detected", "initial_unknown", "stale", "error"]
    gap_first_observed_at: datetime | None = None
    gap_last_observed_at: datetime | None = None
    unknown_lines: int = Field(ge=0, le=MAX_UNKNOWN_PER_BATCH)
    heartbeat_count: int = Field(ge=0, le=MAX_UNKNOWN_PER_BATCH)
    events: list[Event] = Field(max_length=MAX_EVENTS)

    @field_validator("collected_at_utc", "gap_first_observed_at", "gap_last_observed_at")
    @classmethod
    def check_utc(cls, value: datetime | None) -> datetime | None:
        return None if value is None else utc(value)

    @model_validator(mode="after")
    def consistency(self) -> "Batch":
        now = datetime.now(timezone.utc)
        if not now - timedelta(days=RETENTION_DAYS) <= self.collected_at_utc <= now + timedelta(minutes=2):
            raise ValueError("collection timestamp out of bounds")
        if self.continuity == "gap_detected" and (self.gap_first_observed_at is None or self.gap_last_observed_at is None):
            raise ValueError("gap timestamps required")
        if (self.gap_first_observed_at is None) != (self.gap_last_observed_at is None):
            raise ValueError("gap timestamp pair must be complete")
        if self.gap_first_observed_at and not self.gap_first_observed_at <= self.gap_last_observed_at <= self.collected_at_utc:
            raise ValueError("gap timestamp ordering invalid")
        # Coverage freshness is based on collection time, not delayed replay receipt.
        allowed = HEALTH_TYPES if self.source_stream == "health" else RECOVERY_TYPES
        seen = set()
        for ev in self.events:
            if ev.event_type not in allowed:
                raise ValueError("event type not allowlisted for stream")
            if ev.source_record_index in seen:
                raise ValueError("duplicate record ordinal in batch")
            seen.add(ev.source_record_index)
            if ev.event_at_utc > now + timedelta(minutes=2):
                raise ValueError("event timestamp in future")
            if ev.event_at_utc < now - timedelta(days=RETENTION_DAYS):
                raise ValueError("event older than retention")
            if ev.observed_at_utc < ev.event_at_utc or ev.observed_at_utc > self.collected_at_utc + timedelta(minutes=2):
                raise ValueError("observation timestamp outside window")
            if self.source_stream == "health" and ev.egress_slot is None:
                raise ValueError("health event must identify slot")
        return self


def normalized(batch: Batch) -> dict:
    return batch.model_dump(mode="json", exclude={"batch_id"})


def event_hash(batch: Batch, ev: Event) -> tuple[str, str]:
    event_id = canonical_sha([batch.source_stream, batch.source_generation, ev.source_record_index])
    payload_hash = canonical_sha([batch.source_stream, batch.source_generation, ev.model_dump(mode="json")])
    return event_id, payload_hash


def ingest_batch(batch: Batch) -> dict[str, int | str]:
    now = datetime.now(timezone.utc)
    digest = canonical_sha(normalized(batch))
    inserted = 0
    with SessionLocal.begin() as db:
        claimed = db.execute(text("""
            INSERT INTO public.hmn_ingest_batch
            (batch_id,source_stream,payload_sha256,collected_at_utc,ingested_at_utc,accepted_events)
            VALUES (:id,:stream,:digest,:collected,:now,0)
            ON CONFLICT (batch_id) DO NOTHING RETURNING batch_id
        """), {"id": batch.batch_id, "stream": batch.source_stream, "digest": digest, "collected": batch.collected_at_utc, "now": now}).scalar_one_or_none()
        if claimed is None:
            existing = db.execute(text("SELECT payload_sha256 FROM public.hmn_ingest_batch WHERE batch_id=:id FOR UPDATE"), {"id": batch.batch_id}).scalar_one()
            if existing != digest:
                raise ValueError("batch identifier reused with different payload")
            return {"status": "duplicate", "events_added": 0}
        for ev in batch.events:
            event_id, payload_hash = event_hash(batch, ev)
            row = db.execute(text("""
                INSERT INTO public.hmn_event (
                    event_id,source_stream,source_generation,source_record_index,
                    source_coverage_epoch,event_at_utc,observed_at_utc,ingested_at_utc,
                    event_type,result,egress_slot,provenance,event_payload_sha256
                ) VALUES (
                    :id,:stream,:generation,:ordinal,:epoch,:event_at,:observed_at,:ingested,
                    :event_type,:result,:slot,:provenance,:payload_hash
                ) ON CONFLICT DO NOTHING RETURNING event_id
            """), {"id": event_id, "stream": batch.source_stream, "generation": batch.source_generation,
                   "ordinal": ev.source_record_index, "epoch": batch.source_coverage_epoch,
                   "event_at": ev.event_at_utc, "observed_at": ev.observed_at_utc,
                   "ingested": now, "event_type": ev.event_type, "result": ev.result,
                   "slot": ev.egress_slot, "provenance": ev.provenance, "payload_hash": payload_hash}).scalar_one_or_none()
            if row is None:
                known = db.execute(text("SELECT event_payload_sha256 FROM public.hmn_event WHERE event_id=:id"), {"id": event_id}).scalar_one_or_none()
                if known != payload_hash:
                    raise ValueError("source event ordinal collided with different payload")
            else:
                inserted += 1
        db.execute(text("UPDATE public.hmn_ingest_batch SET accepted_events=:n WHERE batch_id=:id"), {"n": inserted, "id": batch.batch_id})
        # A late/replayed collection may add events, but must never regress current coverage.
        # last_success_at records when the source was observed, never when replay arrived.
        latest = db.execute(text("SELECT last_attempt_at FROM public.hmn_stream_coverage WHERE source_stream=:stream FOR UPDATE"), {"stream": batch.source_stream}).scalar_one_or_none()
        if latest is None or batch.collected_at_utc >= latest:
            db.execute(text("""
                INSERT INTO public.hmn_stream_coverage AS c (
                    source_stream,last_attempt_at,last_success_at,continuity,last_coverage_epoch,
                    last_gap_first_at,last_gap_last_at,gap_count,unknown_lines_total,heartbeat_total,ingested_events_total
                ) VALUES (:stream,:collected,:observed_success,:continuity,:epoch,:gapfirst,:gaplast,:gaps,:unknown,:heartbeats,:events)
                ON CONFLICT (source_stream) DO UPDATE SET
                    last_attempt_at=EXCLUDED.last_attempt_at,
                    last_success_at=EXCLUDED.last_success_at,
                    continuity=EXCLUDED.continuity,
                    last_coverage_epoch=EXCLUDED.last_coverage_epoch,
                    last_gap_first_at=COALESCE(EXCLUDED.last_gap_first_at,c.last_gap_first_at),
                    last_gap_last_at=COALESCE(EXCLUDED.last_gap_last_at,c.last_gap_last_at),
                    gap_count=c.gap_count + EXCLUDED.gap_count,
                    unknown_lines_total=c.unknown_lines_total + EXCLUDED.unknown_lines_total,
                    heartbeat_total=c.heartbeat_total + EXCLUDED.heartbeat_total,
                    ingested_events_total=c.ingested_events_total + EXCLUDED.ingested_events_total
                WHERE c.last_attempt_at <= EXCLUDED.last_attempt_at
            """), {"stream": batch.source_stream, "collected": batch.collected_at_utc,
                   "observed_success": batch.collected_at_utc, "continuity": batch.continuity, "epoch": batch.source_coverage_epoch,
                   "gapfirst": batch.gap_first_observed_at, "gaplast": batch.gap_last_observed_at,
                   "gaps": int(batch.continuity == "gap_detected"), "unknown": batch.unknown_lines,
                   "heartbeats": batch.heartbeat_count, "events": inserted})
        else:
            db.execute(text("UPDATE public.hmn_stream_coverage SET ingested_events_total=ingested_events_total+:n WHERE source_stream=:stream"), {"n": inserted, "stream": batch.source_stream})
        cutoff = now - timedelta(days=RETENTION_DAYS)
        db.execute(text("DELETE FROM public.hmn_event WHERE event_at_utc < :cutoff"), {"cutoff": cutoff})
        db.execute(text("DELETE FROM public.hmn_ingest_batch WHERE ingested_at_utc < :cutoff"), {"cutoff": cutoff})
    return {"status": "accepted", "events_added": inserted}


def main() -> int:
    try:
        raw = sys.stdin.buffer.read(MAX_STDIN_BYTES + 1)
        if len(raw) > MAX_STDIN_BYTES:
            raise ValueError("batch too large")
        batch = Batch.model_validate_json(raw)
        result = ingest_batch(batch)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ValueError, UnicodeError) as exc:
        print("HMN_INGEST_REJECTED=invalid_batch", file=sys.stderr)
        return 2
    except Exception:
        # No raw payload, SQL, tokens or provider identities in logs.
        print("HMN_INGEST_UNAVAILABLE=storage_or_internal_error", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
