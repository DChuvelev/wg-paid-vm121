"""Admin-only diagnostic ZIP job state machine.

No outbound calls or shell execution from this module. The only producer is the
fixed operator worker CLI on VM121, invoked by VM130 over the existing admin path.
All DB changes are explicit; callers own commit/rollback.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
import io
import json
import uuid
import zipfile

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import AdminDiagnosticJob

MAX_ZIP_BYTES = 1_048_576
MAX_ZIP_UNCOMPRESSED = 2_000_000
MAX_REPORT_BYTES = 200_000
READY_TTL = timedelta(minutes=30)
QUEUED_TTL = timedelta(minutes=10)
WORKER_LEASE = timedelta(minutes=5)
REPEAT_COOLDOWN = timedelta(seconds=60)
ARCHIVE_MEMBERS = frozenset({"README.md", "report.md", "snapshot.json", "events.jsonl", "manifest.json"})
ACTIVE_STATES = ("queued", "running")
READY_STATES = ("ready", "partial")


class DiagnosticRejected(RuntimeError):
    pass


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def is_past(value: datetime, at: datetime) -> bool:
    """Handle SQLite offline fixtures that omit tzinfo; PG returns aware UTC."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value < at


def _public_cleanup(db: Session, at: datetime) -> None:
    """Expire abandoned work and discard bytes after deadline; no automatic retry."""
    db.execute(update(AdminDiagnosticJob)
               .where(AdminDiagnosticJob.state == "queued", AdminDiagnosticJob.expires_at < at)
               .values(state="failed", updated_at=at, error_code="QUEUE_TIMEOUT")
               .execution_options(synchronize_session=False))
    db.execute(update(AdminDiagnosticJob)
               .where(AdminDiagnosticJob.state == "running", AdminDiagnosticJob.lease_until < at)
               .values(state="failed", updated_at=at, error_code="WORKER_LEASE_TIMEOUT", lease_token=None)
               .execution_options(synchronize_session=False))
    db.execute(update(AdminDiagnosticJob)
               .where(AdminDiagnosticJob.state.in_(READY_STATES), AdminDiagnosticJob.expires_at < at)
               .values(state="expired", updated_at=at, artifact=None, artifact_size=None,
                       artifact_sha256=None, lease_token=None)
               .execution_options(synchronize_session=False))
    db.expire_all()
    # Cleanup history after one day; no ZIP persists beyond 30 minutes.
    db.query(AdminDiagnosticJob).filter(
        AdminDiagnosticJob.state.in_(("failed", "expired")),
        AdminDiagnosticJob.updated_at < at - timedelta(days=1),
    ).delete(synchronize_session=False)


def enqueue(db: Session) -> tuple[AdminDiagnosticJob, bool]:
    """Deduplicate concurrent clicks; DB partial unique index is final arbiter."""
    now = utcnow()
    _public_cleanup(db, now)
    active = db.scalar(select(AdminDiagnosticJob).where(AdminDiagnosticJob.state.in_(ACTIVE_STATES))
                       .order_by(AdminDiagnosticJob.created_at.desc()).limit(1))
    if active is not None:
        db.commit()
        return active, False
    recent = db.scalar(select(AdminDiagnosticJob)
                       .where(AdminDiagnosticJob.created_at >= now - REPEAT_COOLDOWN)
                       .order_by(AdminDiagnosticJob.created_at.desc()).limit(1))
    if recent is not None:
        db.commit()
        return recent, False
    job = AdminDiagnosticJob(
        id=uuid.uuid4(), state="queued", created_at=now, updated_at=now,
        expires_at=now + QUEUED_TTL,
    )
    db.add(job)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        active = db.scalar(select(AdminDiagnosticJob).where(AdminDiagnosticJob.state.in_(ACTIVE_STATES)).limit(1))
        if active is None:
            raise
        return active, False
    return job, True


def claim(db: Session) -> tuple[uuid.UUID, uuid.UUID] | None:
    now = utcnow()
    _public_cleanup(db, now)
    job = db.scalar(select(AdminDiagnosticJob)
                    .where(AdminDiagnosticJob.state == "queued")
                    .order_by(AdminDiagnosticJob.created_at)
                    .with_for_update(skip_locked=True).limit(1))
    if job is None:
        db.commit()
        return None
    token = uuid.uuid4()
    job.state = "running"
    job.started_at = now
    job.updated_at = now
    job.lease_token = token
    job.lease_until = now + WORKER_LEASE
    job.expires_at = job.lease_until
    db.commit()
    return job.id, token


def _validate_zip(payload: bytes) -> tuple[str, str]:
    if not (0 < len(payload) <= MAX_ZIP_BYTES):
        raise DiagnosticRejected("ZIP_SIZE_INVALID")
    if not zipfile.is_zipfile(io.BytesIO(payload)):
        raise DiagnosticRejected("ZIP_INVALID")
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        members = archive.infolist()
        if len(members) != len(ARCHIVE_MEMBERS) or {i.filename for i in members} != ARCHIVE_MEMBERS:
            raise DiagnosticRejected("ZIP_MEMBER_ALLOWLIST")
        if any(i.is_dir() or i.flag_bits & 1 or i.file_size > MAX_REPORT_BYTES or i.compress_size > MAX_ZIP_BYTES for i in members):
            raise DiagnosticRejected("ZIP_MEMBER_INVALID")
        if sum(i.file_size for i in members) > MAX_ZIP_UNCOMPRESSED:
            raise DiagnosticRejected("ZIP_UNCOMPRESSED_LIMIT")
        try:
            raw = {item.filename: archive.read(item) for item in members}
            manifest = json.loads(raw["manifest.json"])
            snapshot = json.loads(raw["snapshot.json"])
        except (OSError, RuntimeError, ValueError, KeyError, UnicodeError, zipfile.BadZipFile) as exc:
            raise DiagnosticRejected("ZIP_CONTENT_INVALID") from exc
        if not isinstance(manifest, dict) or not isinstance(snapshot, dict):
            raise DiagnosticRejected("ZIP_SCHEMA_INVALID")
        hashes = manifest.get("files")
        if not isinstance(hashes, dict) or set(hashes) != ARCHIVE_MEMBERS - {"manifest.json"}:
            raise DiagnosticRejected("ZIP_MANIFEST_INVALID")
        for name, data in raw.items():
            if name == "manifest.json":
                continue
            check = hashes[name]
            if not isinstance(check, dict) or check.get("sha256") != sha256(data).hexdigest() or check.get("bytes") != len(data):
                raise DiagnosticRejected("ZIP_HASH_MISMATCH")
        if snapshot.get("synthetic_fixture") is True:
            raise DiagnosticRejected("ZIP_SYNTHETIC_REFUSED")
        if not isinstance(snapshot.get("schema_version"), str) or not snapshot["schema_version"].startswith("wg-paid-b4-"):
            raise DiagnosticRejected("ZIP_SCHEMA_UNEXPECTED")
        if not isinstance(manifest.get("schema_version"), str) or not manifest["schema_version"].startswith("wg-paid-b4-"):
            raise DiagnosticRejected("ZIP_SCHEMA_UNEXPECTED")
        status = snapshot.get("capture_status")
        if status not in ("complete_for_review_scope", "complete", "partial"):
            raise DiagnosticRejected("ZIP_STATUS_INVALID")
        # Do not confuse a completed *capture* with a guarantee the network is healthy.
        return sha256(payload).hexdigest(), status


def finalize(db: Session, job_id: uuid.UUID, lease_token: uuid.UUID, payload: bytes) -> str:
    digest, capture_status = _validate_zip(payload)
    now = utcnow()
    job = db.scalar(select(AdminDiagnosticJob).where(AdminDiagnosticJob.id == job_id).with_for_update())
    if job is None or job.state != "running" or job.lease_token != lease_token or job.lease_until is None or is_past(job.lease_until, now):
        db.rollback()
        raise DiagnosticRejected("LEASE_INVALID")
    job.state = "ready" if capture_status == "complete" else "partial"
    job.capture_status = capture_status
    job.artifact = payload
    job.artifact_size = len(payload)
    job.artifact_sha256 = digest
    job.completed_at = now
    job.updated_at = now
    job.expires_at = now + READY_TTL
    job.lease_until = None
    job.lease_token = None
    db.commit()
    return job.state


def fail(db: Session, job_id: uuid.UUID, lease_token: uuid.UUID, code: str) -> None:
    if code not in {"COLLECTOR_FAILED", "COLLECTOR_TIMEOUT", "ZIP_INVALID", "SOURCE_UNAVAILABLE"}:
        raise DiagnosticRejected("ERROR_CODE_INVALID")
    now = utcnow()
    job = db.scalar(select(AdminDiagnosticJob).where(AdminDiagnosticJob.id == job_id).with_for_update())
    if job is None or job.state != "running" or job.lease_token != lease_token or job.lease_until is None or is_past(job.lease_until, now):
        db.rollback()
        raise DiagnosticRejected("LEASE_INVALID")
    job.state = "failed"
    job.error_code = code
    job.updated_at = now
    job.lease_token = None
    job.lease_until = None
    db.commit()


def get_visible(db: Session, job_id: uuid.UUID) -> AdminDiagnosticJob | None:
    job = db.get(AdminDiagnosticJob, job_id)
    return job
