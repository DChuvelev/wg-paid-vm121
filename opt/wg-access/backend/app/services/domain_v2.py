from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import uuid

from email_validator import EmailNotValidError, validate_email
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import (
    AccessGrant,
    AccessGrantProtocolLimit,
    AuditEvent,
    ConnectionProfile,
    Plan,
    ProvisioningJob,
    User,
)

SUPPORTED_PROTOCOLS = frozenset({"wireguard", "amneziawg"})
PROFILE_QUOTA_STATUSES = ("requested", "provisioning", "active")


class DomainV2Error(RuntimeError):
    pass


class InvalidIdentity(DomainV2Error):
    pass


class GrantInactive(DomainV2Error):
    pass


class ProtocolNotAllowed(DomainV2Error):
    pass


class ProtocolQuotaExceeded(DomainV2Error):
    pass


@dataclass(frozen=True)
class ProfileRequestResult:
    profile: ConnectionProfile
    job: ProvisioningJob
    created_job: bool


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def normalize_email(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise InvalidIdentity("email is required")
    try:
        normalized = validate_email(text, check_deliverability=False).normalized
    except EmailNotValidError as exc:
        raise InvalidIdentity("invalid email") from exc
    # Product identity is deliberately case-insensitive for both local and
    # domain parts. Do not add provider-specific dot/plus rewriting.
    return normalized.casefold()


def ensure_verified_user(
    db: Session,
    email: str,
    *,
    verified_at: datetime | None = None,
) -> User:
    normalized = normalize_email(email)
    row = db.execute(
        select(User).where(User.email == normalized).with_for_update()
    ).scalar_one_or_none()
    if row is not None:
        if row.email_verified_at is None:
            raise InvalidIdentity("existing user is not verified")
        return row

    row = User(
        id=uuid.uuid4(),
        email=normalized,
        email_verified_at=verified_at or utcnow(),
    )
    db.add(row)
    try:
        db.flush()
    except IntegrityError as exc:
        raise InvalidIdentity("normalized email already exists") from exc
    return row


def grant_is_active(grant: AccessGrant, *, now: datetime | None = None) -> bool:
    point = now or utcnow()
    if grant.status != "active":
        return False
    if grant.valid_from > point:
        return False
    if grant.valid_until is not None and grant.valid_until <= point:
        return False
    return True


def create_grant_from_plan(
    db: Session,
    *,
    user: User,
    plan: Plan,
    source_type: str,
    source_ref: str | None,
    valid_from: datetime,
    valid_until: datetime | None,
) -> AccessGrant:
    if not plan.active:
        raise GrantInactive("plan is inactive")
    grant = AccessGrant(
        id=uuid.uuid4(),
        user_id=user.id,
        plan_id=plan.id,
        status="active",
        source_type=source_type,
        source_ref=source_ref,
        valid_from=valid_from,
        valid_until=valid_until,
    )
    db.add(grant)
    db.flush()
    db.add_all(
        [
            AccessGrantProtocolLimit(
                access_grant_id=grant.id,
                protocol="wireguard",
                profile_limit=plan.default_wireguard_limit,
            ),
            AccessGrantProtocolLimit(
                access_grant_id=grant.id,
                protocol="amneziawg",
                profile_limit=plan.default_amneziawg_limit,
            ),
        ]
    )
    db.flush()
    return grant


def protocol_limit(
    db: Session,
    *,
    grant_id: uuid.UUID,
    protocol: str,
) -> AccessGrantProtocolLimit:
    if protocol not in SUPPORTED_PROTOCOLS:
        raise ProtocolNotAllowed(protocol)
    row = db.execute(
        select(AccessGrantProtocolLimit).where(
            AccessGrantProtocolLimit.access_grant_id == grant_id,
            AccessGrantProtocolLimit.protocol == protocol,
        )
    ).scalar_one_or_none()
    if row is None:
        raise ProtocolNotAllowed(f"grant has no {protocol} limit")
    return row


def enqueue_profile_job(
    db: Session,
    *,
    profile: ConnectionProfile,
    action: str,
    operation_id: str,
    desired_generation: str,
    payload: dict | None = None,
) -> tuple[ProvisioningJob, bool]:
    existing = db.execute(
        select(ProvisioningJob).where(ProvisioningJob.operation_id == operation_id)
    ).scalar_one_or_none()
    if existing is not None:
        if existing.connection_profile_id != profile.id or existing.action != action:
            raise DomainV2Error("operation_id collision")
        return existing, False

    job = ProvisioningJob(
        id=uuid.uuid4(),
        node_id=profile.node_id,
        action=action,
        peer_id=None,
        connection_profile_id=profile.id,
        operation_id=operation_id,
        desired_generation=desired_generation,
        next_attempt_at=None,
        payload_json=dict(payload or {}),
        status="pending",
        attempts=0,
    )
    db.add(job)
    db.flush()
    return job, True


def create_profile_request(
    db: Session,
    *,
    user: User,
    grant_id: uuid.UUID,
    protocol: str,
    node_id: str,
    label: str | None = None,
    now: datetime | None = None,
) -> ProfileRequestResult:
    if protocol not in SUPPORTED_PROTOCOLS:
        raise ProtocolNotAllowed(protocol)
    point = now or utcnow()

    grant = db.execute(
        select(AccessGrant)
        .where(AccessGrant.id == grant_id)
        .with_for_update()
    ).scalar_one_or_none()
    if grant is None or grant.user_id != user.id or not grant_is_active(grant, now=point):
        raise GrantInactive("grant is unavailable")

    limit_row = protocol_limit(db, grant_id=grant.id, protocol=protocol)
    current_count = db.execute(
        select(func.count(ConnectionProfile.id)).where(
            ConnectionProfile.access_grant_id == grant.id,
            ConnectionProfile.protocol == protocol,
            ConnectionProfile.status.in_(PROFILE_QUOTA_STATUSES),
        )
    ).scalar_one()
    if current_count >= limit_row.profile_limit:
        raise ProtocolQuotaExceeded(protocol)

    profile = ConnectionProfile(
        id=uuid.uuid4(),
        user_id=user.id,
        access_grant_id=grant.id,
        protocol=protocol,
        node_id=node_id,
        label=label,
        status="requested",
        expires_at=grant.valid_until,
    )
    db.add(profile)
    db.flush()

    desired_generation = hashlib.sha256(
        f"{profile.id}|{profile.protocol}|requested|1".encode("utf-8")
    ).hexdigest()[:32]
    operation_id = f"profile-provision:{profile.id}:r1"
    job, created = enqueue_profile_job(
        db,
        profile=profile,
        action="provision_profile",
        operation_id=operation_id,
        desired_generation=desired_generation,
        payload={"profile_id": str(profile.id), "protocol": protocol},
    )
    return ProfileRequestResult(profile=profile, job=job, created_job=created)


def record_audit_event(
    db: Session,
    *,
    event_type: str,
    actor_kind: str,
    actor_user_id: uuid.UUID | None = None,
    object_type: str | None = None,
    object_id: str | None = None,
    request_id: str | None = None,
    payload: dict | None = None,
) -> AuditEvent:
    row = AuditEvent(
        id=uuid.uuid4(),
        occurred_at=utcnow(),
        actor_user_id=actor_user_id,
        actor_kind=actor_kind,
        event_type=event_type,
        object_type=object_type,
        object_id=object_id,
        request_id=request_id,
        payload_json=dict(payload or {}),
    )
    db.add(row)
    db.flush()
    return row
