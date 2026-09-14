from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import os
import uuid

from email_validator import EmailNotValidError, validate_email
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import (
    AccessGrant,
    AccessGrantProtocolLimit,
    AuditEvent,
    ConnectionSlot,
    ConnectionProfile,
    Peer,
    PeerCredential,
    Plan,
    ProvisioningJob,
    User,
)

SUPPORTED_PROTOCOLS = frozenset({"wireguard", "amneziawg"})
PROFILE_QUOTA_STATUSES = ("requested", "provisioning", "active", "disabling", "provisioning_failed")
WIREGUARD_RUNTIME_PROTOCOL = "wireguard"
AMNEZIAWG_RUNTIME_PROTOCOL = "amneziawg"


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


@dataclass(frozen=True)
class ConfigurationRequestResult:
    slot: ConnectionSlot
    profiles: dict[str, ConnectionProfile]
    jobs: dict[str, ProvisioningJob]
    created_jobs: dict[str, bool]


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
    slot_limit = int(plan.default_wireguard_limit)
    db.add_all(
        [
            AccessGrantProtocolLimit(
                access_grant_id=grant.id,
                protocol="wireguard",
                profile_limit=slot_limit,
            ),
            AccessGrantProtocolLimit(
                access_grant_id=grant.id,
                protocol="amneziawg",
                profile_limit=slot_limit,
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


def mirrored_configuration_limit(
    db: Session,
    *,
    grant_id: uuid.UUID,
    for_update: bool = False,
) -> int:
    query = select(AccessGrantProtocolLimit).where(
        AccessGrantProtocolLimit.access_grant_id == grant_id,
        AccessGrantProtocolLimit.protocol.in_(SUPPORTED_PROTOCOLS),
    )
    if for_update:
        query = query.with_for_update()
    rows = db.execute(query).scalars().all()
    by_protocol = {row.protocol: row for row in rows}
    if set(by_protocol) != set(SUPPORTED_PROTOCOLS):
        raise ProtocolNotAllowed("grant protocol-limit mirror is incomplete")
    wg = int(by_protocol[WIREGUARD_RUNTIME_PROTOCOL].profile_limit)
    awg = int(by_protocol[AMNEZIAWG_RUNTIME_PROTOCOL].profile_limit)
    if wg != awg:
        raise DomainV2Error("grant protocol-limit mirror drift")
    return wg


def logical_slot_count(
    db: Session,
    *,
    grant_id: uuid.UUID,
    user_id: uuid.UUID | None = None,
) -> int:
    query = select(func.count(ConnectionSlot.id)).where(
        ConnectionSlot.access_grant_id == grant_id,
        ConnectionSlot.disabled_at.is_(None),
    )
    if user_id is not None:
        query = query.where(ConnectionSlot.user_id == user_id)
    return int(db.execute(query).scalar_one())


def _allocator_lock_key(node_id: str, protocol: str) -> int:
    raw = hashlib.sha256(f"wg-paid/domain-v2/ip-allocator/{node_id}/{protocol}".encode("utf-8")).digest()[:8]
    value = int.from_bytes(raw, "big", signed=False)
    return value if value < (1 << 63) else value - (1 << 64)


def reserve_wireguard_tunnel_ip(db: Session, *, profile: ConnectionProfile) -> str:
    """Reserve a unique WireGuard tunnel IP inside the caller transaction.

    The PostgreSQL advisory transaction lock serializes allocation even when the
    profile table is empty. Legacy enabled peers are also treated as reservations
    so Domain V2 cannot collide with an existing VM100 identity.
    """
    if profile.protocol != WIREGUARD_RUNTIME_PROTOCOL:
        raise ProtocolNotAllowed("runtime allocation is currently enabled only for wireguard")
    if profile.tunnel_ip:
        return profile.tunnel_ip

    db.execute(
        text("SELECT pg_advisory_xact_lock(:key)"),
        {"key": _allocator_lock_key(profile.node_id, profile.protocol)},
    )

    from app.services.wireguard import iter_wireguard_client_ips

    used_profiles = set(
        db.execute(
            select(ConnectionProfile.tunnel_ip).where(
                ConnectionProfile.node_id == profile.node_id,
                ConnectionProfile.tunnel_ip.is_not(None),
                ConnectionProfile.id != profile.id,
            )
        ).scalars().all()
    )
    used_legacy = set(
        db.execute(
            select(Peer.tunnel_ip).where(
                Peer.node_id == profile.node_id,
                Peer.enabled.is_(True),
            )
        ).scalars().all()
    )
    used = used_profiles | used_legacy

    for candidate in iter_wireguard_client_ips():
        if candidate in used:
            continue
        profile.tunnel_ip = candidate
        profile.tunnel_ip_reserved_at = utcnow()
        profile.tunnel_ip_released_at = None
        db.flush()
        return candidate
    raise DomainV2Error("wireguard tunnel IP pool exhausted")


def reserve_amneziawg_tunnel_ip(db: Session, *, profile: ConnectionProfile) -> str:
    """Reserve a unique AmneziaWG tunnel IP inside the caller transaction."""
    if profile.protocol != AMNEZIAWG_RUNTIME_PROTOCOL:
        raise ProtocolNotAllowed("profile is not amneziawg")
    if profile.tunnel_ip:
        return profile.tunnel_ip

    db.execute(
        text("SELECT pg_advisory_xact_lock(:key)"),
        {"key": _allocator_lock_key(profile.node_id, profile.protocol)},
    )

    from app.services.amneziawg import iter_amneziawg_client_ips

    used_profiles = set(
        db.execute(
            select(ConnectionProfile.tunnel_ip).where(
                ConnectionProfile.node_id == profile.node_id,
                ConnectionProfile.tunnel_ip.is_not(None),
                ConnectionProfile.id != profile.id,
            )
        ).scalars().all()
    )

    for candidate in iter_amneziawg_client_ips():
        if candidate in used_profiles:
            continue
        profile.tunnel_ip = candidate
        profile.tunnel_ip_reserved_at = utcnow()
        profile.tunnel_ip_released_at = None
        db.flush()
        return candidate
    raise DomainV2Error("amneziawg tunnel IP pool exhausted")


def current_profile_credential(db: Session, *, profile_id: uuid.UUID) -> PeerCredential:
    row = db.execute(
        select(PeerCredential)
        .where(
            PeerCredential.connection_profile_id == profile_id,
            PeerCredential.revoked_at.is_(None),
        )
        .order_by(PeerCredential.revision.desc())
    ).scalars().first()
    if row is None:
        raise DomainV2Error("profile has no active credential revision")
    return row


def prepare_wireguard_profile_provisioning(
    db: Session,
    *,
    profile: ConnectionProfile,
) -> tuple[ProvisioningJob, bool]:
    """Atomically reserve IP, create encrypted credentials and enqueue runtime intent."""
    if profile.protocol != WIREGUARD_RUNTIME_PROTOCOL:
        raise ProtocolNotAllowed("wireguard is the first activated runtime protocol")

    locked = db.execute(
        select(ConnectionProfile)
        .where(ConnectionProfile.id == profile.id)
        .with_for_update()
    ).scalar_one()

    tunnel_ip = reserve_wireguard_tunnel_ip(db, profile=locked)
    credential = db.execute(
        select(PeerCredential)
        .where(
            PeerCredential.connection_profile_id == locked.id,
            PeerCredential.revoked_at.is_(None),
        )
        .order_by(PeerCredential.revision.desc())
        .with_for_update()
    ).scalars().first()
    if credential is None:
        from app.services.credential_service import create_profile_credential_revision
        credential = create_profile_credential_revision(db, profile_id=locked.id).credential

    locked.status = "provisioning"
    locked.updated_at = utcnow()
    desired_generation = hashlib.sha256(
        f"{locked.id}|{locked.protocol}|{credential.public_key}|{tunnel_ip}|r{credential.revision}".encode("utf-8")
    ).hexdigest()[:32]
    operation_id = f"profile-provision:{locked.id}:r{credential.revision}"
    job, created = enqueue_profile_job(
        db,
        profile=locked,
        action="provision_profile",
        operation_id=operation_id,
        desired_generation=desired_generation,
        payload={
            "profile_id": str(locked.id),
            "protocol": locked.protocol,
            "public_key": credential.public_key,
            "tunnel_ip": tunnel_ip,
            "credential_revision": credential.revision,
        },
    )
    return job, created


def prepare_amneziawg_profile_provisioning(
    db: Session,
    *,
    profile: ConnectionProfile,
) -> tuple[ProvisioningJob, bool]:
    """Atomically reserve AWG IP, create encrypted credentials and enqueue runtime intent."""
    if profile.protocol != AMNEZIAWG_RUNTIME_PROTOCOL:
        raise ProtocolNotAllowed("profile is not amneziawg")

    locked = db.execute(
        select(ConnectionProfile)
        .where(ConnectionProfile.id == profile.id)
        .with_for_update()
    ).scalar_one()

    tunnel_ip = reserve_amneziawg_tunnel_ip(db, profile=locked)
    credential = db.execute(
        select(PeerCredential)
        .where(
            PeerCredential.connection_profile_id == locked.id,
            PeerCredential.revoked_at.is_(None),
        )
        .order_by(PeerCredential.revision.desc())
        .with_for_update()
    ).scalars().first()
    if credential is None:
        from app.services.credential_service import create_profile_credential_revision
        credential = create_profile_credential_revision(db, profile_id=locked.id).credential

    locked.status = "provisioning"
    locked.updated_at = utcnow()
    desired_generation = hashlib.sha256(
        f"{locked.id}|{locked.protocol}|{credential.public_key}|{tunnel_ip}|r{credential.revision}".encode("utf-8")
    ).hexdigest()[:32]
    operation_id = f"profile-provision:{locked.id}:r{credential.revision}"
    job, created = enqueue_profile_job(
        db,
        profile=locked,
        action="provision_profile",
        operation_id=operation_id,
        desired_generation=desired_generation,
        payload={
            "profile_id": str(locked.id),
            "protocol": locked.protocol,
            "public_key": credential.public_key,
            "tunnel_ip": tunnel_ip,
            "credential_revision": credential.revision,
        },
    )
    return job, created


def prepare_profile_provisioning(
    db: Session,
    *,
    profile: ConnectionProfile,
) -> tuple[ProvisioningJob, bool]:
    if profile.protocol == WIREGUARD_RUNTIME_PROTOCOL:
        return prepare_wireguard_profile_provisioning(db, profile=profile)
    if profile.protocol == AMNEZIAWG_RUNTIME_PROTOCOL:
        return prepare_amneziawg_profile_provisioning(db, profile=profile)
    raise ProtocolNotAllowed(profile.protocol)


def request_profile_disable(
    db: Session,
    *,
    profile_id: uuid.UUID,
) -> tuple[ConnectionProfile, ProvisioningJob, bool]:
    profile = db.execute(
        select(ConnectionProfile)
        .where(ConnectionProfile.id == profile_id)
        .with_for_update()
    ).scalar_one_or_none()
    if profile is None:
        raise DomainV2Error("connection profile does not exist")
    if profile.protocol not in SUPPORTED_PROTOCOLS:
        raise ProtocolNotAllowed(profile.protocol)
    if profile.status == "disabled":
        existing = db.execute(
            select(ProvisioningJob)
            .where(
                ProvisioningJob.connection_profile_id == profile.id,
                ProvisioningJob.action == "disable_profile",
            )
            .order_by(ProvisioningJob.created_at.desc())
        ).scalars().first()
        if existing is None:
            raise DomainV2Error("disabled profile has no disable ACK history")
        return profile, existing, False
    if not profile.tunnel_ip:
        raise DomainV2Error("profile has no reserved tunnel IP")

    credential = current_profile_credential(db, profile_id=profile.id)
    profile.status = "disabling"
    profile.updated_at = utcnow()
    generation = hashlib.sha256(
        f"{profile.id}|{credential.public_key}|{profile.tunnel_ip}|disable".encode("utf-8")
    ).hexdigest()[:32]
    operation_id = f"profile-disable:{profile.id}:{generation[:12]}"
    job, created = enqueue_profile_job(
        db,
        profile=profile,
        action="disable_profile",
        operation_id=operation_id,
        desired_generation=generation,
        payload={
            "profile_id": str(profile.id),
            "protocol": profile.protocol,
            "public_key": credential.public_key,
            "tunnel_ip": profile.tunnel_ip,
        },
    )
    return profile, job, created


def request_configuration_disable(
    db: Session,
    *,
    slot_id: uuid.UUID,
) -> list[tuple[ConnectionProfile, ProvisioningJob, bool]]:
    slot = db.execute(
        select(ConnectionSlot)
        .where(ConnectionSlot.id == slot_id)
        .with_for_update()
    ).scalar_one_or_none()
    if slot is None:
        raise DomainV2Error("connection slot does not exist")
    profiles = db.execute(
        select(ConnectionProfile)
        .where(ConnectionProfile.connection_slot_id == slot.id)
        .order_by(ConnectionProfile.protocol.asc())
        .with_for_update()
    ).scalars().all()
    results: list[tuple[ConnectionProfile, ProvisioningJob, bool]] = []
    for profile in profiles:
        if profile.status == "disabled":
            continue
        results.append(request_profile_disable(db, profile_id=profile.id))
    if not results:
        raise DomainV2Error("configuration is already disabled")
    return results


def acknowledge_profile_job(db: Session, *, job: ProvisioningJob) -> None:
    if job.connection_profile_id is None:
        return
    profile = db.execute(
        select(ConnectionProfile)
        .where(ConnectionProfile.id == job.connection_profile_id)
        .with_for_update()
    ).scalar_one_or_none()
    if profile is None:
        raise DomainV2Error("connection profile does not exist")
    now = utcnow()
    if job.action == "provision_profile":
        if not profile.tunnel_ip:
            raise DomainV2Error("provision ACK without tunnel IP reservation")
        profile.status = "active"
        profile.updated_at = now
    elif job.action == "disable_profile":
        if profile.tunnel_ip is None:
            raise DomainV2Error("disable ACK without reserved tunnel IP")
        credentials = db.execute(
            select(PeerCredential)
            .where(
                PeerCredential.connection_profile_id == profile.id,
                PeerCredential.revoked_at.is_(None),
            )
            .with_for_update()
        ).scalars().all()
        for credential in credentials:
            credential.revoked_at = now
        profile.status = "disabled"
        profile.disabled_at = now
        profile.tunnel_ip = None
        profile.tunnel_ip_released_at = now
        profile.updated_at = now
    else:
        raise DomainV2Error(f"unsupported Domain V2 job action: {job.action}")

    slot = db.execute(
        select(ConnectionSlot)
        .where(ConnectionSlot.id == profile.connection_slot_id)
        .with_for_update()
    ).scalar_one_or_none()
    if slot is None:
        raise DomainV2Error("connection slot does not exist")
    db.flush()
    if job.action == "provision_profile":
        slot.disabled_at = None
        slot.updated_at = now
    else:
        live_siblings = int(db.execute(
            select(func.count(ConnectionProfile.id)).where(
                ConnectionProfile.connection_slot_id == slot.id,
                ConnectionProfile.status != "disabled",
            )
        ).scalar_one())
        if live_siblings == 0:
            slot.disabled_at = now
            slot.updated_at = now
    db.flush()


def record_profile_job_failure(
    db: Session,
    *,
    job: ProvisioningJob,
    error_text: str,
) -> bool:
    """Return True when the job is scheduled for another attempt."""
    if job.connection_profile_id is None:
        return False
    max_attempts = max(1, int(os.environ.get("WG_DOMAIN_V2_MAX_ATTEMPTS", "8")))
    capped = str(error_text or "provisioning failure")[:1000]
    job.last_error = capped
    job.completed_at = None
    if job.attempts < max_attempts:
        delay = min(300, 5 * (2 ** max(0, job.attempts - 1)))
        job.status = "pending"
        job.next_attempt_at = utcnow() + timedelta(seconds=delay)
        db.flush()
        return True

    job.status = "failed"
    job.next_attempt_at = None
    profile = db.execute(
        select(ConnectionProfile)
        .where(ConnectionProfile.id == job.connection_profile_id)
        .with_for_update()
    ).scalar_one_or_none()
    if profile is not None and job.action == "provision_profile":
        profile.status = "provisioning_failed"
        profile.updated_at = utcnow()
    db.flush()
    return False


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
        next_attempt_at=utcnow(),
        payload_json=dict(payload or {}),
        status="pending",
        attempts=0,
    )
    db.add(job)
    db.flush()
    return job, True


def create_configuration_request(
    db: Session,
    *,
    user: User,
    grant_id: uuid.UUID,
    node_id: str,
    label: str | None = None,
    now: datetime | None = None,
) -> ConfigurationRequestResult:
    point = now or utcnow()
    grant = db.execute(
        select(AccessGrant)
        .where(AccessGrant.id == grant_id)
        .with_for_update()
    ).scalar_one_or_none()
    if grant is None or grant.user_id != user.id or not grant_is_active(grant, now=point):
        raise GrantInactive("grant is unavailable")

    slot_limit = mirrored_configuration_limit(db, grant_id=grant.id, for_update=True)
    current_count = logical_slot_count(db, grant_id=grant.id, user_id=user.id)
    if current_count >= slot_limit:
        raise ProtocolQuotaExceeded("configuration")

    normalized_label = str(label).strip() if label is not None else ""
    slot = ConnectionSlot(
        id=uuid.uuid4(),
        user_id=user.id,
        access_grant_id=grant.id,
        node_id=node_id,
        label=normalized_label or None,
        expires_at=grant.valid_until,
        disabled_at=None,
    )
    db.add(slot)
    db.flush()

    profiles: dict[str, ConnectionProfile] = {}
    jobs: dict[str, ProvisioningJob] = {}
    created_jobs: dict[str, bool] = {}
    for protocol in (WIREGUARD_RUNTIME_PROTOCOL, AMNEZIAWG_RUNTIME_PROTOCOL):
        profile = ConnectionProfile(
            id=uuid.uuid4(),
            connection_slot_id=slot.id,
            user_id=user.id,
            access_grant_id=grant.id,
            protocol=protocol,
            node_id=node_id,
            label=slot.label,
            status="requested",
            expires_at=grant.valid_until,
        )
        db.add(profile)
        db.flush()
        job, created = prepare_profile_provisioning(db, profile=profile)
        profiles[protocol] = profile
        jobs[protocol] = job
        created_jobs[protocol] = created

    return ConfigurationRequestResult(
        slot=slot,
        profiles=profiles,
        jobs=jobs,
        created_jobs=created_jobs,
    )


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
    # Compatibility surface for the pre-P28G API. A user-visible create is now
    # one logical configuration slot with both WG and AWG runtime variants; the
    # legacy caller receives only the variant it requested.
    if protocol not in SUPPORTED_PROTOCOLS:
        raise ProtocolNotAllowed(protocol)
    result = create_configuration_request(
        db,
        user=user,
        grant_id=grant_id,
        node_id=node_id,
        label=label,
        now=now,
    )
    return ProfileRequestResult(
        profile=result.profiles[protocol],
        job=result.jobs[protocol],
        created_job=result.created_jobs[protocol],
    )


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
