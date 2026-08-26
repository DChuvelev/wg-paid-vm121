from __future__ import annotations

import hashlib
from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.models import (
    AccessGrant,
    AuthSession,
    ConnectionProfile,
    MagicLinkToken,
    Order,
    Peer,
    PeerCredential,
    ProvisioningJob,
    Subscription,
    User,
)
from app.services.domain_v2 import record_audit_event, request_profile_disable, utcnow


class UserDeletionError(RuntimeError):
    pass


@dataclass(frozen=True)
class UserDeletionResult:
    user_id: UUID
    email: str
    status: str
    disable_jobs_created: int
    remaining_profiles: int
    legacy_dependency_count: int


def _email_hash(email: str) -> str:
    return hashlib.sha256(str(email).strip().casefold().encode("utf-8")).hexdigest()


def _legacy_dependency_count(db: Session, *, user_id: UUID) -> int:
    total = 0
    for model in (Order, Subscription, Peer):
        total += int(
            db.execute(select(func.count()).select_from(model).where(model.user_id == user_id)).scalar_one()
        )
    return total


def _profiles_not_fully_disabled(db: Session, *, user_id: UUID) -> list[ConnectionProfile]:
    return list(
        db.execute(
            select(ConnectionProfile)
            .where(ConnectionProfile.user_id == user_id)
            .where(
                or_(
                    ConnectionProfile.status != "disabled",
                    ConnectionProfile.tunnel_ip.is_not(None),
                )
            )
            .order_by(ConnectionProfile.created_at.asc())
        ).scalars().all()
    )


def finalize_user_deletion_if_ready(
    db: Session,
    *,
    user_id: UUID,
    request_id: str | None = None,
) -> bool:
    user = db.execute(select(User).where(User.id == user_id).with_for_update()).scalar_one_or_none()
    if user is None:
        return True
    if user.deletion_requested_at is None:
        return False
    if _profiles_not_fully_disabled(db, user_id=user.id):
        return False
    if _legacy_dependency_count(db, user_id=user.id):
        return False

    record_audit_event(
        db,
        event_type="admin.user.deleted",
        actor_kind="system",
        object_type="user",
        object_id=str(user.id),
        request_id=request_id,
        payload={"email_hash": _email_hash(user.email)},
    )
    db.delete(user)
    db.flush()
    return True


def request_admin_user_deletion(
    db: Session,
    *,
    user_id: UUID,
    request_id: str | None,
) -> UserDeletionResult:
    user = db.execute(select(User).where(User.id == user_id).with_for_update()).scalar_one_or_none()
    if user is None:
        raise UserDeletionError("user not found")

    now = utcnow()
    first_request = user.deletion_requested_at is None
    if first_request:
        user.deletion_requested_at = now

    sessions = db.execute(
        select(AuthSession).where(AuthSession.user_id == user.id).with_for_update()
    ).scalars().all()
    for session in sessions:
        if session.revoked_at is None:
            session.revoked_at = now

    grants = db.execute(
        select(AccessGrant).where(AccessGrant.user_id == user.id).with_for_update()
    ).scalars().all()
    for grant in grants:
        if grant.status != "revoked":
            grant.status = "revoked"
            grant.updated_at = now

    tokens = db.execute(
        select(MagicLinkToken)
        .where(
            or_(MagicLinkToken.user_id == user.id, MagicLinkToken.email == user.email),
            MagicLinkToken.consumed_at.is_(None),
        )
        .with_for_update()
    ).scalars().all()
    for token in tokens:
        token.consumed_at = now

    profiles = db.execute(
        select(ConnectionProfile)
        .where(ConnectionProfile.user_id == user.id)
        .order_by(ConnectionProfile.created_at.asc())
        .with_for_update()
    ).scalars().all()

    jobs_created = 0
    for profile in profiles:
        if profile.status == "disabled":
            if profile.tunnel_ip is not None:
                raise UserDeletionError("disabled profile still owns a tunnel IP")
            continue
        if profile.tunnel_ip is None:
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
            profile.disabled_at = profile.disabled_at or now
            profile.updated_at = now
            continue

        _, _, created = request_profile_disable(db, profile_id=profile.id)
        if created:
            jobs_created += 1

    if first_request:
        record_audit_event(
            db,
            event_type="admin.user.delete.requested",
            actor_kind="admin",
            object_type="user",
            object_id=str(user.id),
            request_id=request_id,
            payload={
                "email_hash": _email_hash(user.email),
                "profile_count": len(profiles),
            },
        )

    legacy_count = _legacy_dependency_count(db, user_id=user.id)
    db.flush()
    deleted = finalize_user_deletion_if_ready(db, user_id=user.id, request_id=request_id)
    if deleted:
        return UserDeletionResult(
            user_id=user_id,
            email=user.email,
            status="deleted",
            disable_jobs_created=jobs_created,
            remaining_profiles=0,
            legacy_dependency_count=0,
        )

    remaining = len(_profiles_not_fully_disabled(db, user_id=user.id))
    status = "blocked_legacy_dependencies" if remaining == 0 and legacy_count else "deleting"
    return UserDeletionResult(
        user_id=user.id,
        email=user.email,
        status=status,
        disable_jobs_created=jobs_created,
        remaining_profiles=remaining,
        legacy_dependency_count=legacy_count,
    )
