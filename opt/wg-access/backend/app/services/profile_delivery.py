from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO
import uuid

import qrcode
from qrcode.image.svg import SvgPathImage
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AccessGrant, ConnectionProfile, ConnectionSlot
from app.services.credential_service import decrypt_profile_credential
from app.services.domain_v2 import (
    DomainV2Error,
    ConfigurationRequestResult,
    ProfileRequestResult,
    create_configuration_request,
    create_profile_request,
    current_profile_credential,
    grant_is_active,
    prepare_profile_provisioning,
    record_audit_event,
    request_profile_disable,
    utcnow,
)
from app.services.wireguard import build_client_config as build_wireguard_client_config
from app.services.amneziawg import build_client_config as build_amneziawg_client_config


class ProfileSurfaceError(RuntimeError):
    pass


class ProfileUnavailable(ProfileSurfaceError):
    pass


class ProfileNotReady(ProfileSurfaceError):
    pass


def _owned_profile(
    db: Session,
    *,
    user_id: uuid.UUID,
    profile_id: uuid.UUID,
    for_update: bool = False,
) -> ConnectionProfile:
    query = select(ConnectionProfile).where(
        ConnectionProfile.id == profile_id,
        ConnectionProfile.user_id == user_id,
    )
    if for_update:
        query = query.with_for_update()
    profile = db.execute(query).scalar_one_or_none()
    if profile is None:
        raise ProfileUnavailable("profile unavailable")
    return profile


def list_owned_profiles(db: Session, *, user) -> list[ConnectionProfile]:
    return list(
        db.execute(
            select(ConnectionProfile)
            .where(ConnectionProfile.user_id == user.id)
            .order_by(ConnectionProfile.created_at.asc(), ConnectionProfile.id.asc())
        ).scalars().all()
    )


def create_owned_configuration(
    db: Session,
    *,
    user,
    grant_id: uuid.UUID,
    node_id: str,
    label: str | None,
    request_id: str | None,
    actor_kind: str = "user",
) -> ConfigurationRequestResult:
    try:
        result = create_configuration_request(
            db,
            user=user,
            grant_id=grant_id,
            node_id=node_id,
            label=label,
        )
    except DomainV2Error as exc:
        raise ProfileSurfaceError("configuration request rejected") from exc
    record_audit_event(
        db,
        event_type="configuration.requested",
        actor_kind=actor_kind,
        actor_user_id=(user.id if actor_kind == "user" else None),
        object_type="connection_slot",
        object_id=str(result.slot.id),
        request_id=request_id,
        payload={"protocols": ["wireguard", "amneziawg"]},
    )
    return result


def create_owned_profile(
    db: Session,
    *,
    user,
    grant_id: uuid.UUID,
    protocol: str,
    node_id: str,
    label: str | None,
    request_id: str | None,
) -> ProfileRequestResult:
    try:
        result = create_profile_request(
            db,
            user=user,
            grant_id=grant_id,
            protocol=protocol,
            node_id=node_id,
            label=label,
        )
    except DomainV2Error as exc:
        raise ProfileSurfaceError("profile request rejected") from exc
    record_audit_event(
        db,
        event_type="profile.requested",
        actor_kind="user",
        actor_user_id=user.id,
        object_type="connection_profile",
        object_id=str(result.profile.id),
        request_id=request_id,
        payload={"protocol": protocol, "paired_protocol": ("amneziawg" if protocol == "wireguard" else "wireguard")},
    )
    return result


def update_owned_configuration_label(
    db: Session,
    *,
    user,
    configuration_id: uuid.UUID,
    label: str | None,
    request_id: str | None,
) -> ConnectionSlot:
    slot = db.execute(
        select(ConnectionSlot)
        .where(
            ConnectionSlot.id == configuration_id,
            ConnectionSlot.user_id == user.id,
        )
        .with_for_update()
    ).scalar_one_or_none()
    if slot is None:
        raise ProfileUnavailable("configuration unavailable")
    normalized = str(label).strip() if label is not None else ""
    value = normalized or None
    slot.label = value
    slot.updated_at = utcnow()
    siblings = db.execute(
        select(ConnectionProfile)
        .where(ConnectionProfile.connection_slot_id == slot.id)
        .with_for_update()
    ).scalars().all()
    for sibling in siblings:
        sibling.label = value
        sibling.updated_at = slot.updated_at
    record_audit_event(
        db,
        event_type="configuration.label.updated",
        actor_kind="user",
        actor_user_id=user.id,
        object_type="connection_slot",
        object_id=str(slot.id),
        request_id=request_id,
        payload={"label_set": value is not None},
    )
    db.flush()
    return slot


def update_owned_profile_label(
    db: Session,
    *,
    user,
    profile_id: uuid.UUID,
    label: str | None,
    request_id: str | None,
) -> ConnectionProfile:
    profile = _owned_profile(db, user_id=user.id, profile_id=profile_id, for_update=True)
    update_owned_configuration_label(
        db,
        user=user,
        configuration_id=profile.connection_slot_id,
        label=label,
        request_id=request_id,
    )
    return profile


def profile_slot_ordinal(
    db: Session,
    *,
    user,
    profile_id: uuid.UUID,
) -> int:
    profile = _owned_profile(db, user_id=user.id, profile_id=profile_id)
    slot_ids = db.execute(
        select(ConnectionSlot.id)
        .where(ConnectionSlot.user_id == user.id)
        .order_by(ConnectionSlot.created_at.asc(), ConnectionSlot.id.asc())
    ).scalars().all()
    try:
        return list(slot_ids).index(profile.connection_slot_id) + 1
    except ValueError:
        return 0


def build_owned_profile_config(
    db: Session,
    *,
    user,
    profile_id: uuid.UUID,
    request_id: str | None,
    audit_event: str = "profile.config.delivered",
    audit_actor_kind: str = "user",
    audit_actor_user_id: uuid.UUID | None = None,
) -> str:
    profile = _owned_profile(db, user_id=user.id, profile_id=profile_id)
    if profile.protocol not in {"wireguard", "amneziawg"}:
        raise ProfileNotReady("unsupported protocol")
    if profile.status != "active" or not profile.tunnel_ip:
        raise ProfileNotReady("profile is not active")
    credential = current_profile_credential(db, profile_id=profile.id)
    secret = decrypt_profile_credential(credential)
    private_key = secret.get("private_key", "")
    preshared_key = secret.get("preshared_key", "")
    if not private_key or not preshared_key:
        raise ProfileNotReady("credential is unavailable")
    if profile.protocol == "wireguard":
        config_text = build_wireguard_client_config(private_key, profile.tunnel_ip, preshared_key)
    else:
        config_text = build_amneziawg_client_config(private_key, profile.tunnel_ip, preshared_key)
    record_audit_event(
        db,
        event_type=audit_event,
        actor_kind=audit_actor_kind,
        actor_user_id=(user.id if audit_actor_kind == "user" and audit_actor_user_id is None else audit_actor_user_id),
        object_type="connection_profile",
        object_id=str(profile.id),
        request_id=request_id,
        payload={"credential_revision": credential.revision, "protocol": profile.protocol},
    )
    return config_text


def build_qr_svg(config_text: str) -> bytes:
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, border=4)
    qr.add_data(config_text)
    qr.make(fit=True)
    image = qr.make_image(image_factory=SvgPathImage)
    out = BytesIO()
    image.save(out)
    return out.getvalue()


def revoke_owned_profile(
    db: Session,
    *,
    user,
    profile_id: uuid.UUID,
    request_id: str | None,
):
    _owned_profile(db, user_id=user.id, profile_id=profile_id, for_update=True)
    try:
        profile, job, created = request_profile_disable(db, profile_id=profile_id)
    except DomainV2Error as exc:
        raise ProfileSurfaceError("revoke rejected") from exc
    record_audit_event(
        db,
        event_type="profile.revoke.requested",
        actor_kind="user",
        actor_user_id=user.id,
        object_type="connection_profile",
        object_id=str(profile.id),
        request_id=request_id,
        payload={},
    )
    return profile, job, created


def reissue_owned_profile(
    db: Session,
    *,
    user,
    profile_id: uuid.UUID,
    request_id: str | None,
):
    profile = _owned_profile(db, user_id=user.id, profile_id=profile_id, for_update=True)
    if profile.protocol not in {"wireguard", "amneziawg"}:
        raise ProfileSurfaceError("unsupported protocol")
    if profile.status != "disabled" or profile.tunnel_ip is not None:
        raise ProfileSurfaceError("profile must be fully disabled before reissue")
    grant = db.get(AccessGrant, profile.access_grant_id)
    if grant is None or grant.user_id != user.id or not grant_is_active(grant, now=utcnow()):
        raise ProfileSurfaceError("grant unavailable")
    try:
        job, created = prepare_profile_provisioning(db, profile=profile)
    except DomainV2Error as exc:
        raise ProfileSurfaceError("reissue rejected") from exc
    record_audit_event(
        db,
        event_type="profile.reissue.requested",
        actor_kind="user",
        actor_user_id=user.id,
        object_type="connection_profile",
        object_id=str(profile.id),
        request_id=request_id,
        payload={},
    )
    return profile, job, created
