from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import ConnectionSlot
from app.services.domain_v2 import record_audit_event, utcnow


FORCED_ROUTING_DURATION = timedelta(minutes=30)
FORCED_ROUTING_SELECTORS = frozenset({1, 2, 3, 4, 5})


class ConfigurationRoutingUnavailable(RuntimeError):
    pass


class ConfigurationRoutingRejected(RuntimeError):
    pass


@dataclass(frozen=True)
class EffectiveRoutingState:
    mode: str
    selector: int | None
    expires_at: datetime | None


def effective_configuration_routing(
    slot: ConnectionSlot,
    *,
    now: datetime | None = None,
) -> EffectiveRoutingState:
    edge = now or utcnow()
    selector = slot.forced_selector
    expires_at = slot.forced_until
    if selector in FORCED_ROUTING_SELECTORS and expires_at is not None and expires_at > edge:
        return EffectiveRoutingState(mode="forced", selector=int(selector), expires_at=expires_at)
    return EffectiveRoutingState(mode="automatic", selector=None, expires_at=None)


def set_owned_configuration_routing(
    db: Session,
    *,
    user,
    configuration_id: uuid.UUID,
    mode: str,
    selector: int | None,
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
    if slot is None or slot.disabled_at is not None:
        raise ConfigurationRoutingUnavailable("configuration unavailable")

    now = utcnow()
    if mode == "automatic":
        if selector is not None:
            raise ConfigurationRoutingRejected("automatic mode does not accept selector")
        slot.forced_selector = None
        slot.forced_until = None
    elif mode == "forced":
        if selector not in FORCED_ROUTING_SELECTORS:
            raise ConfigurationRoutingRejected("forced selector must be 1..5")
        slot.forced_selector = int(selector)
        slot.forced_until = now + FORCED_ROUTING_DURATION
    else:
        raise ConfigurationRoutingRejected("unsupported routing mode")

    slot.updated_at = now
    record_audit_event(
        db,
        event_type="configuration.routing_override.updated",
        actor_kind="user",
        actor_user_id=user.id,
        object_type="connection_slot",
        object_id=str(slot.id),
        request_id=request_id,
        payload={
            "mode": mode,
            "selector": slot.forced_selector,
            "expires_at": slot.forced_until.isoformat() if slot.forced_until is not None else None,
            "duration_seconds": int(FORCED_ROUTING_DURATION.total_seconds()) if mode == "forced" else None,
        },
    )
    db.flush()
    return slot
