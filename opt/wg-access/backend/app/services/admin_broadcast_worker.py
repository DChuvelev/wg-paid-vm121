"""Conservative one-shot SMTP queue dispatcher.

Run only under a host-level systemd+flock singleton. Never silently retry a
claimed recipient after interrupted SMTP; unresolved outcomes are uncertain.
"""
from __future__ import annotations

import os
from datetime import timedelta
from uuid import UUID
from sqlalchemy import func, select

from app.db.session import SessionLocal
from app.models import AdminBroadcast, AdminBroadcastRecipient
from app.services.admin_broadcast import recipient_counts, recipient_is_eligible
from app.services.domain_v2 import record_audit_event, utcnow
from app.services.mail_delivery import MailDeliveryError, deliver_admin_broadcast_email, smtp_delivery_status

MAX_PER_MINUTE = 10


def rate_limit() -> int:
    try:
        n = int(os.getenv("WG_ACCESS_BROADCAST_MAX_PER_MIN", "10"))
    except ValueError as exc:
        raise RuntimeError("invalid rate cap") from exc
    if not (1 <= n <= MAX_PER_MINUTE):
        raise RuntimeError("broadcast rate cap must be 1..10")
    return n


def recover_orphan_claims() -> int:
    """Only call this upon new singleton process entry (never during SMTP)."""
    with SessionLocal() as db:
        rows = db.scalars(select(AdminBroadcastRecipient)
                          .where(AdminBroadcastRecipient.state == "in_flight")
                          .with_for_update(skip_locked=True)).all()
        for row in rows:
            row.state = "uncertain"
            row.failure_category = "interrupted_or_unknown"
        db.commit()
        return len(rows)


def _finish_if_done(db, campaign: AdminBroadcast) -> bool:
    counts = recipient_counts(db, campaign.id)
    if counts.get("pending", 0) or counts.get("in_flight", 0):
        return False
    campaign.state = "completed_with_uncertain" if counts.get("uncertain", 0) else "completed"
    campaign.updated_at = utcnow()
    record_audit_event(db, event_type="admin.broadcast.completed", actor_kind="system",
                       object_type="admin_broadcast", object_id=str(campaign.id),
                       payload={"audience": campaign.audience, "recipient_count": campaign.recipient_count,
                                "smtp_accepted": counts.get("smtp_accepted", 0),
                                "uncertain": counts.get("uncertain", 0),
                                "skipped": counts.get("skipped", 0)})
    return True


def claim_next(limit: int):
    """Return (campaign_id, recipient_id, address, subject, body) or a status."""
    with SessionLocal() as db:
        campaign = db.scalar(select(AdminBroadcast)
                             .where(AdminBroadcast.state.in_(["queued", "sending"]))
                             .order_by(AdminBroadcast.confirmed_at, AdminBroadcast.id)
                             .limit(1).with_for_update(skip_locked=True))
        if campaign is None:
            return "idle", None
        if _finish_if_done(db, campaign):
            db.commit()
            return "finished", None
        now = utcnow()
        used = int(db.scalar(select(func.count(AdminBroadcastRecipient.id)).where(
            AdminBroadcastRecipient.claimed_at >= now - timedelta(seconds=60))) or 0)
        if used >= limit:
            return "rate_limited", None
        # Preflight before claiming. Never mark uncertain just because credentials
        # were unavailable before the SMTP attempt could begin.
        if not smtp_delivery_status().get("configured"):
            campaign.state = "paused"
            campaign.updated_at = now
            record_audit_event(db, event_type="admin.broadcast.smtp_not_configured", actor_kind="system",
                               object_type="admin_broadcast", object_id=str(campaign.id), payload={})
            db.commit()
            return "smtp_paused", None
        recipient = db.scalar(select(AdminBroadcastRecipient).where(
            AdminBroadcastRecipient.broadcast_id == campaign.id,
            AdminBroadcastRecipient.state == "pending"
        ).order_by(AdminBroadcastRecipient.normalized_email).limit(1).with_for_update(skip_locked=True))
        if recipient is None:
            return "no_pending", None
        if not recipient_is_eligible(db, recipient, campaign.audience, now=now):
            recipient.state = "skipped"
            recipient.failure_category = "no_longer_eligible"
            db.commit()
            return "skipped", None
        recipient.state = "in_flight"
        recipient.claimed_at = now
        campaign.state = "sending"
        campaign.updated_at = now
        job = (campaign.id, recipient.id, recipient.normalized_email, campaign.subject, campaign.body)
        db.commit()  # CRITICAL: persistent in-flight before SMTP
        return "claimed", job


def settle(claim: tuple, accepted: bool) -> None:
    campaign_id, recipient_id, _email, _subject, _body = claim
    with SessionLocal() as db:
        row = db.scalar(select(AdminBroadcastRecipient)
                        .where(AdminBroadcastRecipient.id == recipient_id).with_for_update())
        if row is None or row.state != "in_flight":
            # Never replay an already accepted or uncertain SMTP outcome.
            raise RuntimeError("broadcast claim was externally modified")
        row.state = "smtp_accepted" if accepted else "uncertain"
        if accepted:
            row.accepted_at = utcnow()
        else:
            row.failure_category = "smtp_result_unknown"
            campaign = db.scalar(select(AdminBroadcast)
                                 .where(AdminBroadcast.id == campaign_id).with_for_update())
            if campaign is not None and campaign.state in {"sending", "queued"}:
                campaign.state = "paused"
                campaign.updated_at = utcnow()
                record_audit_event(db, event_type="admin.broadcast.smtp_uncertain_paused", actor_kind="system",
                                   object_type="admin_broadcast", object_id=str(campaign.id), payload={})
        db.commit()


def main() -> None:
    limit = rate_limit()
    orphaned = recover_orphan_claims()
    print(f"BROADCAST_ORPHAN_CLAIMS_UNCERTAIN={orphaned}")
    for _ in range(limit):
        kind, claim = claim_next(limit)
        if kind == "claimed":
            _campaign_id, _recipient_id, address, subject, body = claim
            try:
                deliver_admin_broadcast_email(to_email=address, subject=subject, body=body)
            except MailDeliveryError:
                settle(claim, accepted=False)
                print("BROADCAST_SMTP_RESULT=uncertain_paused")
                break
            settle(claim, accepted=True)
            print("BROADCAST_SMTP_RESULT=smtp_accepted")
        elif kind in {"skipped", "finished"}:
            print(f"BROADCAST_WORKER_EVENT={kind}")
            continue
        else:
            print(f"BROADCAST_WORKER_STOP={kind}")
            break
    print("RESULT=PASS_BROADCAST_WORKER_BOUNDED")


if __name__ == "__main__":
    main()
