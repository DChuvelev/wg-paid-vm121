#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

WG_ACCESS_ROOT="/opt/wg-access"
LOG_DIR="$WG_ACCESS_ROOT/maintenance-logs"
LOCK="/run/wg-access-expire-subscriptions.lock"
MODE="${1:-run}"

case "$MODE" in
  run|--check-only) ;;
  *)
    echo "usage: $0 [--check-only]" >&2
    exit 64
    ;;
esac

mkdir -p "$LOG_DIR"
out="$LOG_DIR/expire-subscriptions.$(date +%Y%m%d).log"

{
  echo "== $(date -Is) domain-v2-expiry mode=$MODE =="
  flock -n 9 || {
    echo "RESULT=NOOP_DOMAIN_V2_EXPIRY_LOCKED"
    exit 0
  }

  cd "$WG_ACCESS_ROOT"
  test -f docker-compose.yml
  test -f docker-compose.override.yml

  if [[ "$MODE" == "--check-only" ]]; then
    EXPIRY_MODE=check
  else
    EXPIRY_MODE=run
  fi

  docker compose exec -T -e WG_ACCESS_EXPIRY_MODE="$EXPIRY_MODE" backend python - <<'PY'
from __future__ import annotations

from datetime import datetime, timezone
import os
import sys

from sqlalchemy import select

from app.agent_trigger import trigger_wg_access_agent_best_effort
from app.db.session import SessionLocal
from app.models import (
    AccessGrant,
    BillingAccount,
    ConnectionProfile,
    ConnectionSlot,
    Invite,
    ProvisioningJob,
)
from app.services.domain_v2 import (
    DomainV2Error,
    record_audit_event,
    request_configuration_disable,
)
from app.services.billing import apply_due_quantity_transitions

EXPECTED_PROTOCOLS = {"wireguard", "amneziawg"}
MODE = os.environ.get("WG_ACCESS_EXPIRY_MODE", "run")
if MODE not in {"run", "check"}:
    raise SystemExit("invalid WG_ACCESS_EXPIRY_MODE")


def _fmt(value):
    return value.isoformat() if value is not None else "NULL"


def _validate_slot_mirror(db, *, grant, slot):
    if slot.expires_at != grant.valid_until:
        raise DomainV2Error(
            "expiry mirror drift "
            f"grant={grant.id} slot={slot.id} "
            f"grant_until={_fmt(grant.valid_until)} slot_until={_fmt(slot.expires_at)}"
        )

    profiles = db.execute(
        select(ConnectionProfile)
        .where(ConnectionProfile.connection_slot_id == slot.id)
        .order_by(ConnectionProfile.protocol.asc())
        .with_for_update()
    ).scalars().all()

    by_protocol = {profile.protocol: profile for profile in profiles}
    if set(by_protocol) != EXPECTED_PROTOCOLS:
        raise DomainV2Error(
            "configuration protocol pair drift "
            f"grant={grant.id} slot={slot.id} protocols={sorted(by_protocol)}"
        )

    for protocol in sorted(EXPECTED_PROTOCOLS):
        profile = by_protocol[protocol]
        if profile.access_grant_id != grant.id:
            raise DomainV2Error(
                "configuration grant linkage drift "
                f"grant={grant.id} slot={slot.id} profile={profile.id} protocol={protocol}"
            )
        if profile.expires_at != grant.valid_until:
            raise DomainV2Error(
                "profile expiry mirror drift "
                f"grant={grant.id} slot={slot.id} profile={profile.id} protocol={protocol} "
                f"grant_until={_fmt(grant.valid_until)} profile_until={_fmt(profile.expires_at)}"
            )

    return profiles


def _terminalize_superseded_provision_jobs(db, *, profiles, now):
    profile_ids = [profile.id for profile in profiles]
    if not profile_ids:
        return 0

    jobs = db.execute(
        select(ProvisioningJob)
        .where(ProvisioningJob.connection_profile_id.in_(profile_ids))
        .where(ProvisioningJob.action == "provision_profile")
        .where(ProvisioningJob.status.in_(("pending", "running")))
        .order_by(ProvisioningJob.created_at.asc())
        .with_for_update()
    ).scalars().all()

    for job in jobs:
        job.status = "failed"
        job.completed_at = now
        job.next_attempt_at = None
        job.last_error = "superseded by access-grant expiry"
    db.flush()
    return len(jobs)


def _expire_commercial_state(db, *, grant, now):
    account = db.execute(
        select(BillingAccount)
        .where(BillingAccount.access_grant_id == grant.id)
        .with_for_update()
    ).scalar_one_or_none()

    if account is None:
        return {"account_expired": 0, "referrals_revoked": 0}

    active_referrals = db.execute(
        select(Invite)
        .where(Invite.created_by_kind == "user")
        .where(Invite.created_by_user_id == account.user_id)
        .where(Invite.revoked_at.is_(None))
        .where(Invite.used_count < Invite.max_uses)
        .where((Invite.expires_at.is_(None)) | (Invite.expires_at > now))
        .order_by(Invite.created_at.asc(), Invite.id.asc())
        .with_for_update()
    ).scalars().all()

    account.status = "expired"
    account.updated_at = now
    for invite in active_referrals:
        invite.revoked_at = now
    db.flush()

    return {
        "account_expired": 1,
        "referrals_revoked": len(active_referrals),
    }


def _check_finite_grant_integrity(db):
    grants = db.execute(
        select(AccessGrant)
        .where(AccessGrant.status == "active")
        .where(AccessGrant.valid_until.is_not(None))
        .order_by(AccessGrant.valid_until.asc(), AccessGrant.id.asc())
    ).scalars().all()

    slots_checked = 0
    for grant in grants:
        slots = db.execute(
            select(ConnectionSlot)
            .where(ConnectionSlot.access_grant_id == grant.id)
            .where(ConnectionSlot.disabled_at.is_(None))
            .order_by(ConnectionSlot.created_at.asc(), ConnectionSlot.id.asc())
        ).scalars().all()
        for slot in slots:
            _validate_slot_mirror(db, grant=grant, slot=slot)
            slots_checked += 1

    return len(grants), slots_checked


def _process_due_grant(db, *, grant_id, now):
    grant = db.execute(
        select(AccessGrant)
        .where(AccessGrant.id == grant_id)
        .with_for_update()
    ).scalar_one_or_none()

    if (
        grant is None
        or grant.status != "active"
        or grant.valid_until is None
        or grant.valid_until > now
    ):
        return None

    slots = db.execute(
        select(ConnectionSlot)
        .where(ConnectionSlot.access_grant_id == grant.id)
        .where(ConnectionSlot.disabled_at.is_(None))
        .order_by(ConnectionSlot.created_at.asc(), ConnectionSlot.id.asc())
        .with_for_update()
    ).scalars().all()

    grant_slot_details = []
    grant_slots_retired = 0
    grant_disable_jobs_created = 0
    grant_superseded_provision_jobs = 0

    for slot in slots:
        profiles = _validate_slot_mirror(db, grant=grant, slot=slot)
        grant_superseded_provision_jobs += _terminalize_superseded_provision_jobs(
            db,
            profiles=profiles,
            now=now,
        )

        if all(profile.status == "disabled" for profile in profiles):
            raise DomainV2Error(
                "slot terminal-state drift: both profiles disabled while slot remains live "
                f"grant={grant.id} slot={slot.id}"
            )

        disable_results = request_configuration_disable(db, slot_id=slot.id)
        if any(job.status not in {"pending", "running"} for _, job, _ in disable_results):
            raise DomainV2Error(
                "configuration disable intent is not actionable "
                f"grant={grant.id} slot={slot.id}"
            )

        created_here = sum(int(created) for _, _, created in disable_results)
        grant_disable_jobs_created += created_here
        grant_slots_retired += 1
        grant_slot_details.append(
            {
                "connection_slot_id": str(slot.id),
                "disable_jobs_created": created_here,
                "protocols": [profile.protocol for profile, _, _ in disable_results],
            }
        )

    commercial = _expire_commercial_state(db, grant=grant, now=now)

    grant.status = "expired"
    grant.updated_at = now
    record_audit_event(
        db,
        event_type="access_grant.expired",
        actor_kind="system",
        object_type="access_grant",
        object_id=str(grant.id),
        payload={
            "valid_until": _fmt(grant.valid_until),
            "expired_at": _fmt(now),
            "configuration_count": len(slots),
            "configurations": grant_slot_details,
        },
    )

    return {
        "grant_id": str(grant.id),
        "valid_until": _fmt(grant.valid_until),
        "slot_count": len(slots),
        "slots_retired": grant_slots_retired,
        "disable_jobs_created": grant_disable_jobs_created,
        "superseded_provision_jobs": grant_superseded_provision_jobs,
        "commercial_accounts_expired": commercial["account_expired"],
        "referrals_revoked": commercial["referrals_revoked"],
    }


def _due_quantity_transition_ids(db, *, now):
    return db.execute(
        select(BillingAccount.id)
        .where(BillingAccount.pending_period_start.is_not(None))
        .where(BillingAccount.pending_period_start <= now)
        .order_by(BillingAccount.pending_period_start.asc(), BillingAccount.id.asc())
    ).scalars().all()


def main():
    now = datetime.now(timezone.utc)
    db = SessionLocal()
    try:
        if MODE == "check":
            finite_grants, finite_slots = _check_finite_grant_integrity(db)
            due_quantity_ids = _due_quantity_transition_ids(db, now=now)
            db.rollback()
            print(f"FINITE_ACTIVE_GRANTS={finite_grants}")
            print(f"FINITE_ACTIVE_SLOTS_CHECKED={finite_slots}")
            print(f"DUE_QUANTITY_TRANSITIONS={len(due_quantity_ids)}")

        quantity_transitions_applied = 0
        quantity_configurations_created = 0
        quantity_retirements_requested = 0
        quantity_wakeup = False

        if MODE == "run":
            quantity_results = apply_due_quantity_transitions(db, now=now)
            db.commit()
            quantity_transitions_applied = len(quantity_results)
            quantity_configurations_created = sum(int(item.configurations_created) for item in quantity_results)
            quantity_retirements_requested = sum(int(item.retirements_requested) for item in quantity_results)
            quantity_wakeup = any(bool(item.agent_wakeup_needed) for item in quantity_results)
            for item in quantity_results:
                print(
                    "QUANTITY_TRANSITION="
                    f"{item.account_id} quantity={item.quantity_before}->{item.quantity_after} "
                    f"created={item.configurations_created} retirements={item.retirements_requested}"
                )

        due_ids = db.execute(
            select(AccessGrant.id)
            .where(AccessGrant.status == "active")
            .where(AccessGrant.valid_until.is_not(None))
            .where(AccessGrant.valid_until <= now)
            .order_by(AccessGrant.valid_until.asc(), AccessGrant.id.asc())
        ).scalars().all()
        db.rollback()
        print(f"DUE_ACTIVE_GRANTS={len(due_ids)}")

        if MODE == "check":
            print("RESULT=PASS_DOMAIN_V2_EXPIRY_CHECK")
            return 0

        grants_expired = 0
        slots_retired = 0
        disable_jobs_created = 0
        superseded_provision_jobs = 0
        commercial_accounts_expired = 0
        referrals_revoked = 0
        failures = []
        wake_agent = quantity_wakeup

        for grant_id in due_ids:
            try:
                result = _process_due_grant(db, grant_id=grant_id, now=now)
                if result is None:
                    db.rollback()
                    continue
                db.commit()
                grants_expired += 1
                slots_retired += result["slots_retired"]
                disable_jobs_created += result["disable_jobs_created"]
                superseded_provision_jobs += result["superseded_provision_jobs"]
                commercial_accounts_expired += result["commercial_accounts_expired"]
                referrals_revoked += result["referrals_revoked"]
                wake_agent = wake_agent or bool(result["slots_retired"])
                print("EXPIRED_GRANT=" f"{result['grant_id']} configurations={result['slot_count']} " f"valid_until={result['valid_until']}")
            except Exception as exc:
                db.rollback()
                failures.append((str(grant_id), type(exc).__name__, str(exc)))

        if wake_agent:
            trigger_wg_access_agent_best_effort()

        print(f"QUANTITY_TRANSITIONS_APPLIED={quantity_transitions_applied}")
        print(f"QUANTITY_CONFIGURATIONS_CREATED={quantity_configurations_created}")
        print(f"QUANTITY_RETIREMENTS_REQUESTED={quantity_retirements_requested}")
        print(f"GRANTS_EXPIRED={grants_expired}")
        print(f"SLOTS_RETIREMENT_REQUESTED={slots_retired}")
        print(f"DISABLE_JOBS_CREATED={disable_jobs_created}")
        print(f"SUPERSEDED_PROVISION_JOBS={superseded_provision_jobs}")
        print(f"COMMERCIAL_ACCOUNTS_EXPIRED={commercial_accounts_expired}")
        print(f"REFERRALS_REVOKED={referrals_revoked}")
        print(f"EXPIRY_FAILURES={len(failures)}")
        for grant_id, exc_type, message in failures:
            print(f"EXPIRY_FAILURE grant={grant_id} type={exc_type} detail={message}", file=sys.stderr)
        if failures:
            print("RESULT=FAIL_DOMAIN_V2_EXPIRY")
            return 1
        print("RESULT=PASS_DOMAIN_V2_EXPIRY")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
PY
} 9>"$LOCK" 2>&1 | tee -a "$out"
