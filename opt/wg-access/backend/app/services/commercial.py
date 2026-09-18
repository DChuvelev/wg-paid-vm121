from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import (
    AccessGrant,
    BillingAccount,
    BillingOffer,
    BillingPayment,
    Invite,
    Plan,
    User,
)
from app.services.domain_v2 import (
    ConfigurationRequestResult,
    create_configuration_request,
    create_grant_from_plan,
    record_audit_event,
    utcnow,
)

COMMERCIAL_OFFER_CODE = "commercial-rub-v1"


class CommercialError(RuntimeError):
    pass


class ReferralNotEligible(CommercialError):
    pass


class CommercialRegistrationRejected(CommercialError):
    pass


@dataclass(frozen=True)
class ReferralEligibility:
    account: BillingAccount
    offer: BillingOffer


@dataclass(frozen=True)
class TrialRegistrationResult:
    account: BillingAccount
    grant: AccessGrant
    configuration: ConfigurationRequestResult


def active_offer_for_plan(
    db: Session,
    *,
    plan_id: uuid.UUID,
) -> BillingOffer | None:
    return db.execute(
        select(BillingOffer).where(
            BillingOffer.plan_id == plan_id,
            BillingOffer.active.is_(True),
        )
    ).scalar_one_or_none()


def commercial_offer(db: Session) -> BillingOffer:
    row = db.execute(
        select(BillingOffer).where(
            BillingOffer.code == COMMERCIAL_OFFER_CODE,
            BillingOffer.active.is_(True),
        )
    ).scalar_one_or_none()
    if row is None:
        raise CommercialError("commercial offer is unavailable")
    return row


def require_referral_eligible(
    db: Session,
    *,
    user_id: uuid.UUID,
    now: datetime | None = None,
    lock_account: bool = False,
) -> ReferralEligibility:
    point = now or utcnow()
    query = select(BillingAccount).where(BillingAccount.user_id == user_id)
    if lock_account:
        query = query.with_for_update()
    account = db.execute(query).scalar_one_or_none()
    if account is None or account.status != "active_paid":
        raise ReferralNotEligible("referral privilege requires active paid access")
    if account.current_period_start > point or account.current_period_end <= point:
        raise ReferralNotEligible("paid period is not active")
    owner = db.execute(select(User).where(User.id == user_id)).scalar_one_or_none()
    if owner is None or owner.deletion_requested_at is not None:
        raise ReferralNotEligible("referral owner is unavailable")
    offer = db.get(BillingOffer, account.offer_id)
    if offer is None or not offer.active:
        raise ReferralNotEligible("commercial offer is unavailable")
    grant = db.execute(select(AccessGrant).where(AccessGrant.id == account.access_grant_id)).scalar_one_or_none()
    if grant is None or grant.user_id != user_id or grant.plan_id != offer.plan_id:
        raise ReferralNotEligible("commercial entitlement linkage is invalid")
    if grant.status != "active" or grant.valid_from > point or (grant.valid_until is not None and grant.valid_until <= point):
        raise ReferralNotEligible("commercial entitlement is not active")
    successful_payment = db.execute(
        select(BillingPayment.id).where(
            BillingPayment.billing_account_id == account.id,
            BillingPayment.status == "succeeded",
            BillingPayment.succeeded_at.is_not(None),
        ).limit(1)
    ).scalar_one_or_none()
    if successful_payment is None:
        raise ReferralNotEligible("successful own payment is required")
    return ReferralEligibility(account=account, offer=offer)


def commercial_referral_invite_is_effective(
    db: Session,
    *,
    invite: Invite,
    now: datetime | None = None,
) -> bool:
    if invite.created_by_kind != "user" or invite.created_by_user_id is None or invite.plan_id is None:
        return False
    offer = active_offer_for_plan(db, plan_id=invite.plan_id)
    if offer is None:
        return False
    try:
        eligibility = require_referral_eligible(
            db,
            user_id=invite.created_by_user_id,
            now=now,
            lock_account=False,
        )
    except ReferralNotEligible:
        return False
    if eligibility.offer.id != offer.id:
        return False
    return int(invite.wireguard_profile_limit or -1) == int(offer.base_slot_quantity)


def create_commercial_trial_registration(
    db: Session,
    *,
    user: User,
    invite: Invite,
    wg_node_id: str,
    now: datetime | None = None,
    request_id: str | None = None,
) -> TrialRegistrationResult:
    point = now or utcnow()
    if invite.created_by_kind != "user" or invite.created_by_user_id is None or invite.plan_id is None:
        raise CommercialRegistrationRejected("invite is not a commercial referral")
    if not commercial_referral_invite_is_effective(db, invite=invite, now=point):
        raise CommercialRegistrationRejected("commercial referral is no longer eligible")
    offer = active_offer_for_plan(db, plan_id=invite.plan_id)
    if offer is None:
        raise CommercialRegistrationRejected("commercial offer is unavailable")
    if int(offer.base_slot_quantity) != 1:
        raise CommercialRegistrationRejected("P29C trial requires one base configuration")
    if int(invite.wireguard_profile_limit or -1) != int(offer.base_slot_quantity):
        raise CommercialRegistrationRejected("commercial referral configuration limit drift")
    if db.execute(select(BillingAccount.id).where(BillingAccount.user_id == user.id)).scalar_one_or_none() is not None:
        raise CommercialRegistrationRejected("commercial account already exists")
    plan = db.get(Plan, invite.plan_id)
    if plan is None or not plan.active:
        raise CommercialRegistrationRejected("commercial plan is unavailable")
    if int(plan.default_wireguard_limit) != 1 or int(plan.default_amneziawg_limit) != 1:
        raise CommercialRegistrationRejected("commercial plan configuration limit drift")

    period_end = point + timedelta(days=int(offer.trial_days))
    grant = create_grant_from_plan(
        db,
        user=user,
        plan=plan,
        source_type="commercial_trial",
        source_ref=str(invite.id),
        valid_from=point,
        valid_until=period_end,
    )
    account = BillingAccount(
        id=uuid.uuid4(),
        user_id=user.id,
        access_grant_id=grant.id,
        offer_id=offer.id,
        status="trial",
        billing_mode="manual",
        slot_quantity=1,
        pending_slot_quantity=None,
        current_period_start=point,
        current_period_end=period_end,
        grace_until=None,
        payment_method_id=None,
        cancel_at_period_end=False,
        next_charge_at=None,
        created_at=point,
        updated_at=point,
    )
    db.add(account)
    db.flush()
    configuration = create_configuration_request(
        db,
        user=user,
        grant_id=grant.id,
        node_id=wg_node_id,
        label=None,
        now=point,
    )
    if configuration.slot.expires_at != period_end:
        raise CommercialRegistrationRejected("trial slot expiry mirror drift")
    for profile in configuration.profiles.values():
        if profile.expires_at != period_end:
            raise CommercialRegistrationRejected("trial profile expiry mirror drift")
        record_audit_event(
            db,
            event_type="profile.requested",
            actor_kind="system",
            actor_user_id=user.id,
            object_type="connection_profile",
            object_id=str(profile.id),
            request_id=request_id,
            payload={"protocol": profile.protocol, "reason": "commercial_trial_registration"},
        )
    record_audit_event(
        db,
        event_type="billing.trial.started",
        actor_kind="system",
        actor_user_id=user.id,
        object_type="billing_account",
        object_id=str(account.id),
        request_id=request_id,
        payload={
            "offer_code": offer.code,
            "trial_days": int(offer.trial_days),
            "slot_quantity": 1,
            "invite_id": str(invite.id),
            "inviter_user_id": str(invite.created_by_user_id),
        },
    )
    return TrialRegistrationResult(account=account, grant=grant, configuration=configuration)
