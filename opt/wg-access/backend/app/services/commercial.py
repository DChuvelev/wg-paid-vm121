from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import (
    AccessGrant,
    BillingAccount,
    BillingOffer,
    BillingPayment,
    BulkInviteCampaign,
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
TRUSTED_PILOT_PLAN_CODE = "trusted-pilot"


class CommercialError(RuntimeError):
    pass


class ReferralNotEligible(CommercialError):
    pass


class CommercialRegistrationRejected(CommercialError):
    pass


@dataclass(frozen=True)
class ReferralEligibility:
    owner: User
    account: BillingAccount | None
    offer: BillingOffer


@dataclass(frozen=True)
class TrialRegistrationResult:
    account: BillingAccount
    grant: AccessGrant
    configuration: ConfigurationRequestResult


@dataclass(frozen=True)
class ReferralCapability:
    enabled: bool
    limit: int
    active_count: int
    remaining_count: int | None
    can_create: bool


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


def _referral_eligibility(
    db: Session,
    *,
    user_id: uuid.UUID,
    now: datetime | None,
    lock_account: bool,
    require_enabled: bool,
) -> ReferralEligibility:
    point = now or utcnow()

    owner_query = select(User).where(User.id == user_id)
    if lock_account:
        owner_query = owner_query.with_for_update()
    owner = db.execute(owner_query).scalar_one_or_none()
    if owner is None or owner.deletion_requested_at is not None:
        raise ReferralNotEligible("referral owner is unavailable")
    if require_enabled and not bool(owner.referrals_enabled):
        raise ReferralNotEligible("referral privilege is disabled")

    account_query = select(BillingAccount).where(BillingAccount.user_id == user_id)
    if lock_account:
        account_query = account_query.with_for_update()
    account = db.execute(account_query).scalar_one_or_none()

    if account is None:
        trusted_grant = db.execute(
            select(AccessGrant.id)
            .join(Plan, Plan.id == AccessGrant.plan_id)
            .where(
                AccessGrant.user_id == user_id,
                AccessGrant.status == "active",
                AccessGrant.valid_from <= point,
                (AccessGrant.valid_until.is_(None) | (AccessGrant.valid_until > point)),
                Plan.code == TRUSTED_PILOT_PLAN_CODE,
                Plan.active.is_(True),
            )
            .limit(1)
        ).scalar_one_or_none()
        if trusted_grant is None:
            raise ReferralNotEligible("trusted-pilot entitlement is not active")
        return ReferralEligibility(owner=owner, account=None, offer=commercial_offer(db))

    if account.status != "active_paid":
        raise ReferralNotEligible("commercial referral privilege requires active paid access")
    if account.current_period_start > point or account.current_period_end <= point:
        raise ReferralNotEligible("paid period is not active")
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
    return ReferralEligibility(owner=owner, account=account, offer=offer)


def require_referral_eligible(
    db: Session,
    *,
    user_id: uuid.UUID,
    now: datetime | None = None,
    lock_account: bool = False,
) -> ReferralEligibility:
    return _referral_eligibility(
        db,
        user_id=user_id,
        now=now,
        lock_account=lock_account,
        require_enabled=True,
    )


def referral_capability(
    db: Session,
    *,
    user_id: uuid.UUID,
    now: datetime | None = None,
) -> ReferralCapability:
    point = now or utcnow()
    owner = db.execute(select(User).where(User.id == user_id)).scalar_one_or_none()
    if owner is None:
        raise ReferralNotEligible("referral owner is unavailable")
    limit = int(owner.referral_limit)
    if limit < 0:
        raise ReferralNotEligible("referral invite limit is invalid")
    active_count = int(db.execute(
        select(func.count(Invite.id)).where(
            Invite.created_by_kind == "user",
            Invite.created_by_user_id == owner.id,
            Invite.revoked_at.is_(None),
            Invite.used_count < Invite.max_uses,
            (Invite.expires_at.is_(None) | (Invite.expires_at > point)),
        )
    ).scalar_one())
    remaining_count = None if limit == 0 else max(limit - active_count, 0)
    can_create = False
    if bool(owner.referrals_enabled) and (limit == 0 or active_count < limit):
        try:
            require_referral_eligible(db, user_id=owner.id, now=point, lock_account=False)
        except ReferralNotEligible:
            pass
        else:
            can_create = True
    return ReferralCapability(
        enabled=bool(owner.referrals_enabled),
        limit=limit,
        active_count=active_count,
        remaining_count=remaining_count,
        can_create=can_create,
    )


def commercial_invite_is_effective(
    db: Session,
    *,
    invite: Invite,
    now: datetime | None = None,
) -> bool:
    if invite.plan_id is None:
        return False
    offer = active_offer_for_plan(db, plan_id=invite.plan_id)
    if offer is None:
        return False
    if int(invite.wireguard_profile_limit or -1) != int(offer.base_slot_quantity):
        return False
    if invite.bulk_campaign_id is not None:
        campaign = db.get(BulkInviteCampaign, invite.bulk_campaign_id)
        return (
            campaign is not None
            and campaign.plan_id == invite.plan_id
            and invite.created_by_kind == "system"
            and invite.created_by_user_id is None
            and invite.intended_email is not None
            and int(invite.max_uses) == 1
        )
    if invite.created_by_kind == "user":
        if invite.created_by_user_id is None:
            return False
        try:
            eligibility = _referral_eligibility(
                db,
                user_id=invite.created_by_user_id,
                now=now,
                lock_account=False,
                require_enabled=False,
            )
        except ReferralNotEligible:
            return False
        return eligibility.offer.id == offer.id
    return invite.created_by_kind in {"admin", "system"} and invite.created_by_user_id is None


def commercial_referral_invite_is_effective(
    db: Session,
    *,
    invite: Invite,
    now: datetime | None = None,
) -> bool:
    if invite.created_by_kind != "user":
        return False
    return commercial_invite_is_effective(db, invite=invite, now=now)


def create_commercial_trial_registration(
    db: Session,
    *,
    user: User,
    invite: Invite,
    wg_node_id: str,
    now: datetime | None = None,
    request_id: str | None = None,
    bulk_capacity_claimed: bool = False,
) -> TrialRegistrationResult:
    point = now or utcnow()
    if invite.plan_id is None:
        raise CommercialRegistrationRejected("invite is not a commercial onboarding invite")
    if not commercial_invite_is_effective(db, invite=invite, now=point):
        raise CommercialRegistrationRejected("commercial invite is no longer eligible")
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

    campaign = None
    if invite.bulk_campaign_id is not None:
        if not bulk_capacity_claimed:
            raise CommercialRegistrationRejected("bulk invite capacity was not claimed")
        campaign = db.get(BulkInviteCampaign, invite.bulk_campaign_id)
        if campaign is None or campaign.plan_id != invite.plan_id:
            raise CommercialRegistrationRejected("bulk invite campaign is unavailable")
        effective_trial_days = int(campaign.trial_days)
    else:
        if bulk_capacity_claimed:
            raise CommercialRegistrationRejected("unexpected bulk capacity claim")
        if invite.trial_days_override is not None:
            if invite.created_by_kind != "admin":
                raise CommercialRegistrationRejected("trial override is not valid for this invite")
            effective_trial_days = int(invite.trial_days_override)
        else:
            effective_trial_days = int(offer.trial_days)
    if effective_trial_days < 1:
        raise CommercialRegistrationRejected("commercial trial duration is invalid")

    period_end = point + timedelta(days=effective_trial_days)
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
            "trial_days": effective_trial_days,
            "slot_quantity": 1,
            "invite_id": str(invite.id),
            "inviter_user_id": str(invite.created_by_user_id) if invite.created_by_user_id else None,
            "bulk_campaign_id": str(invite.bulk_campaign_id) if invite.bulk_campaign_id else None,
        },
    )
    return TrialRegistrationResult(account=account, grant=grant, configuration=configuration)
