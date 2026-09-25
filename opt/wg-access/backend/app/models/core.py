from datetime import datetime
import uuid

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    Index,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint("referral_limit >= 0", name="users_referral_limit_nonnegative"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(320), nullable=False, index=True, unique=True)
    display_name: Mapped[str | None] = mapped_column(String(160), nullable=True)
    admin_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    referrals_enabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("false"), nullable=False)
    referral_limit: Mapped[int] = mapped_column(Integer, default=3, server_default=text("3"), nullable=False)
    email_verified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    deletion_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)

    orders: Mapped[list["Order"]] = relationship(back_populates="user")
    peers: Mapped[list["Peer"]] = relationship(back_populates="user")


class Plan(Base):
    __tablename__ = "plans"
    __table_args__ = (
        CheckConstraint("default_wireguard_limit >= 0", name="plans_default_wireguard_limit_nonnegative"),
        CheckConstraint("default_amneziawg_limit >= 0", name="plans_default_amneziawg_limit_nonnegative"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    code: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    display_name: Mapped[str] = mapped_column(String(160), nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    default_wireguard_limit: Mapped[int] = mapped_column(Integer, default=3, nullable=False)
    default_amneziawg_limit: Mapped[int] = mapped_column(Integer, default=3, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)


class AccessGrant(Base):
    __tablename__ = "access_grants"
    __table_args__ = (
        UniqueConstraint("source_type", "source_ref", name="uq_access_grants_source"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    plan_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("plans.id"), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    source_type: Mapped[str] = mapped_column(String(32), nullable=False)
    source_ref: Mapped[str | None] = mapped_column(String(160), nullable=True)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)


class AccessGrantProtocolLimit(Base):
    __tablename__ = "access_grant_protocol_limits"
    __table_args__ = (
        CheckConstraint("protocol IN ('wireguard','amneziawg')", name="access_grant_protocol_limits_protocol_check"),
        CheckConstraint("profile_limit >= 0", name="access_grant_protocol_limits_profile_limit_nonnegative"),
    )

    access_grant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("access_grants.id", ondelete="CASCADE"), primary_key=True)
    protocol: Mapped[str] = mapped_column(String(32), primary_key=True)
    profile_limit: Mapped[int] = mapped_column(Integer, nullable=False)


class BulkInviteCampaign(Base):
    __tablename__ = "bulk_invite_campaigns"
    __table_args__ = (
        CheckConstraint("max_registrations >= 1", name="bulk_invite_campaigns_max_positive"),
        CheckConstraint("used_count >= 0 AND used_count <= max_registrations", name="bulk_invite_campaigns_used_count_range"),
        CheckConstraint("trial_days >= 1", name="bulk_invite_campaigns_trial_days_positive"),
        CheckConstraint("recipient_referral_limit >= 0", name="bulk_invite_campaigns_recipient_referral_limit_nonnegative"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    token_hash: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    label: Mapped[str] = mapped_column(String(160), nullable=False)
    # Soft reference by design: historical plans.id is not a live-FK-safe target.
    plan_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    max_registrations: Mapped[int] = mapped_column(Integer, nullable=False)
    used_count: Mapped[int] = mapped_column(Integer, default=0, server_default=text("0"), nullable=False)
    trial_days: Mapped[int] = mapped_column(Integer, nullable=False)
    recipient_referrals_enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default=text("true"), nullable=False)
    recipient_referral_limit: Mapped[int] = mapped_column(Integer, default=3, server_default=text("3"), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)


class Invite(Base):
    __tablename__ = "invites"
    __table_args__ = (
        CheckConstraint("max_uses >= 1", name="invites_max_uses_positive"),
        CheckConstraint("used_count >= 0 AND used_count <= max_uses", name="invites_used_count_range"),
        CheckConstraint("wireguard_profile_limit >= 0", name="invites_wireguard_profile_limit_nonnegative"),
        CheckConstraint("recipient_referral_limit >= 0", name="invites_recipient_referral_limit_nonnegative"),
        CheckConstraint("created_by_kind IN ('admin','user','system')", name="invites_created_by_kind_check"),
        CheckConstraint(
            "bulk_campaign_id IS NULL OR (intended_email IS NOT NULL AND created_by_kind = 'system' AND created_by_user_id IS NULL AND max_uses = 1)",
            name="invites_bulk_child_shape_check",
        ),
        UniqueConstraint("bulk_campaign_id", "intended_email", name="uq_invites_bulk_campaign_email"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    token_hash: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_by_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    created_by_label: Mapped[str] = mapped_column(String(320), nullable=False)
    intended_email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    pending_email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    wireguard_profile_limit: Mapped[int | None] = mapped_column(Integer, nullable=True)
    plan_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("plans.id"), nullable=True)
    bulk_campaign_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("bulk_invite_campaigns.id"),
        nullable=True,
        index=True,
    )
    recipient_referrals_enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default=text("true"), nullable=False)
    recipient_referral_limit: Mapped[int] = mapped_column(Integer, default=3, server_default=text("3"), nullable=False)
    max_uses: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    used_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)


class InviteRedemption(Base):
    __tablename__ = "invite_redemptions"
    __table_args__ = (
        UniqueConstraint("invite_id", "user_id", name="uq_invite_redemptions_invite_user"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    invite_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("invites.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    redeemed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)


class MagicLinkToken(Base):
    __tablename__ = "magic_link_tokens"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    token_hash: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    email: Mapped[str] = mapped_column(String(320), nullable=False, index=True)
    user_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True)
    invite_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("invites.id", ondelete="CASCADE"), nullable=True, index=True)
    purpose: Mapped[str] = mapped_column(String(32), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)


class AuthSession(Base):
    __tablename__ = "auth_sessions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ConnectionSlot(Base):
    __tablename__ = "connection_slots"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # Legacy rows may retain owner UUIDs whose users were historically deleted.
    # New application-created slots still use the authenticated user's UUID.
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    access_grant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("access_grants.id", ondelete="CASCADE"), nullable=False, index=True)
    node_id: Mapped[str] = mapped_column(String(64), nullable=False)
    label: Mapped[str | None] = mapped_column(String(160), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)


class ConnectionProfile(Base):
    __tablename__ = "connection_profiles"
    __table_args__ = (
        CheckConstraint("protocol IN ('wireguard','amneziawg')", name="connection_profiles_protocol_check"),
        UniqueConstraint("connection_slot_id", "protocol", name="uq_connection_profiles_slot_protocol"),
        Index(
            "uq_connection_profiles_node_tunnel_ip_reserved",
            "node_id",
            "tunnel_ip",
            unique=True,
            postgresql_where=text("tunnel_ip IS NOT NULL"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    connection_slot_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("connection_slots.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    access_grant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("access_grants.id", ondelete="CASCADE"), nullable=False, index=True)
    protocol: Mapped[str] = mapped_column(String(32), nullable=False)
    node_id: Mapped[str] = mapped_column(String(64), nullable=False)
    label: Mapped[str | None] = mapped_column(String(160), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    tunnel_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    tunnel_ip_reserved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    tunnel_ip_released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class PeerCredential(Base):
    __tablename__ = "peer_credentials"
    __table_args__ = (
        CheckConstraint("revision >= 1", name="peer_credentials_revision_positive"),
        CheckConstraint("key_version >= 1", name="peer_credentials_key_version_positive"),
        UniqueConstraint("connection_profile_id", "revision", name="uq_peer_credentials_profile_revision"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    connection_profile_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("connection_profiles.id", ondelete="CASCADE"), nullable=False, index=True)
    revision: Mapped[int] = mapped_column(Integer, nullable=False)
    public_key: Mapped[str | None] = mapped_column(String(128), nullable=True, unique=True)
    secret_ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    key_version: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False, index=True)
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    actor_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    event_type: Mapped[str] = mapped_column(String(96), nullable=False, index=True)
    object_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    object_id: Mapped[str | None] = mapped_column(String(160), nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    payload_json: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)


class BillingOffer(Base):
    __tablename__ = "billing_offers"
    __table_args__ = (
        CheckConstraint("currency = 'RUB'", name="billing_offers_currency_rub"),
        CheckConstraint("base_slot_quantity >= 1", name="billing_offers_base_slot_quantity_positive"),
        CheckConstraint("base_monthly_kopeks >= 0", name="billing_offers_base_monthly_kopeks_nonnegative"),
        CheckConstraint("extra_slot_monthly_kopeks >= 0", name="billing_offers_extra_slot_monthly_kopeks_nonnegative"),
        CheckConstraint("trial_days >= 1", name="billing_offers_trial_days_positive"),
        CheckConstraint("max_slot_quantity >= base_slot_quantity", name="billing_offers_max_slot_quantity_valid"),
        CheckConstraint("active_referral_invite_limit >= 0", name="billing_offers_referral_limit_nonnegative"),
        UniqueConstraint("plan_id", name="uq_billing_offers_plan_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    code: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    currency: Mapped[str] = mapped_column(String(3), default="RUB", nullable=False)
    base_slot_quantity: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    base_monthly_kopeks: Mapped[int] = mapped_column(Integer, nullable=False)
    extra_slot_monthly_kopeks: Mapped[int] = mapped_column(Integer, nullable=False)
    trial_days: Mapped[int] = mapped_column(Integer, default=7, nullable=False)
    max_slot_quantity: Mapped[int] = mapped_column(Integer, default=3, nullable=False)
    active_referral_invite_limit: Mapped[int] = mapped_column(Integer, default=3, nullable=False)
    # Live plans.id has historical referenced-key drift. Do not add an ORM FK
    # that the accepted production schema cannot truthfully enforce; P29C links
    # the deterministic internal commercial plan at the service boundary.
    plan_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)


class BillingAccount(Base):
    __tablename__ = "billing_accounts"
    __table_args__ = (
        CheckConstraint("status IN ('trial','active_paid','past_due','expired')", name="billing_accounts_status_check"),
        CheckConstraint("billing_mode IN ('manual','recurring')", name="billing_accounts_mode_check"),
        CheckConstraint("slot_quantity >= 1", name="billing_accounts_slot_quantity_positive"),
        CheckConstraint("pending_slot_quantity IS NULL OR pending_slot_quantity >= 1", name="billing_accounts_pending_slot_quantity_positive"),
        CheckConstraint("current_period_end > current_period_start", name="billing_accounts_period_positive"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # Legacy users.id is a service-validated soft reference because the accepted
    # live table is not a valid new FK target. access_grants.id is a proven FK
    # target and remains database-enforced.
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, unique=True, index=True)
    access_grant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("access_grants.id"), nullable=False, unique=True, index=True)
    offer_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("billing_offers.id"), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    billing_mode: Mapped[str] = mapped_column(String(16), nullable=False)
    slot_quantity: Mapped[int] = mapped_column(Integer, nullable=False)
    pending_slot_quantity: Mapped[int | None] = mapped_column(Integer, nullable=True)
    current_period_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    current_period_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    grace_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    payment_method_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    cancel_at_period_end: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    next_charge_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)


class BillingPayment(Base):
    __tablename__ = "billing_payments"
    __table_args__ = (
        CheckConstraint("provider = 'yookassa'", name="billing_payments_provider_yookassa"),
        CheckConstraint("kind IN ('initial','manual_renewal','auto_renewal','upgrade')", name="billing_payments_kind_check"),
        CheckConstraint("status IN ('created','pending','succeeded','canceled')", name="billing_payments_status_check"),
        CheckConstraint("amount_kopeks >= 0", name="billing_payments_amount_nonnegative"),
        CheckConstraint("currency = 'RUB'", name="billing_payments_currency_rub"),
        CheckConstraint("quantity_before >= 1", name="billing_payments_quantity_before_positive"),
        CheckConstraint("quantity_after >= 1", name="billing_payments_quantity_after_positive"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    billing_account_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("billing_accounts.id", ondelete="SET NULL"), nullable=True, index=True)
    provider: Mapped[str] = mapped_column(String(32), default="yookassa", nullable=False)
    provider_payment_id: Mapped[str | None] = mapped_column(String(128), nullable=True, unique=True)
    idempotence_key: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    provider_status: Mapped[str | None] = mapped_column(String(64), nullable=True)
    amount_kopeks: Mapped[int] = mapped_column(Integer, nullable=False)
    currency: Mapped[str] = mapped_column(String(3), default="RUB", nullable=False)
    quantity_before: Mapped[int] = mapped_column(Integer, nullable=False)
    quantity_after: Mapped[int] = mapped_column(Integer, nullable=False)
    target_period_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    target_period_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    succeeded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


# Legacy compatibility tables remain mapped while the existing agent/read APIs
# are retired incrementally. They are not Domain V2 entitlement authority.
class InviteCode(Base):
    __tablename__ = "invite_codes"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    code: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    max_uses: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    used_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)


class Order(Base):
    __tablename__ = "orders"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)
    access_grant_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("access_grants.id", ondelete="SET NULL"), nullable=True, index=True)
    plan_code: Mapped[str] = mapped_column(String(64), nullable=False)
    months: Mapped[int] = mapped_column(Integer, nullable=False)
    amount_rub: Mapped[float] = mapped_column(Numeric(10, 2), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="created", nullable=False, index=True)
    yookassa_payment_id: Mapped[str | None] = mapped_column(String(128), nullable=True, unique=True)
    idempotence_key: Mapped[str | None] = mapped_column(String(128), nullable=True, unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    paid_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped["User"] = relationship(back_populates="orders")


class Subscription(Base):
    __tablename__ = "subscriptions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), default="active", nullable=False, index=True)
    plan_code: Mapped[str] = mapped_column(String(64), nullable=False)
    auto_renew: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    paid_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    payment_method_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    next_charge_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    retry_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    canceled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Peer(Base):
    __tablename__ = "peers"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)
    node_id: Mapped[str] = mapped_column(String(64), default="ddn-test", nullable=False, index=True)
    public_key: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    preshared_key: Mapped[str] = mapped_column(String(128), nullable=False)
    tunnel_ip: Mapped[str] = mapped_column(String(64), nullable=False)
    paid_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped["User"] = relationship(back_populates="peers")


class ProvisioningJob(Base):
    __tablename__ = "provisioning_jobs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    node_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    peer_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("peers.id"), nullable=True, index=True)
    connection_profile_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("connection_profiles.id", ondelete="CASCADE"), nullable=True, index=True)
    operation_id: Mapped[str | None] = mapped_column(String(128), nullable=True, unique=True)
    desired_generation: Mapped[str | None] = mapped_column(String(128), nullable=True)
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    payload_json: Mapped[dict] = mapped_column(JSONB, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="pending", nullable=False, index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
