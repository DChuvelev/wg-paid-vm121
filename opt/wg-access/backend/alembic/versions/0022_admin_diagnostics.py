"""Bounded private Admin diagnostics queue and ZIP delivery.

Revision ID: 0022_admin_diagnostics
Revises: 0021_admin_broadcasts
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, BYTEA

revision = '0022_admin_diagnostics'
down_revision = '0021_admin_broadcasts'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'admin_diagnostic_jobs',
        sa.Column('id', UUID(as_uuid=True), primary_key=True),
        sa.Column('state', sa.String(16), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True)),
        sa.Column('completed_at', sa.DateTime(timezone=True)),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('lease_until', sa.DateTime(timezone=True)),
        sa.Column('lease_token', UUID(as_uuid=True)),
        sa.Column('artifact', BYTEA()),
        sa.Column('artifact_size', sa.Integer()),
        sa.Column('artifact_sha256', sa.String(64)),
        sa.Column('capture_status', sa.String(48)),
        sa.Column('error_code', sa.String(48)),
        sa.CheckConstraint("state IN ('queued','running','ready','partial','failed','expired')", name='admin_diagnostic_state_allowed'),
        sa.CheckConstraint('artifact_size IS NULL OR (artifact_size >= 1 AND artifact_size <= 1048576)', name='admin_diagnostic_size_bounded'),
        sa.CheckConstraint('artifact IS NULL OR octet_length(artifact) <= 1048576', name='admin_diagnostic_blob_bounded'),
    )
    op.create_index('ix_admin_diagnostic_jobs_created_at', 'admin_diagnostic_jobs', ['created_at'])
    op.create_index('uq_admin_diagnostic_single_active', 'admin_diagnostic_jobs', [sa.text('(1)')], unique=True,
                    postgresql_where=sa.text("state IN ('queued','running')"))


def downgrade() -> None:
    op.drop_index('uq_admin_diagnostic_single_active', table_name='admin_diagnostic_jobs')
    op.drop_index('ix_admin_diagnostic_jobs_created_at', table_name='admin_diagnostic_jobs')
    op.drop_table('admin_diagnostic_jobs')
