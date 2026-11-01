"""Create scan_records table.

Revision ID: 0001_create_scan_records
Revises:
Create Date: 2026-10-20 00:00:00

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "0001_create_scan_records"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "scan_records",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("owner_hash", sa.String(length=64), nullable=False),
        sa.Column("url_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("display_url", sa.String(length=512), nullable=False),
        sa.Column("host", sa.String(length=255), nullable=False),
        sa.Column("normalized_url", sa.Text(), nullable=True),
        sa.Column("verdict", sa.String(length=32), nullable=False),
        sa.Column("heuristic_index", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("detector_version", sa.String(length=32), nullable=False),
        sa.Column("model_version", sa.String(length=64), nullable=True),
        sa.Column("is_demo", sa.Boolean(), nullable=False),
        sa.Column("findings", sa.JSON(), nullable=False),
        sa.Column("provider_results", sa.JSON(), nullable=False),
        sa.Column("ml_result", sa.JSON(), nullable=True),
        sa.Column("component_status", sa.JSON(), nullable=False),
        sa.Column("result", sa.JSON(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scan_records")),
    )
    with op.batch_alter_table("scan_records", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_scan_records_created_at"), ["created_at"], unique=False)
        batch_op.create_index(batch_op.f("ix_scan_records_expires_at"), ["expires_at"], unique=False)
        batch_op.create_index(batch_op.f("ix_scan_records_owner_hash"), ["owner_hash"], unique=False)
        batch_op.create_index(batch_op.f("ix_scan_records_url_fingerprint"), ["url_fingerprint"], unique=False)
        batch_op.create_index(batch_op.f("ix_scan_records_host"), ["host"], unique=False)
        batch_op.create_index(batch_op.f("ix_scan_records_verdict"), ["verdict"], unique=False)
        batch_op.create_index(batch_op.f("ix_scan_records_is_demo"), ["is_demo"], unique=False)
        batch_op.create_index("ix_scan_records_owner_created", ["owner_hash", "created_at"], unique=False)


def downgrade():
    with op.batch_alter_table("scan_records", schema=None) as batch_op:
        batch_op.drop_index("ix_scan_records_owner_created")
        batch_op.drop_index(batch_op.f("ix_scan_records_is_demo"))
        batch_op.drop_index(batch_op.f("ix_scan_records_verdict"))
        batch_op.drop_index(batch_op.f("ix_scan_records_host"))
        batch_op.drop_index(batch_op.f("ix_scan_records_url_fingerprint"))
        batch_op.drop_index(batch_op.f("ix_scan_records_owner_hash"))
        batch_op.drop_index(batch_op.f("ix_scan_records_expires_at"))
        batch_op.drop_index(batch_op.f("ix_scan_records_created_at"))

    op.drop_table("scan_records")
