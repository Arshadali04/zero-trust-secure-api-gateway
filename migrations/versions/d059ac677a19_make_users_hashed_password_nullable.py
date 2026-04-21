"""Make users.hashed_password nullable

Revision ID: d059ac677a19
Revises:
Create Date: 2026-04-19 20:15:26.032251
"""
from alembic import op
import sqlalchemy as sa

revision = "d059ac677a19"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # SQLite-safe alter using batch mode
    with op.batch_alter_table("users") as batch_op:
        batch_op.alter_column(
            "hashed_password",
            existing_type=sa.VARCHAR(length=255),
            nullable=True,
        )


def downgrade() -> None:
    with op.batch_alter_table("users") as batch_op:
        batch_op.alter_column(
            "hashed_password",
            existing_type=sa.VARCHAR(length=255),
            nullable=False,
        )