"""Make users.hashed_password nullable (OAuth-only accounts have no password)

Revision ID: d059ac677a19
Revises: a3536f8a2d84
Create Date: 2026-04-19 20:15:26.032251

Re-pointed to follow the initial schema. It previously declared
``down_revision = None`` while a3536f8a2d84 ("initial schema") claimed to follow
*it*, so the chain built ``users`` only after trying to ALTER it.
"""
from alembic import op
import sqlalchemy as sa

revision = "d059ac677a19"
down_revision = "a3536f8a2d84"
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