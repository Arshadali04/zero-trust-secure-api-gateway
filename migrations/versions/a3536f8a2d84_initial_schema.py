"""Initial schema — creates every table from the ORM metadata.

Revision ID: a3536f8a2d84
Revises: None  (this is the root of the chain)
Create Date: 2026-04-21 16:46:14.846619

WHY THIS FILE LOOKS LIKE THIS
-----------------------------
As shipped, this revision had ``upgrade(): pass`` and ``down_revision =
'd059ac677a19'``, i.e. the "initial schema" ran *second*, after a revision that
ALTERs ``users``. So ``alembic upgrade head`` against an empty database failed
with "no such table: users", and the only reason deployment worked at all was
that ``init_db()`` calls ``Base.metadata.create_all`` at startup — which made the
migrations decorative and schema drift undetectable.

The chain is now rooted here, and this revision actually builds the schema. It
does so from ``Base.metadata`` rather than a hand-transcribed list of
``op.create_table`` calls, which is the standard way to adopt Alembic over an
existing model set: there is exactly one definition of the schema (the models),
so this file cannot drift away from them. ``checkfirst=True`` keeps it safe to
stamp or run against a database that ``create_all`` already populated.

Every schema change after this one should be a real
``alembic revision --autogenerate`` diff.
"""
from alembic import op

# revision identifiers, used by Alembic.
revision = 'a3536f8a2d84'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    from gateway.db.models import Base
    import gateway.core.tokens  # noqa: F401  registers RefreshToken on Base

    Base.metadata.create_all(bind=op.get_bind(), checkfirst=True)


def downgrade() -> None:
    from gateway.db.models import Base
    import gateway.core.tokens  # noqa: F401

    Base.metadata.drop_all(bind=op.get_bind())
