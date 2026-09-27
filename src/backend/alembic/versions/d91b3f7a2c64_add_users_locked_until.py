"""add users.locked_until

Временная блокировка входа после серии неудачных попыток (пароль или код 2FA): до этого момента
вход отклоняется, после — счётчик failed_login_attempts начинается заново. Отдельно от
account_status='blocked': то — ручная блокировка суперадмином, она сама не снимается.

nullable: у существующих пользователей блокировки нет.

Revision ID: d91b3f7a2c64
Revises: c4e8a1d2f905
Create Date: 2026-09-27 12:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'd91b3f7a2c64'
down_revision: Union[str, Sequence[str], None] = 'c4e8a1d2f905'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("users", sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True), schema="public")


def downgrade() -> None:
    op.drop_column("users", "locked_until", schema="public")
