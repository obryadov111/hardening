"""add users.password_changed_at

Время последней смены пароля. Токены, выданные раньше, отклоняются (в токене есть iat): после
сброса пароля администратором или смены пароля самим пользователем прежние сессии перестают
работать — иначе украденный токен жил бы ещё до ACCESS_TOKEN_EXPIRE_MINUTES.

nullable: у существующих пользователей значение пустое, их текущие токены продолжают работать.

Revision ID: c4e8a1d2f905
Revises: b7d2e4f18c63
Create Date: 2026-09-27 11:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'c4e8a1d2f905'
down_revision: Union[str, Sequence[str], None] = 'b7d2e4f18c63'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("users", sa.Column("password_changed_at", sa.DateTime(timezone=True), nullable=True), schema="public")


def downgrade() -> None:
    op.drop_column("users", "password_changed_at", schema="public")
