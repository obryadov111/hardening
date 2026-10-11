"""add scan_snapshots.collection (источник данных снимка)

Откуда агент взял данные: NULL — живой хост или устройство (как раньше), иначе описание источника,
например выгрузка конфигурации: {"source": "offline-config", "files": [{"command", "file", "sha256",
"modified"}], "declared_pack": true}. Проверка по выгрузке не равна проверке живого устройства:
конфигурация могла измениться после выгрузки, — поэтому источник хранится в снимке и виден в отчёте.

Revision ID: b8e3f0a5c217
Revises: a7d2e9c4f1b8
Create Date: 2026-10-11 10:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'b8e3f0a5c217'
down_revision: Union[str, Sequence[str], None] = 'a7d2e9c4f1b8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("scan_snapshots", sa.Column("collection", postgresql.JSONB(), nullable=True), schema="public")


def downgrade() -> None:
    op.drop_column("scan_snapshots", "collection", schema="public")
