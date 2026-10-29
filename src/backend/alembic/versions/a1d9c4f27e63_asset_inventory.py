"""asset inventory: оборудование актива (CPU, ОЗУ, диски, материнка, MAC, UUID) и опц. ПДн

Инвентаризация активов по запросу заказчика: агент собирает паспорт «железа» хоста и, при запуске
с --collect-identity, учётные данные (имя пользователя, домен, доменные группы). Одна строка на актив,
перезаписывается прогоном; при удалении актива удаляется каскадом. ПДн вынесены сюда, а не в assets:
они не участвуют в оценке compliance и требуют отдельного режима обработки.

Revision ID: a1d9c4f27e63
Revises: c9f2a7e4d815
Create Date: 2026-10-29 00:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision: str = "a1d9c4f27e63"
down_revision: str | Sequence[str] | None = "c9f2a7e4d815"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "asset_inventory",
        sa.Column("asset_id", UUID(as_uuid=True),
                  sa.ForeignKey("public.assets.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("mac_address", sa.Text(), nullable=True),
        sa.Column("device_uuid", sa.Text(), nullable=True),
        sa.Column("cpu_model", sa.Text(), nullable=True),
        sa.Column("cpu_cores", sa.Integer(), nullable=True),
        sa.Column("memory_mb", sa.Integer(), nullable=True),
        sa.Column("board_vendor", sa.Text(), nullable=True),
        sa.Column("board_product", sa.Text(), nullable=True),
        sa.Column("disks", JSONB(), nullable=True),
        sa.Column("username", sa.Text(), nullable=True),
        sa.Column("domain", sa.Text(), nullable=True),
        sa.Column("domain_groups", JSONB(), nullable=True),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=True),
        schema="public",
    )


def downgrade() -> None:
    op.drop_table("asset_inventory", schema="public")
