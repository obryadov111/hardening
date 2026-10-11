"""agent transport over the internet: run_id/collected_at of a run, agent key expiry and last IP

ingestion_batches.run_id — идентификатор прогона, который задаёт агент: прогон из очереди агента
(сервер был недоступен) может прийти повторно — сервер не создаёт второй снимок (уникально в организации).
ingestion_batches.collected_at — когда агент собрал данные (из очереди прогон приходит позже).
agent_api_keys.expires_at / last_used_ip / revoked_at — ключ на объект заказчика со сроком действия,
видно, откуда он использовался последний раз; отзыв фиксируется временем.

Revision ID: c4f2a8d6e913
Revises: b8e3f0a5c217
Create Date: 2026-10-12 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'c4f2a8d6e913'
down_revision: Union[str, Sequence[str], None] = 'b8e3f0a5c217'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("ingestion_batches", sa.Column("run_id", postgresql.UUID(as_uuid=True), nullable=True), schema="public")
    op.add_column("ingestion_batches", sa.Column("collected_at", sa.DateTime(timezone=True), nullable=True), schema="public")
    op.create_index(
        "uq_ingestion_batches_org_run", "ingestion_batches", ["organization_id", "run_id"], unique=True,
        schema="public", postgresql_where=sa.text("run_id IS NOT NULL"),
    )
    op.add_column("agent_api_keys", sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True), schema="public")
    op.add_column("agent_api_keys", sa.Column("last_used_ip", sa.Text(), nullable=True), schema="public")
    op.add_column("agent_api_keys", sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True), schema="public")


def downgrade() -> None:
    op.drop_column("agent_api_keys", "revoked_at", schema="public")
    op.drop_column("agent_api_keys", "last_used_ip", schema="public")
    op.drop_column("agent_api_keys", "expires_at", schema="public")
    op.drop_index("uq_ingestion_batches_org_run", table_name="ingestion_batches", schema="public")
    op.drop_column("ingestion_batches", "collected_at", schema="public")
    op.drop_column("ingestion_batches", "run_id", schema="public")
