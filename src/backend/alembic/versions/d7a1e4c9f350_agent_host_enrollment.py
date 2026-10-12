"""agent host enrollment: key of a site enrolls hosts, each host gets its own key

agent_hosts — хост, зарегистрированный агентом: при первом запуске агент обменивает ключ регистрации
(agent_api_keys, ключ площадки из интерфейса) на собственный ключ хоста. Отчёт по ключу хоста
принимается только с его именем: утечка ключа с одного хоста не даёт подделать отчёты остальных,
отозвать можно один хост. Имя хоста — одно активное в организации (hostname_norm — в нижнем регистре).
agent_api_keys.direct_use — ключ принимается на /api/ingest напрямую, без регистрации: так работали
агенты до регистрации хостов. Для существующих ключей — да (установленные агенты продолжают работать),
новые ключи — только регистрация.

Revision ID: d7a1e4c9f350
Revises: c4f2a8d6e913
Create Date: 2026-10-12 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'd7a1e4c9f350'
down_revision: Union[str, Sequence[str], None] = 'c4f2a8d6e913'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "agent_api_keys", sa.Column("direct_use", sa.Boolean(), nullable=False, server_default=sa.true()), schema="public",
    )
    op.alter_column("agent_api_keys", "direct_use", server_default=sa.false(), schema="public")
    op.create_table(
        "agent_hosts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("public.client_organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("enrollment_key_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("public.agent_api_keys.id", ondelete="SET NULL"), nullable=True),
        sa.Column("hostname", sa.Text(), nullable=False),
        sa.Column("hostname_norm", sa.Text(), nullable=False),
        sa.Column("key_hash", sa.Text(), nullable=False, unique=True),
        sa.Column("os", sa.Text(), nullable=True),
        sa.Column("status", sa.Text(), nullable=False, server_default="active"),
        sa.Column("enrolled_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("enrolled_ip", sa.Text(), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen_ip", sa.Text(), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("status IN ('active', 'revoked', 'replaced')", name="ck_agent_hosts_status"),
        schema="public",
    )
    op.create_index(
        "uq_agent_hosts_org_active_hostname", "agent_hosts", ["organization_id", "hostname_norm"], unique=True,
        schema="public", postgresql_where=sa.text("status <> 'replaced'"),
    )


def downgrade() -> None:
    op.drop_index("uq_agent_hosts_org_active_hostname", table_name="agent_hosts", schema="public")
    op.drop_table("agent_hosts", schema="public")
    op.drop_column("agent_api_keys", "direct_use", schema="public")
