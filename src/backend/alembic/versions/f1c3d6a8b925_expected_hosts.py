"""expected hosts: inventory list (AD export, CSV) to compare with reporting agents

expected_hosts — какие хосты должны отчитываться: выгрузка компьютеров из AD или любой список. Отчёт об
охвате сравнивает его с хостами, приславшими данные: кто молчит, где агент не установлен, кто отчитывается,
но в списке не значится. hostname_norm — короткое имя в нижнем регистре (PC-001.corp.local → pc-001):
агент на Windows присылает имя NetBIOS, в AD — DNS-имя. Список заменяется целиком при каждой загрузке.

Revision ID: f1c3d6a8b925
Revises: e8b2f5a1c470
Create Date: 2026-10-12 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'f1c3d6a8b925'
down_revision: Union[str, Sequence[str], None] = 'e8b2f5a1c470'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "expected_hosts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("public.client_organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("hostname", sa.Text(), nullable=False),
        sa.Column("hostname_norm", sa.Text(), nullable=False),
        sa.Column("os", sa.Text(), nullable=True),
        sa.Column("last_logon", sa.Text(), nullable=True),
        sa.Column("source", sa.Text(), nullable=True),
        sa.Column("imported_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("imported_by", sa.Text(), nullable=True),
        sa.UniqueConstraint("organization_id", "hostname_norm", name="uq_expected_hosts_org_hostname"),
        schema="public",
    )


def downgrade() -> None:
    op.drop_table("expected_hosts", schema="public")
