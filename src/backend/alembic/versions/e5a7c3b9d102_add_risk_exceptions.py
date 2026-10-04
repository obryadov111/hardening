"""add risk_exceptions (принятый риск)

Исключение — решение администратора организации не устранять конкретное нарушение: проверка
(код правила или id проверки пака) на одном активе или на всех активах организации, с
обоснованием и, по желанию, сроком действия. Отзыв не удаляет запись (revoked_at), чтобы
оставалась история решений.

Статус проверки при этом остаётся фактом (fail); принятое нарушение помечается ссылкой
risk_exception_id и не входит в compliance score. В снимке ссылка фиксирует, что риск был
принят на момент прогона; scan_snapshots.accepted_risks — их число.

Revision ID: e5a7c3b9d102
Revises: d91b3f7a2c64
Create Date: 2026-10-04 15:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

# revision identifiers, used by Alembic.
revision: str = 'e5a7c3b9d102'
down_revision: Union[str, Sequence[str], None] = 'd91b3f7a2c64'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "risk_exceptions",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("organization_id", UUID(as_uuid=True), sa.ForeignKey("public.client_organizations.id", ondelete="CASCADE"), nullable=False),
        # NULL — исключение действует на все активы организации.
        sa.Column("asset_id", UUID(as_uuid=True), sa.ForeignKey("public.assets.id", ondelete="CASCADE"), nullable=True),
        sa.Column("check_key", sa.Text(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", UUID(as_uuid=True), sa.ForeignKey("public.users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", UUID(as_uuid=True), sa.ForeignKey("public.users.id", ondelete="SET NULL"), nullable=True),
        schema="public",
    )
    op.create_index("ix_risk_exceptions_org_check", "risk_exceptions", ["organization_id", "check_key"], schema="public")

    for table in ("hardening_checks", "scan_check_results"):
        op.add_column(
            table,
            sa.Column("risk_exception_id", UUID(as_uuid=True), sa.ForeignKey("public.risk_exceptions.id", ondelete="SET NULL"), nullable=True),
            schema="public",
        )
    op.add_column("scan_snapshots", sa.Column("accepted_risks", sa.Integer(), nullable=False, server_default="0"), schema="public")


def downgrade() -> None:
    op.drop_column("scan_snapshots", "accepted_risks", schema="public")
    for table in ("scan_check_results", "hardening_checks"):
        op.drop_column(table, "risk_exception_id", schema="public")
    op.drop_index("ix_risk_exceptions_org_check", table_name="risk_exceptions", schema="public")
    op.drop_table("risk_exceptions", schema="public")
