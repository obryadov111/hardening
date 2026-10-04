"""add bdu (Банк данных угроз ФСТЭК: уязвимости и уязвимое ПО)

Локальная копия БДУ для сопоставления установленного ПО с уязвимыми версиями. Загружается командой
`python -m app.commands.bdu import <vulxml.zip>` из официальной выгрузки ФСТЭК; при повторной загрузке
таблицы заменяются целиком.

- bdu_vulnerabilities — уязвимость: CVSS 3/2, эксплуатация, статус устранения, CVE, рекомендация;
- bdu_software — уязвимое ПО с разобранным диапазоном версий (только записи, где версия — диапазон
  или точная версия; «-» и релизы дистрибутивов не загружаются);
- bdu_imports — журнал загрузок (когда, сколько).

Revision ID: f3c1a9e7b2d4
Revises: e5a7c3b9d102
Create Date: 2026-10-04 17:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'f3c1a9e7b2d4'
down_revision: Union[str, Sequence[str], None] = 'e5a7c3b9d102'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "bdu_vulnerabilities",
        sa.Column("bdu_id", sa.Text(), primary_key=True),  # BDU:2024-01234
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("cvss3", sa.Numeric(3, 1), nullable=True),
        sa.Column("cvss3_vector", sa.Text(), nullable=True),
        sa.Column("cvss2", sa.Numeric(3, 1), nullable=True),
        sa.Column("exploit_status", sa.Text(), nullable=True),
        sa.Column("incident", sa.Text(), nullable=True),  # «Да» — эксплуатация в реальных атаках
        sa.Column("fix_status", sa.Text(), nullable=True),
        sa.Column("solution", sa.Text(), nullable=True),
        sa.Column("cves", sa.Text(), nullable=True),  # через запятую
        sa.Column("published", sa.Date(), nullable=True),
        schema="public",
    )
    op.create_table(
        "bdu_software",
        sa.Column("id", sa.BigInteger(), sa.Identity(), primary_key=True),
        sa.Column("bdu_id", sa.Text(), sa.ForeignKey("public.bdu_vulnerabilities.bdu_id", ondelete="CASCADE"), nullable=False),
        sa.Column("product", sa.Text(), nullable=False),  # название в нижнем регистре
        sa.Column("vendor", sa.Text(), nullable=True),
        sa.Column("version_expr", sa.Text(), nullable=False),
        sa.Column("lo", sa.Text(), nullable=True),
        sa.Column("lo_incl", sa.Boolean(), nullable=False),
        sa.Column("hi", sa.Text(), nullable=True),
        sa.Column("hi_incl", sa.Boolean(), nullable=False),
        schema="public",
    )
    op.create_index("ix_bdu_software_product", "bdu_software", ["product"], schema="public")
    op.create_table(
        "bdu_imports",
        sa.Column("id", sa.Integer(), sa.Identity(), primary_key=True),
        sa.Column("imported_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("source", sa.Text(), nullable=True),
        sa.Column("vulnerabilities", sa.Integer(), nullable=False),
        sa.Column("software_rows", sa.Integer(), nullable=False),
        sa.Column("skipped_rows", sa.Integer(), nullable=False),
        schema="public",
    )


def downgrade() -> None:
    op.drop_table("bdu_imports", schema="public")
    op.drop_index("ix_bdu_software_product", table_name="bdu_software", schema="public")
    op.drop_table("bdu_software", schema="public")
    op.drop_table("bdu_vulnerabilities", schema="public")
