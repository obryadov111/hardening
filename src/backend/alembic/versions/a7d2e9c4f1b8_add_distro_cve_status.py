"""add distro_cve_status (статус CVE в дистрибутиве по OVAL Ubuntu)

Данные Canonical (OVAL по CVE для каждого релиза Ubuntu): для CVE и бинарного пакета — версия, в
которой уязвимость исправлена, или NULL, если исправления пока нет. CVE, которых нет в данных,
дистрибутив считает не затрагивающими релиз либо не отслеживает. Загружается командой
`python -m app.commands.bdu oval <релиз> <файл>`; данные релиза заменяются целиком.

Revision ID: a7d2e9c4f1b8
Revises: f3c1a9e7b2d4
Create Date: 2026-10-04 20:30:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'a7d2e9c4f1b8'
down_revision: Union[str, Sequence[str], None] = 'f3c1a9e7b2d4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "distro_cve_status",
        sa.Column("id", sa.BigInteger(), sa.Identity(), primary_key=True),
        sa.Column("distro", sa.Text(), nullable=False),          # ubuntu
        sa.Column("release", sa.Text(), nullable=False),         # noble
        sa.Column("cve", sa.Text(), nullable=False),
        sa.Column("source_package", sa.Text(), nullable=False),
        sa.Column("binary_package", sa.Text(), nullable=False),
        sa.Column("fixed_version", sa.Text(), nullable=True),    # NULL — исправления пока нет
        sa.Column("priority", sa.Text(), nullable=True),
        sa.Column("usns", sa.Text(), nullable=True),             # через запятую
        schema="public",
    )
    op.create_index("ix_distro_cve_status_lookup", "distro_cve_status", ["distro", "release", "cve"], schema="public")
    op.create_table(
        "distro_oval_imports",
        sa.Column("id", sa.Integer(), sa.Identity(), primary_key=True),
        sa.Column("distro", sa.Text(), nullable=False),
        sa.Column("release", sa.Text(), nullable=False),
        sa.Column("imported_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("source", sa.Text(), nullable=True),
        sa.Column("cves", sa.Integer(), nullable=False),
        sa.Column("rows", sa.Integer(), nullable=False),
        schema="public",
    )


def downgrade() -> None:
    op.drop_table("distro_oval_imports", schema="public")
    op.drop_index("ix_distro_cve_status_lookup", table_name="distro_cve_status", schema="public")
    op.drop_table("distro_cve_status", schema="public")
