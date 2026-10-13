"""software search indexes: name order and trigram search for the inventory page

Нагрузочный тест (1000 хостов, 1,5 млн строк ПО): первая страница «Инвентаризации ПО» — 3,8 с (сортировка
по названию без индекса), поиск — 11 с (ILIKE полным проходом). Индекс по названию и триграммный индекс
(pg_trgm — стандартное расширение PostgreSQL) по «название версия производитель».

Revision ID: c9f2a7e4d815
Revises: b4e8d1f6a2c9
Create Date: 2026-10-13 00:00:00.000000

"""
from collections.abc import Sequence

from alembic import op

revision: str = "c9f2a7e4d815"
down_revision: str | Sequence[str] | None = "b4e8d1f6a2c9"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# То же выражение — в запросе (app/api/routes/data.py, SOFTWARE_SEARCH): иначе индекс не используется.
SEARCH_EXPR = "(coalesce(name, '') || ' ' || coalesce(version, '') || ' ' || coalesce(vendor, ''))"


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
    op.create_index("ix_software_name", "software", ["name"], schema="public")
    op.execute(f"CREATE INDEX ix_software_search ON public.software USING gin ({SEARCH_EXPR} gin_trgm_ops)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS public.ix_software_search")
    op.drop_index("ix_software_name", table_name="software", schema="public")
