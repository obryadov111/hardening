"""scan runs: один прогон организации на много хостов

Снимок хоста остаётся в scan_snapshots. Прогон (scan_runs) собирает снимки одного окна:
автоокно по расписанию агентов или ручное. Уже накопленные снимки раскладываются волнами
по двое локальных суток от полуночи первого снимка плюс час RandomDelay — так отдельный
скан на каждый ПК за 2–3 ноября становится одним прогоном. Повторный снимок того же
хоста в волне не входит в прогон (остаётся в таблице, run_id пустой).

Оценка прогона не хранится: её считают по суммам снимков. Индекс run_id — страница
прогона на сотни хостов. Уникальность (run_id, asset_id) — один хост в прогоне.

Revision ID: f0c2a7e91b54
Revises: a1d9c4f27e63
Create Date: 2026-11-08 00:00:00.000000

"""
from collections.abc import Sequence
from datetime import UTC, datetime
from uuid import uuid4
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision: str = "f0c2a7e91b54"
down_revision: str | Sequence[str] | None = "a1d9c4f27e63"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ZERO = "00000000-0000-0000-0000-000000000000"
BACKFILL_NOTE = "Собрано из отдельных снимков при обновлении: волна двое суток плюс час RandomDelay"


def upgrade() -> None:
    op.create_table(
        "scan_runs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", UUID(as_uuid=True),
                  sa.ForeignKey("public.client_organizations.id"), nullable=False),
        sa.Column("environment_id", UUID(as_uuid=True),
                  sa.ForeignKey("public.environments.id", ondelete="SET NULL"), nullable=True),
        sa.Column("run_number", sa.Integer(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("schedule", sa.Text(), nullable=False),
        sa.Column("label", sa.Text(), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("opened_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_ends_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("opened_by", UUID(as_uuid=True),
                  sa.ForeignKey("public.users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("closed_by", UUID(as_uuid=True),
                  sa.ForeignKey("public.users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("status IN ('open', 'closed')", name="ck_scan_runs_status"),
        sa.CheckConstraint("source IN ('auto', 'manual')", name="ck_scan_runs_source"),
        sa.CheckConstraint("schedule IN ('daily', 'weekly', 'manual')", name="ck_scan_runs_schedule"),
        schema="public",
    )
    op.create_index("uq_scan_runs_org_number", "scan_runs", ["organization_id", "run_number"],
                    unique=True, schema="public")
    op.create_index("ix_scan_runs_org_opened", "scan_runs", ["organization_id", "opened_at"], schema="public")
    op.execute(
        f"""
        CREATE UNIQUE INDEX uq_scan_runs_one_open
        ON public.scan_runs (organization_id, (COALESCE(environment_id, '{ZERO}'::uuid)))
        WHERE status = 'open'
        """
    )
    op.create_table(
        "organization_scan_settings",
        sa.Column("organization_id", UUID(as_uuid=True),
                  sa.ForeignKey("public.client_organizations.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("schedule", sa.Text(), nullable=False, server_default="daily"),
        sa.CheckConstraint("schedule IN ('daily', 'weekly')", name="ck_org_scan_schedule"),
        schema="public",
    )
    op.add_column("scan_snapshots", sa.Column("run_id", UUID(as_uuid=True), nullable=True), schema="public")
    op.add_column("scan_snapshots", sa.Column("asset_id", UUID(as_uuid=True), nullable=True), schema="public")
    op.create_foreign_key(
        "fk_scan_snapshots_run_id", "scan_snapshots", "scan_runs",
        ["run_id"], ["id"], source_schema="public", referent_schema="public", ondelete="SET NULL",
    )
    op.create_foreign_key(
        "fk_scan_snapshots_asset_id", "scan_snapshots", "assets",
        ["asset_id"], ["id"], source_schema="public", referent_schema="public", ondelete="SET NULL",
    )
    op.execute(
        """
        UPDATE scan_snapshots s
        SET asset_id = sub.asset_id
        FROM (
            SELECT DISTINCT ON (snapshot_id) snapshot_id, asset_id
            FROM scan_check_results
            WHERE asset_id IS NOT NULL
            ORDER BY snapshot_id, checked_at DESC NULLS LAST
        ) sub
        WHERE s.id = sub.snapshot_id
        """
    )
    _backfill()
    op.execute(
        """
        CREATE INDEX ix_scan_snapshots_run_id
        ON public.scan_snapshots (run_id)
        WHERE run_id IS NOT NULL
        """
    )
    op.execute(
        """
        CREATE UNIQUE INDEX uq_scan_snapshots_run_asset
        ON public.scan_snapshots (run_id, asset_id)
        WHERE run_id IS NOT NULL AND asset_id IS NOT NULL
        """
    )
    op.create_index("ix_scan_snapshots_asset_id", "scan_snapshots", ["asset_id"], schema="public")
    op.execute(
        """
        CREATE INDEX ix_scan_check_results_snapshot_fail
        ON public.scan_check_results (snapshot_id)
        WHERE status = 'fail'
        """
    )


def _backfill() -> None:
    """Та же раскладка, что plan_backfill: двое суток от полуночи первого снимка волны."""
    from app.core.config import settings
    from app.services.scan_runs import plan_backfill

    bind = op.get_bind()
    rows = bind.execute(sa.text("""
        SELECT id, organization_id, asset_id, scan_number,
               COALESCE(started_at, created_at) AS ts
        FROM scan_snapshots
        WHERE organization_id IS NOT NULL
        ORDER BY organization_id, COALESCE(started_at, created_at), scan_number
    """)).mappings().all()
    if not rows:
        return
    try:
        tz = ZoneInfo(settings.DISPLAY_TIMEZONE)
    except ZoneInfoNotFoundError:
        tz = ZoneInfo("UTC")
    now = datetime.now(UTC)
    for plan in plan_backfill(rows, tz, now):
        run_id = uuid4()
        bind.execute(sa.text("""
            INSERT INTO scan_runs (
                id, organization_id, run_number, status, source, schedule, label, notes,
                opened_at, window_ends_at, closed_at, created_at
            ) VALUES (
                :id, :org, :num, :status, 'auto', 'daily', :label, :notes,
                :opened, :ends, :closed, :created
            )
        """), {
            "id": run_id,
            "org": plan["organization_id"],
            "num": plan["run_number"],
            "status": plan["status"],
            "label": plan["label"],
            "notes": BACKFILL_NOTE,
            "opened": plan["opened_at"],
            "ends": plan["window_ends_at"],
            "closed": plan["closed_at"],
            "created": plan["opened_at"],
        })
        if plan["member_ids"]:
            bind.execute(
                sa.text("UPDATE scan_snapshots SET run_id = :run WHERE id = :id"),
                [{"run": run_id, "id": snapshot_id} for snapshot_id in plan["member_ids"]],
            )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS public.ix_scan_check_results_snapshot_fail")
    op.execute("DROP INDEX IF EXISTS public.uq_scan_snapshots_run_asset")
    op.execute("DROP INDEX IF EXISTS public.ix_scan_snapshots_run_id")
    op.drop_index("ix_scan_snapshots_asset_id", table_name="scan_snapshots", schema="public")
    op.drop_constraint("fk_scan_snapshots_asset_id", "scan_snapshots", schema="public", type_="foreignkey")
    op.drop_constraint("fk_scan_snapshots_run_id", "scan_snapshots", schema="public", type_="foreignkey")
    op.drop_column("scan_snapshots", "asset_id", schema="public")
    op.drop_column("scan_snapshots", "run_id", schema="public")
    op.drop_table("organization_scan_settings", schema="public")
    op.execute("DROP INDEX IF EXISTS public.uq_scan_runs_one_open")
    op.drop_index("ix_scan_runs_org_opened", table_name="scan_runs", schema="public")
    op.drop_index("uq_scan_runs_org_number", table_name="scan_runs", schema="public")
    op.drop_table("scan_runs", schema="public")
