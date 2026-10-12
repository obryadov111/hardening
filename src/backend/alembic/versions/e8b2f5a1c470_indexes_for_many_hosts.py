"""indexes for many hosts: foreign keys used on every agent run

Нагрузочный тест (1000 хостов, отчёт сервера: 36 проверок, 1502 программы) показал квадратичный рост:
каждый отчёт удаляет прежний список ПО хоста (DELETE FROM software WHERE asset_id = …), а индекса по
asset_id не было — полный проход по таблице, которая растёт на ~1500 строк с каждым хостом. Удаление ПО
проверяет и ссылки из configs (configs.software_id). Номер скана — MAX(scan_number) по организации, и при
параллельных отчётах номера совпадали (772 скана — 110 номеров): индекс уникальный, номер выдаётся под
блокировкой (routes/ingest.py). История проверок актива и исключения риска — по asset_id.

Revision ID: e8b2f5a1c470
Revises: d7a1e4c9f350
Create Date: 2026-10-12 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'e8b2f5a1c470'
down_revision: Union[str, Sequence[str], None] = 'd7a1e4c9f350'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

INDEXES = [
    ("ix_software_asset_id", "software", ["asset_id"]),
    ("ix_configs_software_id", "configs", ["software_id"]),
    ("ix_scan_check_results_asset_id", "scan_check_results", ["asset_id"]),
    ("uq_scan_snapshots_org_scan_number", "scan_snapshots", ["organization_id", "scan_number"]),
    ("ix_risk_exceptions_asset_id", "risk_exceptions", ["asset_id"]),
    ("ix_agent_collections_batch_id", "agent_collections", ["batch_id"]),
]


def upgrade() -> None:
    for name, table, columns in INDEXES:
        op.create_index(name, table, columns, unique=name.startswith("uq_"), schema="public")


def downgrade() -> None:
    for name, table, _ in reversed(INDEXES):
        op.drop_index(name, table_name=table, schema="public")
