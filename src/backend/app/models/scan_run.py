import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class ScanRun(Base):
    """Прогон организации: много снимков хостов за одно окно (сутки или неделя агентов, либо вручную).

    Снимок хоста по-прежнему лежит в scan_snapshots. Здесь только границы окна и то, открыт ли прогон.
    Сводка (оценка, нарушения) в строку не пишется — её считают запросом по снимкам прогона.
    """

    __tablename__ = "scan_runs"
    __table_args__ = {"schema": "public"}

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("public.client_organizations.id"), nullable=False
    )
    environment_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("public.environments.id"), nullable=True
    )
    run_number: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(Text, nullable=False)  # auto | manual
    schedule: Mapped[str] = mapped_column(Text, nullable=False)  # daily | weekly | manual
    label: Mapped[str | None] = mapped_column(Text, nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    window_ends_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    opened_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("public.users.id"), nullable=True
    )
    closed_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("public.users.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class OrganizationScanSettings(Base):
    """Расписание автопрогона организации. Нет строки — ежедневно, как unit-файл агента."""

    __tablename__ = "organization_scan_settings"
    __table_args__ = {"schema": "public"}

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("public.client_organizations.id"), primary_key=True
    )
    schedule: Mapped[str] = mapped_column(Text, nullable=False, default="daily")
