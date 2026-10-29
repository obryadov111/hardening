import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = {"schema": "public"}

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    environment_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("public.environments.id"), nullable=True
    )
    hostname: Mapped[str] = mapped_column(Text, nullable=False)
    ip_address: Mapped[str | None] = mapped_column(Text, nullable=True)
    os: Mapped[str | None] = mapped_column(Text, nullable=True)
    asset_type: Mapped[str | None] = mapped_column(Text, nullable=True)
    criticality: Mapped[str | None] = mapped_column(Text, nullable=True)
    platform_tags: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AssetInventory(Base):
    """Инвентаризация актива: оборудование и (опционально) учётные данные — одна строка на актив,
    перезаписывается при каждом прогоне агента. Отделена от assets: это данные паспорта «железа»
    и ПДн (имя пользователя, доменные группы), а не то, по чему движок считает compliance."""

    __tablename__ = "asset_inventory"
    __table_args__ = {"schema": "public"}

    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("public.assets.id", ondelete="CASCADE"), primary_key=True
    )
    mac_address: Mapped[str | None] = mapped_column(Text, nullable=True)
    device_uuid: Mapped[str | None] = mapped_column(Text, nullable=True)  # machine-id / DMI product_uuid
    cpu_model: Mapped[str | None] = mapped_column(Text, nullable=True)
    cpu_cores: Mapped[int | None] = mapped_column(Integer, nullable=True)
    memory_mb: Mapped[int | None] = mapped_column(Integer, nullable=True)
    board_vendor: Mapped[str | None] = mapped_column(Text, nullable=True)
    board_product: Mapped[str | None] = mapped_column(Text, nullable=True)
    disks: Mapped[list | None] = mapped_column(JSONB, nullable=True)  # [{name, model, size_gb, type}]
    # ПДн — заполняются только при запуске агента с --collect-identity.
    username: Mapped[str | None] = mapped_column(Text, nullable=True)
    domain: Mapped[str | None] = mapped_column(Text, nullable=True)
    domain_groups: Mapped[list | None] = mapped_column(JSONB, nullable=True)  # [str]
    collected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
