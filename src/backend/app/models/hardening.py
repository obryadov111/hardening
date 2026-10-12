import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, Numeric, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class HardeningRule(Base):
    __tablename__ = "hardening_rules"
    __table_args__ = {"schema": "public"}

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    product_type: Mapped[str | None] = mapped_column(Text, nullable=True)
    rule_code: Mapped[str | None] = mapped_column(Text, unique=True, nullable=True)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    expected_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    source: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class HardeningCheck(Base):
    __tablename__ = "hardening_checks"
    __table_args__ = {"schema": "public"}

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("public.assets.id"), nullable=True)
    rule_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("public.hardening_rules.id"), nullable=True)
    actual_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    expected_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(Text, nullable=False)
    checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Только для проверок контент-пака (rule_id у них пустой).
    check_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    pack_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    pack_version: Mapped[str | None] = mapped_column(Text, nullable=True)
    title: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Принятый риск на момент прогона (только у fail); такое нарушение не входит в score.
    risk_exception_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("public.risk_exceptions.id", ondelete="SET NULL"), nullable=True
    )


class ScanCheckResult(Base):
    __tablename__ = "scan_check_results"
    __table_args__ = {"schema": "public"}

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    snapshot_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("public.scan_snapshots.id"), nullable=True)
    asset_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("public.assets.id"), nullable=True)
    rule_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("public.hardening_rules.id"), nullable=True)
    actual_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    expected_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(Text, nullable=False)
    checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    check_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    pack_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    pack_version: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    title: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Принятый риск на момент прогона (только у fail); такое нарушение не входит в score.
    risk_exception_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("public.risk_exceptions.id", ondelete="SET NULL"), nullable=True
    )


class HardeningReport(Base):
    __tablename__ = "hardening_reports"
    __table_args__ = {"schema": "public"}

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("public.client_organizations.id"), nullable=True)
    total_checks: Mapped[int | None] = mapped_column(Integer, nullable=True, default=0)
    passed: Mapped[int | None] = mapped_column(Integer, nullable=True, default=0)
    failed: Mapped[int | None] = mapped_column(Integer, nullable=True, default=0)
    compliance_score: Mapped[float | None] = mapped_column(Numeric, nullable=True)
    generated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class IngestionBatch(Base):
    __tablename__ = "ingestion_batches"
    __table_args__ = {"schema": "public"}

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("public.client_organizations.id"), nullable=True)
    received_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    source: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="pending")
    assets_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    software_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    checks_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    report_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("public.hardening_reports.id"), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    scan_label: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Задаёт агент: повторная отправка прогона из очереди агента не создаёт второй снимок.
    run_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    collected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AgentCollection(Base):
    __tablename__ = "agent_collections"
    __table_args__ = {"schema": "public"}

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("public.assets.id"), nullable=True)
    batch_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("public.ingestion_batches.id"), nullable=True)
    collected_data: Mapped[dict] = mapped_column(JSONB, nullable=False)
    collected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AgentApiKey(Base):
    __tablename__ = "agent_api_keys"
    __table_args__ = {"schema": "public"}

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("public.client_organizations.id"), nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    key_hash: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_ip: Mapped[str | None] = mapped_column(Text, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Ключ принимается на /api/ingest напрямую (агенты до регистрации хостов); новые — только регистрация хостов.
    direct_use: Mapped[bool] = mapped_column(default=False, nullable=False)


class AgentHost(Base):
    """Хост, зарегистрированный агентом по ключу площадки (AgentApiKey): у хоста свой ключ, отчёт по нему
    принимается только с его именем. status: active; revoked — отозван администратором, имя занято, пока
    запись не удалят; replaced — имя перерегистрировано другой установкой (хост долго молчал)."""

    __tablename__ = "agent_hosts"
    __table_args__ = {"schema": "public"}

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("public.client_organizations.id"), nullable=False)
    enrollment_key_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("public.agent_api_keys.id"), nullable=True)
    hostname: Mapped[str] = mapped_column(Text, nullable=False)
    hostname_norm: Mapped[str] = mapped_column(Text, nullable=False)
    key_hash: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    os: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(Text, default="active", nullable=False)
    enrolled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    enrolled_ip: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen_ip: Mapped[str | None] = mapped_column(Text, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ExpectedHost(Base):
    """Хост, который должен отчитываться (выгрузка из AD или список): основа отчёта об охвате.
    hostname_norm — короткое имя в нижнем регистре: в AD DNS-имя, агент на Windows присылает имя NetBIOS."""

    __tablename__ = "expected_hosts"
    __table_args__ = {"schema": "public"}

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("public.client_organizations.id"), nullable=False)
    hostname: Mapped[str] = mapped_column(Text, nullable=False)
    hostname_norm: Mapped[str] = mapped_column(Text, nullable=False)
    os: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_logon: Mapped[str | None] = mapped_column(Text, nullable=True)
    source: Mapped[str | None] = mapped_column(Text, nullable=True)
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    imported_by: Mapped[str | None] = mapped_column(Text, nullable=True)
