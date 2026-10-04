import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, Numeric, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class ScanSnapshot(Base):
    __tablename__ = "scan_snapshots"
    __table_args__ = {"schema": "public"}

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("public.client_organizations.id"), nullable=True
    )
    scan_number: Mapped[int] = mapped_column(Integer, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    total_checks: Mapped[int | None] = mapped_column(Integer, nullable=True, default=0)
    passed: Mapped[int | None] = mapped_column(Integer, nullable=True, default=0)
    failed: Mapped[int | None] = mapped_column(Integer, nullable=True, default=0)
    # Нарушения с принятым риском: в failed и в score не входят.
    accepted_risks: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    compliance_score: Mapped[float | None] = mapped_column(Numeric, nullable=True)
    exported_pdf_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    exported_excel_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    ingestion_batch_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("public.ingestion_batches.id"), nullable=True
    )
    snapshot_label: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str | None] = mapped_column(Text, nullable=True)
    total_assets: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_software: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
