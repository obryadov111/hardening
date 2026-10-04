from datetime import datetime
from decimal import Decimal
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class OrganizationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    industry: str | None = None
    country: str | None = None


class AssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    environment_id: UUID | None = None
    hostname: str
    ip_address: str | None = None
    os: str | None = None
    asset_type: str | None = None
    criticality: str | None = None
    created_at: datetime | None = None


class OrganizationAssetOut(BaseModel):
    id: UUID
    environment_id: UUID | None = None
    environment_name: str | None = None
    hostname: str
    ip_address: str | None = None
    os: str | None = None
    asset_type: str | None = None
    criticality: str | None = None
    created_at: datetime | None = None
    software_count: int = 0
    failed_checks_count: int = 0


class SoftwareOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    asset_id: UUID | None = None
    name: str
    version: str | None = None
    vendor: str | None = None
    category: str | None = None
    type: str | None = None


class ScanSnapshotOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    scan_number: int
    total_checks: int | None = 0
    passed: int | None = 0
    failed: int | None = 0
    accepted_risks: int = 0
    compliance_score: Decimal | None = None
    snapshot_label: str | None = None
    status: str | None = None
    total_assets: int
    total_software: int
    created_at: datetime | None = None
    previous_snapshot_id: UUID | None = None  # предыдущий снимок с общим активом — для сравнения


class LatestReportOut(BaseModel):
    compliance_score: float | None = None
    generated_at: datetime | None = None
    total_checks: int = 0
    failed: int = 0


class DashboardSummaryOut(BaseModel):
    assetsCount: int = 0
    softwareCount: int = 0
    checksCount: int = 0
    passedChecks: int = 0
    failedChecks: int = 0
    acceptedChecks: int = 0  # нарушения с принятым риском: не в failedChecks и не в score
    notEvaluatedChecks: int = 0  # error: проверка не выполнилась, в score не входит
    coverage: float | None = None  # доля выполненных (pass/fail) проверок, %
    reportsCount: int = 0
    latestReport: LatestReportOut | None = None
    environmentsCount: int = 0
    criticalAssets: int = 0
