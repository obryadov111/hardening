
from pydantic import BaseModel, Field


class IngestSoftwareIn(BaseModel):
    name: str
    version: str | None = None
    vendor: str | None = None
    category: str | None = None
    type: str | None = None


class IngestAssetIn(BaseModel):
    hostname: str
    ip_address: str | None = None
    os: str | None = None
    asset_type: str | None = None
    criticality: str | None = None


class IngestPackRef(BaseModel):
    id: str = Field(..., max_length=100)
    version: str = Field(..., max_length=32)


class IngestProbeResult(BaseModel):
    """Результат одной пробы агента. found=False — проба не смогла выполниться (нет файла, команда не отработала)."""

    found: bool = True
    value: str | int | float | bool | None = None
    evidence: str | None = Field(default=None, max_length=500, description="Совпавшая строка, секреты замаскированы")
    error: str | None = Field(default=None, max_length=500)


class IngestPackRun(BaseModel):
    """Прогон одного пака: какой пак (и версия) и результаты его проб."""

    id: str = Field(..., max_length=100)
    version: str = Field(..., max_length=32)
    probe_results: dict[str, IngestProbeResult] = Field(default_factory=dict)


class IngestRequest(BaseModel):
    environment: str = Field(..., description="Имя окружения (создаётся, если не существует)")
    asset: IngestAssetIn
    software: list[IngestSoftwareIn] = Field(default_factory=list)
    facts: dict = Field(default_factory=dict, description="Сырые факты по категориям: {'ssh': {'permit_root_login': 'no'}, ...}")
    scan_label: str | None = None
    platform_tags: list[str] = Field(
        default_factory=list, max_length=20,
        description="Теги платформы (класс → семейство → продукт); правило с product_type из тегов тоже применяется",
    )
    pack: IngestPackRef | None = Field(default=None, description="Один пак (прежний формат): пак для probe_results")
    probe_results: dict[str, IngestProbeResult] = Field(
        default_factory=dict, description="{id проверки пака: результат пробы} для одиночного pack"
    )
    packs: list[IngestPackRun] = Field(
        default_factory=list, max_length=10,
        description="Несколько паков за один прогон актива: ОС + Docker + СУБД. Один прогон — один снимок и общая оценка",
    )


class IngestChecksSummary(BaseModel):
    total: int
    passed: int
    failed: int
    errors: int


class IngestCoverage(BaseModel):
    total: int
    evaluated: int
    errors: int
    ratio: float | None = None


class IngestPackSummary(BaseModel):
    id: str
    version: str
    maturity: str
    total: int
    passed: int
    failed: int
    errors: int


class IngestResponse(BaseModel):
    batch_id: str
    asset_id: str
    snapshot_id: str
    checks: IngestChecksSummary
    compliance_score: float | None = None
    accepted_risks: int = Field(default=0, description="Нарушения с принятым риском: не входят в failed и в score")
    coverage: IngestCoverage | None = None
    packs: list[IngestPackSummary] = Field(default_factory=list, description="Итоги по каждому паку прогона")
    report_id: str
