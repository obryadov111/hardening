import uuid
from datetime import datetime
from typing import Literal

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


class IngestDiskIn(BaseModel):
    name: str | None = None
    model: str | None = None
    size_gb: float | None = None
    type: str | None = None  # ssd | hdd | nvme | unknown


class IngestInventoryIn(BaseModel):
    """Инвентаризация оборудования актива. Поля с ПДн (username, domain, domain_groups)
    агент присылает только при запуске с --collect-identity."""

    mac_address: str | None = Field(default=None, max_length=64)
    device_uuid: str | None = Field(default=None, max_length=128)
    cpu_model: str | None = None
    cpu_cores: int | None = Field(default=None, ge=0)
    memory_mb: int | None = Field(default=None, ge=0)
    board_vendor: str | None = None
    board_product: str | None = None
    disks: list[IngestDiskIn] = Field(default_factory=list, max_length=64)
    username: str | None = Field(default=None, max_length=256)
    domain: str | None = Field(default=None, max_length=256)
    domain_groups: list[str] = Field(default_factory=list, max_length=256)


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


class IngestCollectionFile(BaseModel):
    command: str = Field(..., max_length=200)
    file: str = Field(..., max_length=255)
    sha256: str = Field(..., pattern="^[0-9a-f]{64}$")
    modified: str | None = Field(default=None, max_length=32, description="Время изменения файла выгрузки, UTC ISO 8601")


class IngestCollection(BaseModel):
    """Источник данных прогона, если это не живой хост: выгрузка конфигурации проверяется теми же
    паками, но конфигурация могла измениться после выгрузки — это должно быть видно в отчёте."""

    source: Literal["offline-config"]
    files: list[IngestCollectionFile] = Field(default_factory=list, max_length=50)
    declared_pack: bool = Field(default=False, description="Пак задан оператором (--pack), платформа по выгрузке не подтверждена")


class IngestRequest(BaseModel):
    environment: str = Field(..., description="Имя окружения (создаётся, если не существует)")
    asset: IngestAssetIn
    inventory: IngestInventoryIn | None = Field(
        default=None, description="Инвентаризация оборудования актива; нет — агент её не собирал (сетевое устройство, выгрузка)",
    )
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
    collection: IngestCollection | None = Field(default=None, description="Источник данных; нет — живой хост или устройство")
    run_id: uuid.UUID | None = Field(
        default=None, description="Идентификатор прогона от агента: повторная отправка из очереди не создаёт второй снимок",
    )
    collected_at: datetime | None = Field(
        default=None, description="Когда агент собрал данные (прогон из очереди приходит позже); нет — время приёма",
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
