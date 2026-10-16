"""Проверка по опросу: аудитор отвечает на вопросы пака (transport: manual) по экранам системы управления устройством.

Отвечает администратор организации: результат — обычный снимок с источником «опрос» (scan_snapshots.collection):
кто и когда ответил, какие вопросы пропущены. Пропущенный вопрос — «не проверено», а не соблюдение.
"""
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_pack_registry, require_org_access, require_org_admin
from app.api.routes.ingest import ingest_payload
from app.models.user import User
from app.schemas.ingest import (
    IngestAssetIn,
    IngestPackRun,
    IngestProbeResult,
    IngestRequest,
    IngestResponse,
    IngestSoftwareIn,
)
from app.services.manual_scan import ManualScanError, firmware_software, manual_packs, probe_results
from app.services.packs.registry import PackRegistry

router = APIRouter(tags=["manual-scans"])


class ManualAnswer(BaseModel):
    value: bool | str | float | int | None = None
    comment: str | None = Field(default=None, max_length=1000)


class ManualScanIn(BaseModel):
    pack: str = Field(..., min_length=1, max_length=100)
    hostname: str = Field(..., min_length=1, max_length=255)
    environment: str = Field("network", min_length=1, max_length=100)
    ip_address: str | None = Field(default=None, max_length=64)
    criticality: str = Field("medium", pattern="^(low|medium|high|critical)$")
    scan_label: str | None = Field(default=None, max_length=200)
    answers: dict[str, ManualAnswer] = Field(default_factory=dict, max_length=200)
    firmware_version: str | None = Field(default=None, max_length=100)


@router.get("/organizations/{organization_id}/manual-scans/packs")
def list_manual_packs(
    organization_id: str,
    _: User = Depends(require_org_access),
    registry: PackRegistry = Depends(get_pack_registry),
):
    """Паки для проверки по опросу и их вопросы (у каждого — где смотреть в системе управления)."""
    return {"packs": manual_packs(registry)}


@router.post("/organizations/{organization_id}/manual-scans", response_model=IngestResponse)
def submit_manual_scan(
    organization_id: str,
    body: ManualScanIn,
    current_user: User = Depends(require_org_admin),
    db: Session = Depends(get_db),
    registry: PackRegistry = Depends(get_pack_registry),
):
    pack = registry.get(body.pack)
    if pack is None or pack.transport != "manual":
        raise HTTPException(status_code=422, detail=f"Нет пака {body.pack!r} для проверки по опросу")
    try:
        results, skipped = probe_results(pack, {k: v.model_dump() for k, v in body.answers.items()})
        software = firmware_software(pack, body.firmware_version)
    except ManualScanError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if len(skipped) == len(pack.checks):
        raise HTTPException(status_code=422, detail="Нет ни одного ответа")

    now = datetime.now(UTC)
    collection = {
        "source": "manual",
        "answered_by": current_user.email,
        "answered_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "unanswered": skipped,
    }
    payload = IngestRequest(
        environment=body.environment.strip(),
        asset=IngestAssetIn(
            hostname=body.hostname.strip(), ip_address=(body.ip_address or "").strip() or None, os=None,
            asset_type=pack.asset_type or "network-device", criticality=body.criticality,
        ),
        platform_tags=list(pack.tags),
        software=[IngestSoftwareIn(**entry) for entry in software],
        packs=[IngestPackRun(id=pack.pack, version=pack.version,
                             probe_results={k: IngestProbeResult(**v) for k, v in results.items()})],
        scan_label=body.scan_label,
    )
    return ingest_payload(db, registry, organization_id, payload, collection=collection, source="manual")
