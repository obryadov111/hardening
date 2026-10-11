"""Проверка по выгрузке конфигурации, загруженной через интерфейс (без агента).

Загружает администратор организации: результат — обычный снимок, как от агента, с источником
«выгрузка конфигурации» (scan_snapshots.collection), кто и когда загрузил, и SHA-256 каждого файла.
"""
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_pack_registry, require_org_access, require_org_admin
from app.api.routes.ingest import ingest_payload
from app.models.user import User
from app.schemas.ingest import IngestAssetIn, IngestPackRun, IngestProbeResult, IngestRequest, IngestResponse
from app.services.offline_scan import MAX_FILE_BYTES, MAX_FILES, OfflineScanError, offline_packs, run_offline
from app.services.packs.registry import PackRegistry

router = APIRouter(tags=["offline-scans"])

CRITICALITY = {"low", "medium", "high", "critical"}


@router.get("/organizations/{organization_id}/offline-scans/packs")
def list_offline_packs(
    organization_id: str,
    _: User = Depends(require_org_access),
    registry: PackRegistry = Depends(get_pack_registry),
):
    """Какие паки можно проверить по выгрузке и какие файлы (команды) им нужны."""
    return {"max_files": MAX_FILES, "max_file_bytes": MAX_FILE_BYTES, "packs": offline_packs(registry)}


@router.post("/organizations/{organization_id}/offline-scans", response_model=IngestResponse)
async def upload_offline_scan(
    organization_id: str,
    hostname: str = Form(..., min_length=1, max_length=255),
    commands: list[str] = Form(..., description="Команда для каждого файла, в том же порядке, что files"),
    files: list[UploadFile] = File(...),
    environment: str = Form("network", min_length=1, max_length=100),
    pack: str | None = Form(None, max_length=100),
    ip_address: str | None = Form(None, max_length=64),
    criticality: str = Form("medium"),
    scan_label: str | None = Form(None, max_length=200),
    exported_at: datetime | None = Form(None, description="Когда снята выгрузка; по умолчанию неизвестно"),
    current_user: User = Depends(require_org_admin),
    db: Session = Depends(get_db),
    registry: PackRegistry = Depends(get_pack_registry),
):
    if len(commands) != len(files):
        raise HTTPException(status_code=422, detail="Для каждого файла нужна команда, чью выгрузку он содержит")
    if len(files) > MAX_FILES:
        raise HTTPException(status_code=422, detail=f"Не больше {MAX_FILES} файлов за раз")
    if criticality not in CRITICALITY:
        raise HTTPException(status_code=422, detail="Критичность: low, medium, high или critical")
    now = datetime.now(UTC)
    if exported_at is not None:
        exported_at = exported_at if exported_at.tzinfo else exported_at.replace(tzinfo=UTC)
        if exported_at > now:
            raise HTTPException(status_code=422, detail="Дата выгрузки не может быть в будущем")

    data: dict[str, bytes] = {}
    names: dict[str, str] = {}
    for command, upload in zip(commands, files, strict=True):
        command = command.strip()
        if command in data:
            raise HTTPException(status_code=422, detail=f"Выгрузка команды {command!r} загружена дважды")
        content = await upload.read(MAX_FILE_BYTES + 1)
        if len(content) > MAX_FILE_BYTES:
            raise HTTPException(status_code=413, detail=f"Файл {upload.filename} больше {MAX_FILE_BYTES // 1_000_000} МБ")
        data[command], names[command] = content, (upload.filename or "")[:255]

    try:
        run = run_offline(registry, data, pack or None)
    except OfflineScanError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    collection = run.collection
    for entry in collection["files"]:
        # Время файла во временном каталоге — момент загрузки, а не выгрузки: подменяется датой выгрузки.
        entry["modified"] = exported_at.strftime("%Y-%m-%dT%H:%M:%SZ") if exported_at else None
        entry["uploaded_name"] = names.get(entry["command"], "")
    collection["uploaded_by"] = current_user.email
    collection["uploaded_at"] = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    payload = IngestRequest(
        environment=environment.strip(),
        asset=IngestAssetIn(
            hostname=hostname.strip(), ip_address=(ip_address or "").strip() or None, os=None,
            asset_type=run.asset_type or "network-device", criticality=criticality,
        ),
        platform_tags=run.tags,
        packs=[
            IngestPackRun(id=pack_.pack, version=pack_.version,
                          probe_results={k: IngestProbeResult(**v) for k, v in results.items()})
            for pack_, results in run.packs
        ],
        scan_label=scan_label,
    )
    return ingest_payload(db, registry, organization_id, payload, collection=collection, source="offline-upload")
