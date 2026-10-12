"""Ключи агентов и отчёты агентов, перенесённые файлом.

Ключ агента — на объект заказчика (площадку, сегмент): со сроком действия, отзывом, временем и адресом
последнего использования. Показывается один раз при создании; хранится только SHA-256. Это ключ
регистрации: агент при первом запуске получает по нему свой ключ хоста (routes/agent.py, enroll). Хосты —
здесь же: список, отзыв, удаление регистрации (после неё имя хоста можно зарегистрировать заново).

Отчёт из изолированного сегмента (агент --out): подписан HMAC-SHA256 ключом SHA-256(ключ агента) —
сервер проверяет подпись по хранимому хэшу, тот, кто переносит файл, ключа не знает и подменить
результаты не может. Подпись проверяется ключами этой организации, в том числе отозванными после
снятия отчёта: отчёт снят, пока ключ был действителен (срок — по collected_at).
"""
import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy.exc import DataError
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_pack_registry, normalize_hostname, require_org_admin
from app.api.routes.ingest import ingest_payload
from app.core.config import settings
from app.core.security import generate_agent_api_key, hash_agent_api_key
from app.models.hardening import AgentApiKey, AgentHost
from app.models.user import User
from app.schemas.ingest import IngestRequest, IngestResponse
from app.services.packs.manifest import ed25519_public_key
from app.services.packs.registry import PackRegistry

router = APIRouter(tags=["agent-keys"])

MAX_REPORT_BYTES = 10_000_000


class AgentKeyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100, description="Объект заказчика: площадка, сегмент, город")
    expires_in_days: int | None = Field(365, ge=1, le=1825, description="Срок действия; null — бессрочно")


def _key_out(key: AgentApiKey) -> dict:
    now = datetime.now(UTC)
    if not key.is_active:
        state = "revoked"
    elif key.expires_at is not None and key.expires_at <= now:
        state = "expired"
    else:
        state = "active"
    return {
        "id": str(key.id), "name": key.name, "state": state,
        "created_at": key.created_at, "expires_at": key.expires_at, "revoked_at": key.revoked_at,
        "last_used_at": key.last_used_at, "last_used_ip": key.last_used_ip, "direct_use": key.direct_use,
    }


def _host_out(host: AgentHost, key_names: dict) -> dict:
    return {
        "id": str(host.id), "hostname": host.hostname, "os": host.os, "status": host.status,
        "enrollment_key": key_names.get(host.enrollment_key_id),
        "enrolled_at": host.enrolled_at, "enrolled_ip": host.enrolled_ip,
        "last_seen_at": host.last_seen_at, "last_seen_ip": host.last_seen_ip, "revoked_at": host.revoked_at,
    }


@router.get("/organizations/{organization_id}/agent-keys")
def list_agent_keys(organization_id: str, _: User = Depends(require_org_admin), db: Session = Depends(get_db)):
    keys = db.query(AgentApiKey).filter(AgentApiKey.organization_id == organization_id).order_by(AgentApiKey.created_at.desc()).all()
    public_key = ed25519_public_key(settings.PACK_SIGNING_ED25519_KEY) if settings.PACK_SIGNING_ED25519_KEY else None
    key_names = {k.id: k.name for k in keys}
    hosts = (
        db.query(AgentHost)
        .filter(AgentHost.organization_id == organization_id, AgentHost.status != "replaced")
        .order_by(AgentHost.hostname_norm)
        .all()
    )
    return {"keys": [_key_out(k) for k in keys], "hosts": [_host_out(h, key_names) for h in hosts], "pack_public_key": public_key}


@router.post("/organizations/{organization_id}/agent-keys", status_code=201)
def create_agent_key(organization_id: str, body: AgentKeyCreate, _: User = Depends(require_org_admin), db: Session = Depends(get_db)):
    raw = generate_agent_api_key()
    now = datetime.now(UTC)
    key = AgentApiKey(
        organization_id=organization_id, name=body.name.strip(), key_hash=hash_agent_api_key(raw), created_at=now,
        expires_at=now + timedelta(days=body.expires_in_days) if body.expires_in_days else None,
    )
    db.add(key)
    db.commit()
    db.refresh(key)
    return {**_key_out(key), "key": raw}


@router.post("/organizations/{organization_id}/agent-keys/{key_id}/revoke")
def revoke_agent_key(organization_id: str, key_id: str, _: User = Depends(require_org_admin), db: Session = Depends(get_db)):
    key = db.query(AgentApiKey).filter(AgentApiKey.organization_id == organization_id, AgentApiKey.id == key_id).first()
    if key is None:
        raise HTTPException(status_code=404, detail="Ключ не найден")
    if key.is_active:
        key.is_active, key.revoked_at = False, datetime.now(UTC)
        db.commit()
    return _key_out(key)


def _org_host(db: Session, organization_id: str, host_id: str) -> AgentHost:
    host = None
    try:
        host = db.query(AgentHost).filter(AgentHost.organization_id == organization_id, AgentHost.id == host_id).first()
    except DataError:  # не UUID
        db.rollback()
    if host is None:
        raise HTTPException(status_code=404, detail="Хост не найден")
    return host


@router.post("/organizations/{organization_id}/agent-hosts/{host_id}/revoke")
def revoke_agent_host(organization_id: str, host_id: str, _: User = Depends(require_org_admin), db: Session = Depends(get_db)):
    """Отзыв ключа хоста: отчёты от него не принимаются, имя занято — по ключу площадки его заново не
    зарегистрировать, пока регистрацию не удалят."""
    host = _org_host(db, organization_id, host_id)
    if host.status == "active":
        host.status, host.revoked_at = "revoked", datetime.now(UTC)
        db.commit()
    return _host_out(host, {})


@router.delete("/organizations/{organization_id}/agent-hosts/{host_id}", status_code=204)
def delete_agent_host(organization_id: str, host_id: str, _: User = Depends(require_org_admin), db: Session = Depends(get_db)):
    """Удаление регистрации: ключ хоста перестаёт действовать, имя освобождается — агент переустановленного
    хоста регистрируется заново. Актив и история проверок хоста остаются."""
    host = _org_host(db, organization_id, host_id)
    db.delete(host)
    db.commit()


def _canonical(payload: dict) -> bytes:
    """Те же байты, что подписывает агент (agent/collector.py, canonical)."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


@router.post("/organizations/{organization_id}/agent-reports", response_model=IngestResponse)
async def upload_agent_report(
    organization_id: str,
    file: UploadFile = File(...),
    current_user: User = Depends(require_org_admin),
    db: Session = Depends(get_db),
    registry: PackRegistry = Depends(get_pack_registry),
):
    content = await file.read(MAX_REPORT_BYTES + 1)
    if len(content) > MAX_REPORT_BYTES:
        raise HTTPException(status_code=413, detail=f"Отчёт больше {MAX_REPORT_BYTES // 1_000_000} МБ")
    try:
        report = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise HTTPException(status_code=422, detail="Файл — не отчёт агента (ожидается JSON, сохранённый агентом с --out)") from None
    if not isinstance(report, dict) or report.get("format") != "hardening-agent-report" or not isinstance(report.get("payload"), dict):
        raise HTTPException(status_code=422, detail="Файл — не отчёт агента (ожидается JSON, сохранённый агентом с --out)")
    if report.get("version") != 1:
        raise HTTPException(status_code=422, detail=f"Неподдерживаемая версия отчёта: {report.get('version')!r}")

    message, signature = _canonical(report["payload"]), str(report.get("signature") or "")
    def signed_by(key_hash: str) -> bool:
        return hmac.compare_digest(hmac.new(key_hash.encode("ascii"), message, hashlib.sha256).hexdigest(), signature)

    # Подписать мог ключ площадки (изолированный сегмент — хост не регистрировался) или ключ хоста.
    keys = db.query(AgentApiKey).filter(AgentApiKey.organization_id == organization_id).all()
    signer = next((k for k in keys if signed_by(k.key_hash)), None)
    signer_host = None
    if signer is None:
        hosts = db.query(AgentHost).filter(AgentHost.organization_id == organization_id).all()
        signer_host = next((h for h in hosts if signed_by(h.key_hash)), None)
    if signer is None and signer_host is None:
        raise HTTPException(status_code=422, detail="Подпись отчёта не совпала ни с одним ключом агента этой организации: "
                                                    "файл изменён или снят ключом другой организации")
    try:
        payload = IngestRequest.model_validate(report["payload"])
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=f"Отчёт агента не прошёл проверку формата: {exc.errors()[:3]}") from None
    collected = payload.collected_at
    if signer_host is not None:
        if normalize_hostname(payload.asset.hostname) != signer_host.hostname_norm:
            raise HTTPException(status_code=422, detail=f"Отчёт подписан ключом хоста {signer_host.hostname}, а снят "
                                                        f"с хоста {payload.asset.hostname}")
        if signer_host.revoked_at is not None and (collected is None or collected > signer_host.revoked_at):
            raise HTTPException(status_code=422, detail="Отчёт снят после отзыва ключа хоста")
    elif collected is not None and signer.expires_at is not None and collected > signer.expires_at:
        raise HTTPException(status_code=422, detail="Отчёт снят после окончания срока действия ключа агента")
    elif collected is not None and signer.revoked_at is not None and collected > signer.revoked_at:
        raise HTTPException(status_code=422, detail="Отчёт снят после отзыва ключа агента")

    # Живой хост — source «agent-report»; выгрузка конфигурации (агент --offline-dir) — свой source сохраняется.
    collection = payload.collection.model_dump() if payload.collection else {"source": "agent-report"}
    collection |= {
        "transfer": "file",
        "agent_key": signer.name if signer is not None else f"хост {signer_host.hostname}",
        "uploaded_by": current_user.email,
        "uploaded_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "file_sha256": hashlib.sha256(content).hexdigest(),
        "uploaded_name": (file.filename or "")[:255],
    }
    return ingest_payload(db, registry, organization_id, payload, collection=collection, source="agent-report-file")
