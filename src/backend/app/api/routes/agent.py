from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.deps import (
    AgentIdentity, client_ip, get_agent_identity, get_agent_organization_id, get_db, get_pack_registry, normalize_hostname,
)
from app.core.config import settings
from app.core.security import generate_agent_host_key, hash_agent_api_key
from app.models.hardening import AgentHost
from app.services.packs.manifest import signed_manifests
from app.services.packs.registry import PackRegistry

router = APIRouter(prefix="/agent", tags=["agent"])


@router.get("/manifests")
def list_manifests(
    transport: str | None = Query(default=None, pattern="^(local|ssh)$"),
    _organization_id: str = Depends(get_agent_organization_id),
    registry: PackRegistry = Depends(get_pack_registry),
):
    """Подписанные манифесты актуальных версий паков для агента.

    Агент сам определяет по detect-условиям, какие паки подходят его хосту, проверяет подпись
    и выполняет только описанные в манифесте пробы. Подписи — Ed25519 (signature_ed25519, у агента только
    открытый ключ) и/или HMAC (signature, старая схема) — какими ключами сервер настроен.
    """
    if not settings.PACK_SIGNING_KEY and not settings.PACK_SIGNING_ED25519_KEY:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Ключ подписи паков не настроен (PACK_SIGNING_ED25519_KEY или PACK_SIGNING_KEY)",
        )
    return {"manifests": signed_manifests(registry.latest(transport), settings.PACK_SIGNING_KEY, settings.PACK_SIGNING_ED25519_KEY)}


class EnrollRequest(BaseModel):
    hostname: str = Field(..., min_length=1, max_length=255, description="Имя хоста — то же, что агент присылает в отчёте")
    os: str | None = Field(default=None, max_length=200)


@router.post("/enroll", status_code=201)
def enroll(
    body: EnrollRequest,
    request: Request,
    identity: AgentIdentity = Depends(get_agent_identity),
    db: Session = Depends(get_db),
):
    """Регистрация хоста: агент при первом запуске обменивает ключ площадки на собственный ключ хоста.

    Ключ площадки ставится на все хосты сразу (GPO, Ansible) — а отчёт по ключу хоста принимается только
    с его именем: утечка ключа с одного хоста не даёт подделать отчёты остальных, отозвать можно один хост.
    Имя занято, пока хост активен или отозван администратором. Новая установка занимает имя хоста, который
    молчит дольше AGENT_REENROLL_AFTER_DAYS (переустановка ОС, замена ПК): хост на связи так не перехватить.
    """
    if identity.host is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Хост уже зарегистрирован — это ключ хоста, а не площадки")
    hostname = body.hostname.strip()
    norm = normalize_hostname(hostname)
    if not norm:
        raise HTTPException(status_code=422, detail="Пустое имя хоста")

    now = datetime.now(UTC)
    existing = (
        db.query(AgentHost)
        .filter(AgentHost.organization_id == identity.organization_id, AgentHost.hostname_norm == norm, AgentHost.status != "replaced")
        .with_for_update()
        .first()
    )
    if existing is not None:
        if existing.status == "revoked":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Регистрация хоста {existing.hostname} отозвана администратором. Чтобы зарегистрировать "
                       "его заново, удалите прежнюю регистрацию на странице «Агенты»",
            )
        last_seen = existing.last_seen_at or existing.enrolled_at
        if now - last_seen < timedelta(days=settings.AGENT_REENROLL_AFTER_DAYS):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Хост {existing.hostname} уже зарегистрирован и был на связи {last_seen:%Y-%m-%d %H:%M} UTC. "
                       "Если агент переустановлен, удалите прежнюю регистрацию на странице «Агенты»",
            )
        existing.status = "replaced"
        db.flush()

    raw = generate_agent_host_key()
    ip = client_ip(request)
    host = AgentHost(
        organization_id=identity.organization_id, enrollment_key_id=identity.key_id, hostname=hostname, hostname_norm=norm,
        key_hash=hash_agent_api_key(raw), os=body.os, status="active", enrolled_at=now, enrolled_ip=ip,
        last_seen_at=now, last_seen_ip=ip,
    )
    db.add(host)
    try:
        db.commit()
    except IntegrityError:  # тот же хост регистрируется одновременно двумя запросами
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Хост {hostname} уже регистрируется") from None
    return {"host_id": str(host.id), "hostname": hostname, "key": raw}
