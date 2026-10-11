from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.api.deps import get_agent_organization_id, get_pack_registry
from app.core.config import settings
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
