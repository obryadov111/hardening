"""Манифест пака для агента и его подпись.

В манифест попадает только то, что нужно агенту: как распознать платформу и какие
пробы выполнить. Утверждения, критичность и рекомендации остаются на сервере —
их можно править без пересбора данных и без обновления агента.

Подпись — по каноническому JSON, две схемы:
- Ed25519 (PACK_SIGNING_ED25519_KEY): у агента только открытый ключ — подписать им нельзя, компрометация
  хоста с агентом не даёт подделать паки для других. Агент проверяет подпись на чистом Python
  (agent/probes.py, ed25519_verify) — без зависимостей.
- HMAC-SHA256 (PACK_SIGNING_KEY) — старая схема, на время перехода: ключ симметричный, им же проверяет
  агент, поэтому ключ с любого хоста с агентом позволяет подделывать паки для всех.
Сервер отдаёт обе подписи, если заданы оба ключа; агент с открытым ключом принимает только Ed25519.
"""
import base64
import hashlib
import hmac
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from app.services.packs.models import Pack

MANIFEST_SCHEMA_VERSION = 1


def build_manifest(pack: Pack) -> dict:
    return {
        "schema": MANIFEST_SCHEMA_VERSION,
        "pack": pack.pack,
        "version": pack.version,
        "maturity": pack.maturity,
        "tags": list(pack.tags),
        "transport": pack.transport,
        "asset_type": pack.asset_type,
        "detect": [rule.model_dump(mode="json", exclude_none=True) for rule in pack.detect],
        "checks": [
            {"id": check.id, "probe": check.probe.model_dump(mode="json", exclude_none=True)}
            for check in pack.checks
        ],
    }


def canonical_json(manifest: dict) -> bytes:
    """Одинаковый набор байт на сервере и в агенте: сортировка ключей, без пробелов, UTF-8."""
    return json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign_manifest(manifest: dict, key: str) -> str:
    return hmac.new(key.encode("utf-8"), canonical_json(manifest), hashlib.sha256).hexdigest()


def verify_manifest(manifest: dict, signature: str, key: str) -> bool:
    return hmac.compare_digest(sign_manifest(manifest, key), signature)


def _ed25519_private(key_b64: str) -> Ed25519PrivateKey:
    """Закрытый ключ — 32 байта (seed) в Base64: так его выдаёт `python -m app.commands.pack_signing_key`."""
    raw = base64.b64decode(key_b64.strip(), validate=True)
    if len(raw) != 32:
        raise ValueError("PACK_SIGNING_ED25519_KEY — 32 байта в Base64")
    return Ed25519PrivateKey.from_private_bytes(raw)


def sign_manifest_ed25519(manifest: dict, key_b64: str) -> str:
    return base64.b64encode(_ed25519_private(key_b64).sign(canonical_json(manifest))).decode("ascii")


def ed25519_public_key(key_b64: str) -> str:
    """Открытый ключ (Base64) — его прописывают в настройках агента (HARDENING_PACK_PUBLIC_KEY)."""
    return base64.b64encode(_ed25519_private(key_b64).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode("ascii")


def generate_ed25519_key() -> str:
    from cryptography.hazmat.primitives.serialization import NoEncryption, PrivateFormat

    raw = Ed25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    return base64.b64encode(raw).decode("ascii")


def signed_manifests(packs, hmac_key: str | None, ed25519_key: str | None) -> list[dict]:
    """Ответ /api/agent/manifests: манифест и подписи всеми заданными ключами."""
    items = []
    for pack in packs:
        manifest = build_manifest(pack)
        item = {"manifest": manifest}
        if hmac_key:
            item["signature"] = sign_manifest(manifest, hmac_key)
        if ed25519_key:
            item["signature_ed25519"] = sign_manifest_ed25519(manifest, ed25519_key)
        items.append(item)
    return items
