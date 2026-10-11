"""Ключ подписи паков Ed25519.

    python -m app.commands.pack_signing_key            # новый ключ: строка для .env и открытый ключ
    python -m app.commands.pack_signing_key --public   # открытый ключ для текущего PACK_SIGNING_ED25519_KEY

Закрытый ключ — только в .env сервера (не в git). Открытый — в настройки агентов (HARDENING_PACK_PUBLIC_KEY
или --pack-public-key); его же показывает интерфейс на странице ключей агентов.
"""
import sys

from app.services.packs.manifest import ed25519_public_key, generate_ed25519_key


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if "--public" in argv:
        from app.core.config import settings

        if not settings.PACK_SIGNING_ED25519_KEY:
            print("PACK_SIGNING_ED25519_KEY не задан", file=sys.stderr)
            return 1
        print(ed25519_public_key(settings.PACK_SIGNING_ED25519_KEY))
        return 0
    key = generate_ed25519_key()
    print("# в .env сервера (секрет):")
    print(f"PACK_SIGNING_ED25519_KEY={key}")
    print("# в настройки агентов (открытый):")
    print(f"HARDENING_PACK_PUBLIC_KEY={ed25519_public_key(key)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
