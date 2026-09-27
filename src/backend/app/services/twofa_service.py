import base64
import hmac
import io
import secrets
from datetime import UTC, datetime

import pyotp
import qrcode

from app.core.config import settings


def generate_totp_secret() -> str:
    return pyotp.random_base32()


def build_totp_uri(email: str, secret: str) -> str:
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=email, issuer_name=settings.TOTP_ISSUER)


def verify_totp_code(secret: str, code: str) -> bool:
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)


def match_totp_step(secret: str, code: str) -> int | None:
    """Номер 30-секундного интервала, которому соответствует код (окно ±1 интервал), или None.
    Нужен, чтобы засчитать код один раз: повтор того же кода — тот же интервал."""
    totp = pyotp.TOTP(secret)
    now = datetime.now(UTC)
    current = totp.timecode(now)
    for offset in (0, -1, 1):
        if hmac.compare_digest(str(code), totp.at(now, offset)):
            return current + offset
    return None


def generate_backup_codes(count: int = 8) -> list[str]:
    return [secrets.token_hex(4).upper() for _ in range(count)]


def build_qr_base64(uri: str) -> str:
    image = qrcode.make(uri)
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return base64.b64encode(buffer.getvalue()).decode("utf-8")