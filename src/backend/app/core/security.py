import base64
import os
import re
import secrets
from datetime import UTC, datetime, timedelta
from hashlib import sha256

import bcrypt
from cryptography.fernet import Fernet
from jose import jwt

from app.core.config import settings

# bcrypt напрямую (раньше — через passlib: он не развивается и импортирует модуль crypt, удалённый в
# Python 3.13). Хеши те же ($2b$, 12 раундов) — прежние пароли проверяются. bcrypt учитывает первые
# 72 байта пароля (36 кириллических символов); passlib обрезал так же, поэтому обрезка явная.
BCRYPT_MAX_BYTES = 72


def _secret(password: str) -> bytes:
    return password.encode("utf-8")[:BCRYPT_MAX_BYTES]


# Формат проверяется до bcrypt: на усечённом хеше bcrypt 4.0 не бросает ValueError, а паникует
# (PanicException — наследник BaseException, обычный except его не ловит).
BCRYPT_HASH = re.compile(r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$")


def verify_password(plain_password: str, password_hash: str) -> bool:
    if not BCRYPT_HASH.match(password_hash or ""):
        return False
    return bcrypt.checkpw(_secret(plain_password), password_hash.encode("ascii"))


def hash_password(password: str) -> str:
    return bcrypt.hashpw(_secret(password), bcrypt.gensalt(rounds=12)).decode("ascii")


ACCESS_TOKEN_TYPE = "access"


def create_access_token(subject: str) -> str:
    now = datetime.now(UTC)
    expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    # iat с долями секунды: токен, выданный до смены пароля в ту же секунду, тоже должен отзываться
    # type — токен доступа; промежуточный токен входа (pre_2fa, только пароль) им не принимается (deps.py)
    payload = {"sub": subject, "type": ACCESS_TOKEN_TYPE, "exp": expire, "iat": now.timestamp()}
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


PASSWORD_MIN_LENGTH = 12
PASSWORD_MAX_LENGTH = 128


def password_problem(password: str, email: str | None = None) -> str | None:
    """Причина, по которой пароль не подходит, или None. Проверяется для паролей, задаваемых через
    API (создание пользователя, сброс, смена); существующие хэши не пересматриваются."""
    if len(password) < PASSWORD_MIN_LENGTH:
        return f"пароль короче {PASSWORD_MIN_LENGTH} символов"
    if len(password) > PASSWORD_MAX_LENGTH:
        return f"пароль длиннее {PASSWORD_MAX_LENGTH} символов"
    if not password.strip():
        return "пароль не может состоять из пробелов"
    if email and password.strip().lower() == email.strip().lower():
        return "пароль не должен совпадать с email"
    return None


def _build_fernet() -> Fernet:
    raw = sha256(settings.TOTP_SECRET_ENCRYPTION_KEY.encode("utf-8")).digest()
    key = base64.urlsafe_b64encode(raw)
    return Fernet(key)


def encrypt_totp_secret(secret: str) -> str:
    return _build_fernet().encrypt(secret.encode("utf-8")).decode("utf-8")


def decrypt_totp_secret(secret_encrypted: str) -> str:
    return _build_fernet().decrypt(secret_encrypted.encode("utf-8")).decode("utf-8")


def hash_backup_code(code: str) -> str:
    return sha256(code.encode("utf-8")).hexdigest()


def generate_random_password(length: int = 24) -> str:
    alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*"
    return "".join(alphabet[ord(os.urandom(1)) % len(alphabet)] for _ in range(length))


def generate_agent_api_key() -> str:
    """Ключ агента-сборщика. Выдаётся один раз при создании — хранится только hash."""
    return "yak_" + secrets.token_urlsafe(32)


def generate_agent_host_key() -> str:
    """Ключ зарегистрированного хоста: выдаётся агенту один раз при регистрации — хранится только hash."""
    return "yah_" + secrets.token_urlsafe(32)


def hash_agent_api_key(key: str) -> str:
    return sha256(key.encode("utf-8")).hexdigest()