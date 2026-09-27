"""Двухфакторная аутентификация (TOTP): подключение, отключение, резервные коды — для самого пользователя.

Подключение в два шага: setup выдаёт новый секрет (QR и строку для ручного ввода) и сохраняет его
неактивным; confirm включает 2FA только после верного кода из приложения — так нельзя включить
2FA с секретом, который не попал в приложение, и потерять доступ. При включении выдаются
одноразовые резервные коды: показываются один раз, хранятся только хэши.

Отключение требует пароль и код (или резервный код): украденной сессии недостаточно. Неверный
пароль здесь учитывается в том же лимите попыток, что и вход (services/login_guard.py).

Сброс 2FA пользователю, потерявшему и телефон, и резервные коды, — у суперадмина (admin_users).
"""
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db
from app.core.security import decrypt_totp_secret, encrypt_totp_secret, hash_backup_code
from app.models.user import User
from app.models.user_2fa import User2FA
from app.services.login_guard import check_password, ensure_not_locked, register_failure
from app.services.twofa_service import (
    build_qr_base64,
    build_totp_uri,
    generate_backup_codes,
    generate_totp_secret,
    match_totp_step,
    verify_totp_code,
)

TOTP_INTERVAL = 30  # секунд, стандарт RFC 6238 (pyotp по умолчанию)

router = APIRouter(prefix="/auth/2fa", tags=["2fa"])


class CodeRequest(BaseModel):
    code: str


class DisableRequest(BaseModel):
    password: str
    code: str


def normalize_backup_code(code: str) -> str:
    return code.strip().upper().replace("-", "").replace(" ", "")


def use_backup_code(db: Session, user_id, code: str) -> bool:
    """Списывает резервный код. Одним UPDATE: два параллельных запроса не используют один код дважды."""
    digest = hash_backup_code(normalize_backup_code(code))
    used = db.execute(
        text("""
            UPDATE user_2fa SET backup_codes_hashes = backup_codes_hashes - CAST(:h AS text), updated_at = now()
            WHERE user_id = :uid AND is_enabled AND backup_codes_hashes ? CAST(:h AS text)
            RETURNING id
        """),
        {"h": digest, "uid": str(user_id)},
    ).first()
    return used is not None


def use_totp_code(db: Session, twofa: User2FA, code: str) -> bool:
    """Код из приложения засчитывается один раз. В last_used_at хранится начало интервала последнего
    принятого кода; код того же или более раннего интервала отклоняется — подсмотренный код нельзя
    ввести повторно, пока он ещё «живой» (окно ±30 с). Одним UPDATE: два параллельных запроса с
    одним кодом не пройдут оба."""
    step = match_totp_step(decrypt_totp_secret(twofa.secret_encrypted), code)
    if step is None:
        return False
    step_start = datetime.fromtimestamp(step * TOTP_INTERVAL, UTC)
    accepted = db.execute(
        text("""
            UPDATE user_2fa SET last_used_at = :step_start, updated_at = now()
            WHERE user_id = :uid AND (last_used_at IS NULL OR last_used_at < :step_start)
            RETURNING id
        """),
        {"step_start": step_start, "uid": str(twofa.user_id)},
    ).first()
    return accepted is not None


def check_second_factor(db: Session, twofa: User2FA, code: str) -> bool:
    """Код из приложения (6 цифр, одноразовый в пределах своего интервала) или резервный код
    (одноразовый — при успехе списывается)."""
    code = code.strip()
    if code.isdigit() and len(code) == 6:
        return use_totp_code(db, twofa, code)
    return use_backup_code(db, twofa.user_id, code)


def _twofa(db: Session, user: User) -> User2FA | None:
    return db.query(User2FA).filter(User2FA.user_id == user.id).first()


@router.get("")
def status_2fa(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    twofa = _twofa(db, current_user)
    enabled = bool(twofa and twofa.is_enabled)
    return {"enabled": enabled, "backup_codes_left": len(twofa.backup_codes_hashes or []) if enabled else 0}


@router.post("/setup")
def setup(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    twofa = _twofa(db, current_user)
    if twofa and twofa.is_enabled:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="2FA уже включена — сначала отключите её")
    secret = generate_totp_secret()
    now = datetime.now(UTC)
    if twofa is None:
        twofa = User2FA(user_id=current_user.id, secret_encrypted=encrypt_totp_secret(secret), is_enabled=False,
                        backup_codes_hashes=[], created_at=now, updated_at=now)
        db.add(twofa)
    else:  # незавершённое подключение — новый секрет вместо прежнего
        twofa.secret_encrypted, twofa.backup_codes_hashes, twofa.updated_at = encrypt_totp_secret(secret), [], now
    db.commit()
    uri = build_totp_uri(current_user.email, secret)
    return {"secret": secret, "otpauth_uri": uri, "qr_png_base64": build_qr_base64(uri)}


@router.post("/confirm")
def confirm(body: CodeRequest, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    twofa = _twofa(db, current_user)
    if twofa is None or twofa.is_enabled:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Нет незавершённого подключения 2FA")
    if not verify_totp_code(decrypt_totp_secret(twofa.secret_encrypted), body.code.strip()):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Неверный код — проверьте время на телефоне и повторите")
    codes = generate_backup_codes()
    now = datetime.now(UTC)
    twofa.is_enabled, twofa.confirmed_at, twofa.updated_at = True, now, now
    twofa.backup_codes_hashes = [hash_backup_code(c) for c in codes]
    db.commit()
    return {"enabled": True, "backup_codes": codes}


@router.post("/disable")
def disable(body: DisableRequest, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    twofa = _twofa(db, current_user)
    if twofa is None or not twofa.is_enabled:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="2FA не включена")
    ensure_not_locked(current_user)
    if not check_password(current_user, body.password):
        register_failure(db, current_user)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Неверный пароль")
    if not check_second_factor(db, twofa, body.code):
        register_failure(db, current_user)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Неверный код")
    db.delete(twofa)
    db.commit()
    return {"enabled": False}
