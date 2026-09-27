"""Защита входа от подбора пароля и кода 2FA.

Правила:
  * неудачная попытка (неверный пароль или код 2FA) увеличивает users.failed_login_attempts —
    атомарно в SQL, чтобы параллельные запросы не обошли порог;
  * после settings.LOGIN_MAX_FAILED_ATTEMPTS подряд вход блокируется до locked_until
    (settings.LOGIN_LOCKOUT_MINUTES), счётчик обнуляется — после разблокировки снова полный запас;
  * счётчик сбрасывается только после ПОЛНОГО входа (с 2FA — после верного кода). Иначе, зная
    пароль, можно было бы бесконечно подбирать код 2FA, чередуя его с верным паролем;
  * заблокированная учётка не проверяет пароль вовсе — подбор во время блокировки бесполезен.

Ограничения (осознанные):
  * ответ «слишком много попыток» показывает, что такой email существует, — но только после серии
    неудачных попыток по нему; без блокировки вход был бы открыт для подбора, что хуже;
  * блокировку можно навести на чужую учётку, намеренно ошибаясь, — поэтому она временная, и её
    может снять суперадмин («Разблокировать» в «Пользователях системы»);
  * лимита по IP нет: за прокси (Vite, nginx) все запросы приходят с одного адреса, и такой лимит
    позволил бы одному атакующему закрыть вход всем пользователям.
"""
import math
from datetime import UTC, datetime, timedelta

from fastapi import HTTPException, status
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import hash_password, verify_password
from app.models.user import User

# Проверка пароля для несуществующего email идёт против этого хэша: иначе такой ответ был бы
# заметно быстрее (без bcrypt), и по времени можно было бы узнать, какие email зарегистрированы.
_DUMMY_HASH = hash_password("timing-equalizer-not-a-real-password")


def check_password(user: User | None, password: str) -> bool:
    if user is None:
        verify_password(password, _DUMMY_HASH)
        return False
    return verify_password(password, user.password_hash)


def ensure_not_locked(user: User | None) -> None:
    if user is None or user.locked_until is None:
        return
    remaining = (user.locked_until - datetime.now(UTC)).total_seconds()
    if remaining > 0:
        minutes = max(1, math.ceil(remaining / 60))
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Слишком много неудачных попыток входа. Повторите через {minutes} мин.",
        )


def register_failure(db: Session, user: User | None) -> None:
    if user is None:
        return
    attempts = db.execute(
        text("UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = :id RETURNING failed_login_attempts"),
        {"id": str(user.id)},
    ).scalar()
    if attempts >= settings.LOGIN_MAX_FAILED_ATTEMPTS:
        db.execute(
            text("UPDATE users SET failed_login_attempts = 0, locked_until = :until WHERE id = :id"),
            {"id": str(user.id), "until": datetime.now(UTC) + timedelta(minutes=settings.LOGIN_LOCKOUT_MINUTES)},
        )
    db.commit()


def register_success(user: User) -> None:
    """Вызывается перед commit успешного входа (вызывающий коммитит вместе с last_login_at)."""
    user.failed_login_attempts = 0
    user.locked_until = None
