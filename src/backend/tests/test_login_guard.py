"""Защита входа от подбора: блокировка после серии неудач, 2FA, срок временного токена."""
from datetime import UTC, datetime, timedelta

import pyotp
import pytest
from jose import jwt
from sqlalchemy import text

from app.core.config import settings
from app.core.security import encrypt_totp_secret
from app.services import login_guard

PASSWORD = "Right-password-123"
MAX = settings.LOGIN_MAX_FAILED_ATTEMPTS


@pytest.fixture
def user(make_user):
    return make_user("guarded@example.com", password=PASSWORD)


def login(client, password, email="guarded@example.com"):
    return client.post("/api/auth/login", json={"email": email, "password": password})


def state(db, user_id):
    db.expire_all()
    return db.execute(text("SELECT failed_login_attempts, locked_until FROM users WHERE id = :id"), {"id": user_id}).one()


# ---------- пароль ----------

def test_failures_below_the_limit_do_not_lock_and_success_resets_the_counter(client, db, user):
    for _ in range(MAX - 1):
        assert login(client, "wrong-password-000").status_code == 401
    assert state(db, user).failed_login_attempts == MAX - 1

    assert login(client, PASSWORD).status_code == 200
    assert tuple(state(db, user)) == (0, None)


def test_lock_after_the_limit_even_with_the_right_password(client, db, user):
    for _ in range(MAX):
        assert login(client, "wrong-password-000").status_code == 401

    locked = login(client, PASSWORD)
    assert locked.status_code == 429
    assert "Слишком много неудачных попыток" in locked.json()["detail"]
    attempts, until = state(db, user)
    assert attempts == 0 and until > datetime.now(UTC) + timedelta(minutes=settings.LOGIN_LOCKOUT_MINUTES - 1)


def test_password_is_not_even_checked_while_locked(client, db, user, monkeypatch):
    for _ in range(MAX):
        login(client, "wrong-password-000")
    calls = []
    monkeypatch.setattr(login_guard, "verify_password", lambda *a: calls.append(a) or True)
    assert login(client, PASSWORD).status_code == 429
    assert calls == []  # подбор во время блокировки ничего не проверяет


def test_lock_expires_by_itself(client, db, user):
    for _ in range(MAX):
        login(client, "wrong-password-000")
    db.execute(text("UPDATE users SET locked_until = now() - interval '1 second' WHERE id = :id"), {"id": user})
    db.commit()
    assert login(client, PASSWORD).status_code == 200


def test_unknown_email_gets_the_same_answer_and_the_same_bcrypt_work(client, monkeypatch):
    calls = []
    real = login_guard.verify_password
    monkeypatch.setattr(login_guard, "verify_password", lambda p, h: calls.append(h) or real(p, h))
    resp = login(client, "whatever-password", email="nobody@example.com")
    assert resp.status_code == 401 and resp.json()["detail"] == "Неверный логин или пароль"
    assert calls == [login_guard._DUMMY_HASH]  # время ответа не выдаёт, что такого email нет


def test_superadmin_unlocks_and_reset_password_clears_the_lock(client, db, user, make_user, auth_header):
    make_user("root@example.com", is_superadmin=True)
    root = auth_header("root@example.com")
    for _ in range(MAX):
        login(client, "wrong-password-000")

    listed = {u["email"]: u for u in client.get("/api/admin/users", headers=root).json()}
    assert listed["guarded@example.com"]["locked_until"] is not None

    assert client.post(f"/api/admin/users/{user}/activate", headers=root).status_code == 200
    assert tuple(state(db, user)) == (0, None)
    assert login(client, PASSWORD).status_code == 200


# ---------- 2FA ----------

@pytest.fixture
def user_2fa(db, user):
    secret = pyotp.random_base32()
    db.execute(
        text("INSERT INTO user_2fa (user_id, secret_encrypted, is_enabled, backup_codes_hashes) VALUES (:u, :s, true, '[]')"),
        {"u": user, "s": encrypt_totp_secret(secret)},
    )
    db.commit()
    return user, pyotp.TOTP(secret)


def verify(client, temp_token, code):
    return client.post("/api/auth/verify-2fa", json={"temp_token": temp_token, "code": code})


def wrong_code(totp):
    return f"{(int(totp.now()) + 1) % 1_000_000:06d}"


def test_2fa_code_guessing_is_limited(client, db, user_2fa):
    user_id, totp = user_2fa
    temp = login(client, PASSWORD).json()["temp_token"]
    for _ in range(MAX):
        assert verify(client, temp, wrong_code(totp)).status_code == 401
    assert verify(client, temp, totp.now()).status_code == 429  # даже верный код — заблокировано


def test_right_password_does_not_reset_the_2fa_failure_counter(client, db, user_2fa):
    """Иначе, зная пароль, код 2FA можно было бы подбирать бесконечно, чередуя его с верным паролем."""
    user_id, totp = user_2fa
    for _ in range(MAX - 1):
        temp = login(client, PASSWORD).json()["temp_token"]
        verify(client, temp, wrong_code(totp))
    temp = login(client, PASSWORD).json()["temp_token"]
    assert verify(client, temp, wrong_code(totp)).status_code == 401
    assert login(client, PASSWORD).status_code == 429


def test_right_code_completes_login_and_resets_the_counter(client, db, user_2fa):
    user_id, totp = user_2fa
    temp = login(client, PASSWORD).json()["temp_token"]
    verify(client, temp, wrong_code(totp))
    ok = verify(client, temp, totp.now())
    assert ok.status_code == 200 and ok.json()["access_token"]
    assert tuple(state(db, user_id)) == (0, None)


def test_pre_2fa_token_expires_and_tokens_without_exp_are_rejected(client, user_2fa):
    user_id, totp = user_2fa
    temp = login(client, PASSWORD).json()["temp_token"]
    claims = jwt.get_unverified_claims(temp)
    assert claims["exp"] - datetime.now(UTC).timestamp() <= settings.PRE_2FA_TOKEN_EXPIRE_MINUTES * 60 + 5

    expired = jwt.encode({"sub": str(user_id), "type": "pre_2fa", "exp": datetime.now(UTC) - timedelta(seconds=1)},
                         settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    assert verify(client, expired, totp.now()).status_code == 401
    forever = jwt.encode({"sub": str(user_id), "type": "pre_2fa"}, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    assert verify(client, forever, totp.now()).status_code == 401  # как выдавались раньше — без срока
