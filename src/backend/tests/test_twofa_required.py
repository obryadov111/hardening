"""Обязательная 2FA (REQUIRE_2FA): без неё после входа по паролю открыты только подключение 2FA,
/auth/me и смена пароля; остальной API — 403, пока 2FA не включена."""
import pyotp
import pytest

from app.core.config import settings

PASSWORD = "Right-password-123"


@pytest.fixture(autouse=True)
def require_2fa(monkeypatch):
    monkeypatch.setattr(settings, "REQUIRE_2FA", True)


@pytest.fixture
def session(client, make_user):
    make_user("must@example.com", password=PASSWORD, is_superadmin=True)
    token = client.post("/api/auth/login", json={"email": "must@example.com", "password": PASSWORD}).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_without_2fa_only_setup_is_open(client, session):
    me = client.get("/api/auth/me", headers=session)
    assert me.status_code == 200 and me.json()["two_factor_setup_required"] is True

    blocked = client.get("/api/admin/users", headers=session)
    assert blocked.status_code == 403
    assert blocked.json()["detail"] == "Нужно подключить двухфакторную защиту"

    assert client.get("/api/auth/2fa", headers=session).json()["enabled"] is False
    assert client.post("/api/auth/2fa/setup", headers=session).status_code == 200


def test_after_enabling_2fa_api_opens_for_the_same_session(client, session):
    secret = client.post("/api/auth/2fa/setup", headers=session).json()["secret"]
    confirmed = client.post("/api/auth/2fa/confirm", json={"code": pyotp.TOTP(secret).now()}, headers=session)
    assert confirmed.status_code == 200

    assert client.get("/api/auth/me", headers=session).json()["two_factor_setup_required"] is False
    assert client.get("/api/admin/users", headers=session).status_code == 200


def test_disabling_2fa_closes_api_again(client, session):
    secret = client.post("/api/auth/2fa/setup", headers=session).json()["secret"]
    totp = pyotp.TOTP(secret)
    backup = client.post("/api/auth/2fa/confirm", json={"code": totp.now()}, headers=session).json()["backup_codes"]

    off = client.post("/api/auth/2fa/disable", json={"password": PASSWORD, "code": backup[0]}, headers=session)
    assert off.status_code == 200
    assert client.get("/api/admin/users", headers=session).status_code == 403
    assert client.get("/api/auth/me", headers=session).json()["two_factor_setup_required"] is True


def test_optional_mode_does_not_block(client, session, monkeypatch):
    monkeypatch.setattr(settings, "REQUIRE_2FA", False)
    assert client.get("/api/admin/users", headers=session).status_code == 200
    assert client.get("/api/auth/me", headers=session).json()["two_factor_setup_required"] is False


def test_temporary_password_comes_before_2fa_setup(client, db, make_user):
    from sqlalchemy import text

    user_id = make_user("temp@example.com", password=PASSWORD)
    db.execute(text("UPDATE users SET must_change_password = true WHERE id = :id"), {"id": user_id})
    db.commit()
    token = client.post("/api/auth/login", json={"email": "temp@example.com", "password": PASSWORD}).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    assert client.post("/api/auth/2fa/setup", headers=headers).json()["detail"] == "Нужно сменить временный пароль"
