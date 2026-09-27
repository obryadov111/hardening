"""2FA: подключение, вход по коду и резервному коду, отключение, сброс суперадмином."""
import pyotp
import pytest

PASSWORD = "Right-password-123"


@pytest.fixture
def session(client, make_user):
    make_user("tfa@example.com", password=PASSWORD)
    token = client.post("/api/auth/login", json={"email": "tfa@example.com", "password": PASSWORD}).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def enable(client, session):
    setup = client.post("/api/auth/2fa/setup", headers=session).json()
    totp = pyotp.TOTP(setup["secret"])
    confirmed = client.post("/api/auth/2fa/confirm", json={"code": totp.now()}, headers=session)
    assert confirmed.status_code == 200
    return totp, confirmed.json()["backup_codes"]


def login(client, password=PASSWORD):
    return client.post("/api/auth/login", json={"email": "tfa@example.com", "password": password})


def second_factor(client, code):
    temp = login(client).json()["temp_token"]
    return client.post("/api/auth/verify-2fa", json={"temp_token": temp, "code": code})


# ---------- подключение ----------

def test_setup_returns_qr_and_secret_and_enables_only_after_a_right_code(client, session):
    setup = client.post("/api/auth/2fa/setup", headers=session)
    assert setup.status_code == 200
    body = setup.json()
    assert body["otpauth_uri"].startswith("otpauth://totp/") and body["qr_png_base64"] and body["secret"]

    wrong = client.post("/api/auth/2fa/confirm", json={"code": "000000"}, headers=session)
    assert wrong.status_code == 400
    assert client.get("/api/auth/2fa", headers=session).json()["enabled"] is False
    assert "access_token" in login(client).json() and login(client).json()["access_token"]  # не включена — вход без кода

    confirmed = client.post("/api/auth/2fa/confirm", json={"code": pyotp.TOTP(body["secret"]).now()}, headers=session).json()
    assert confirmed["enabled"] is True and len(confirmed["backup_codes"]) == 8
    assert client.get("/api/auth/2fa", headers=session).json() == {"enabled": True, "backup_codes_left": 8}
    assert login(client).json()["two_factor_required"] is True


def test_setup_again_when_enabled_is_rejected(client, session):
    enable(client, session)
    assert client.post("/api/auth/2fa/setup", headers=session).status_code == 409


# ---------- вход ----------

def test_login_with_app_code(client, session):
    totp, _ = enable(client, session)
    resp = second_factor(client, totp.now())
    assert resp.status_code == 200 and resp.json()["access_token"]


def test_backup_code_works_once_and_tolerates_format(client, session):
    _, codes = enable(client, session)
    code = codes[0]
    formatted = f"{code[:4].lower()}-{code[4:].lower()}"  # как человек может ввести: строчными, через дефис

    assert second_factor(client, formatted).status_code == 200
    assert second_factor(client, code).status_code == 401  # одноразовый
    assert client.get("/api/auth/2fa", headers=session).json()["backup_codes_left"] == 7


# ---------- отключение ----------

def test_disable_requires_password_and_code(client, session):
    totp, codes = enable(client, session)
    assert client.post("/api/auth/2fa/disable", json={"password": "wrong-password-0", "code": totp.now()}, headers=session).status_code == 400
    assert client.post("/api/auth/2fa/disable", json={"password": PASSWORD, "code": "000000"}, headers=session).status_code == 400

    assert client.post("/api/auth/2fa/disable", json={"password": PASSWORD, "code": codes[1]}, headers=session).status_code == 200
    assert client.get("/api/auth/2fa", headers=session).json()["enabled"] is False
    assert login(client).json()["access_token"]  # снова без кода


# ---------- сброс суперадмином ----------

def test_superadmin_resets_lost_2fa(client, db, session, make_user, auth_header):
    enable(client, session)
    make_user("root@example.com", is_superadmin=True)
    root = auth_header("root@example.com")
    user_id = next(u["id"] for u in client.get("/api/admin/users", headers=root).json() if u["email"] == "tfa@example.com")

    assert client.post(f"/api/admin/users/{user_id}/reset-2fa", headers=root).status_code == 200
    assert login(client).json()["access_token"]  # вход по паролю, дальше пользователь подключает 2FA заново
    assert client.post(f"/api/admin/users/{user_id}/reset-2fa", headers=root).status_code == 409  # уже нет


def test_reset_2fa_rules(client, db, session, make_user, auth_header):
    make_user("root@example.com", is_superadmin=True)
    root = auth_header("root@example.com")
    users = {u["email"]: u["id"] for u in client.get("/api/admin/users", headers=root).json()}
    assert client.post(f"/api/admin/users/{users['root@example.com']}/reset-2fa", headers=root).status_code == 400  # себе — нельзя
    assert client.post(f"/api/admin/users/{users['tfa@example.com']}/reset-2fa", headers=session).status_code == 403  # не суперадмин
