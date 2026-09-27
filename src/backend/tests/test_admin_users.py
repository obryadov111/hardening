"""Учётные записи (суперадмин), временный пароль, смена пароля, отзыв сессий, блокировка."""
import time

import pytest
from sqlalchemy import text

GOOD = "Temp-password-123"
NEW = "My-own-password-456"


@pytest.fixture
def root(make_user, auth_header):
    make_user("root@example.com", is_superadmin=True)
    return auth_header("root@example.com")


@pytest.fixture
def login(client):
    def _login(email, password):
        resp = client.post("/api/auth/login", json={"email": email, "password": password})
        return resp
    return _login


def bearer(resp):
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


def create(client, root, **overrides):
    body = {"email": "new.user@example.com", "password": GOOD, "full_name": "Новый Пользователь", **overrides}
    return client.post("/api/admin/users", json=body, headers=root)


# ---------- только суперадмин ----------

def test_only_superadmin_manages_accounts(client, make_org, make_user, add_membership, auth_header):
    org_id = make_org("Org")
    add_membership(make_user("org-admin@example.com"), org_id, role="admin")
    headers = auth_header("org-admin@example.com")  # администратор организации — не суперадмин
    assert client.get("/api/admin/users", headers=headers).status_code == 403
    assert client.post("/api/admin/users", json={"email": "x@example.com", "password": GOOD}, headers=headers).status_code == 403
    assert client.get("/api/admin/users").status_code in (401, 403)


def test_create_user_with_organization_and_list(client, root, make_org):
    org_id = make_org("Клиент")
    resp = create(client, root, organization_id=org_id, role="auditor")
    assert resp.status_code == 201 and resp.json()["must_change_password"] is True

    users = {u["email"]: u for u in client.get("/api/admin/users", headers=root).json()}
    created = users["new.user@example.com"]
    assert created["organizations"] == [{"id": org_id, "name": "Клиент", "role": "auditor"}]
    assert (created["is_superadmin"], created["must_change_password"], created["full_name"]) == (False, True, "Новый Пользователь")


@pytest.mark.parametrize(("overrides", "status"), [
    ({"password": "short"}, 422),
    ({"password": "new.user@example.com"}, 422),       # пароль = email (длина проходит)
    ({"role": "owner"}, 422),
    ({"is_superadmin": True}, 422),                     # суперадмина через API не создать
    ({"organization_id": "00000000-0000-0000-0000-000000000000"}, 404),
])
def test_create_user_validation(client, root, overrides, status):
    assert create(client, root, **overrides).status_code == status


def test_duplicate_email_is_rejected_case_insensitively(client, root):
    assert create(client, root).status_code == 201
    assert create(client, root, email="New.User@Example.com").status_code == 409


# ---------- временный пароль ----------

def test_temporary_password_closes_everything_until_changed(client, root, login):
    create(client, root)
    session = bearer(login("new.user@example.com", GOOD))

    me = client.get("/api/auth/me", headers=session)
    assert me.status_code == 200 and me.json()["must_change_password"] is True
    blocked = client.get("/api/organizations", headers=session)
    assert blocked.status_code == 403 and blocked.json()["detail"] == "Нужно сменить временный пароль"

    changed = client.post("/api/auth/change-password", json={"current_password": GOOD, "new_password": NEW}, headers=session)
    assert changed.status_code == 200
    fresh = bearer(changed)
    assert client.get("/api/organizations", headers=fresh).status_code == 200
    assert client.get("/api/auth/me", headers=fresh).json()["must_change_password"] is False
    # старый токен отозван, старый пароль не работает, новый — работает
    assert client.get("/api/auth/me", headers=session).status_code == 401
    assert login("new.user@example.com", GOOD).status_code == 401
    assert login("new.user@example.com", NEW).status_code == 200


@pytest.mark.parametrize(("current", "new", "status"), [
    ("wrong-current-password", NEW, 400),
    (GOOD, "short", 422),
    (GOOD, GOOD, 422),  # новый должен отличаться
])
def test_change_password_validation(client, root, login, current, new, status):
    create(client, root)
    session = bearer(login("new.user@example.com", GOOD))
    resp = client.post("/api/auth/change-password", json={"current_password": current, "new_password": new}, headers=session)
    assert resp.status_code == status


# ---------- сброс пароля и блокировка ----------

def _user_id(db, email):
    return db.execute(text("SELECT id FROM users WHERE email = :e"), {"e": email}).scalar()


def test_reset_password_revokes_sessions_and_requires_change(client, db, root, make_user, login):
    make_user("worker@example.com", password="Old-password-789")
    session = bearer(login("worker@example.com", "Old-password-789"))
    assert client.get("/api/organizations", headers=session).status_code == 200

    time.sleep(0.01)
    resp = client.post(f"/api/admin/users/{_user_id(db, 'worker@example.com')}/reset-password", json={"new_password": GOOD}, headers=root)
    assert resp.status_code == 200

    assert client.get("/api/organizations", headers=session).status_code == 401  # украденный токен больше не работает
    assert login("worker@example.com", "Old-password-789").status_code == 401
    after = bearer(login("worker@example.com", GOOD))
    assert client.get("/api/auth/me", headers=after).json()["must_change_password"] is True


def test_block_takes_effect_immediately_and_activate_restores(client, db, root, make_user, login):
    make_user("worker@example.com", password="Old-password-789")
    session = bearer(login("worker@example.com", "Old-password-789"))
    uid = _user_id(db, "worker@example.com")

    assert client.post(f"/api/admin/users/{uid}/block", headers=root).json()["account_status"] == "blocked"
    assert client.get("/api/organizations", headers=session).status_code == 403  # уже выданный токен
    assert login("worker@example.com", "Old-password-789").status_code == 403

    assert client.post(f"/api/admin/users/{uid}/activate", headers=root).status_code == 200
    assert client.get("/api/organizations", headers=session).status_code == 200


def test_superadmin_cannot_block_or_reset_self(client, db, root):
    uid = _user_id(db, "root@example.com")
    assert client.post(f"/api/admin/users/{uid}/block", headers=root).status_code == 400
    assert client.post(f"/api/admin/users/{uid}/reset-password", json={"new_password": GOOD}, headers=root).status_code == 400


def test_unknown_user_and_action(client, root):
    missing = "00000000-0000-0000-0000-000000000000"
    assert client.post(f"/api/admin/users/{missing}/block", headers=root).status_code == 404
    assert client.post(f"/api/admin/users/{missing}/delete", headers=root).status_code == 422
