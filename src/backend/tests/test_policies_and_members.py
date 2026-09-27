"""Политики и участники организации: права доступа, защита от потери управления, изоляция организаций."""
import uuid

import pytest
from sqlalchemy import text


@pytest.fixture
def org(make_org, make_user, add_membership, auth_header):
    """Организация с админом и наблюдателем; возвращает id и заголовки обоих."""
    org_id = make_org("Policy Org")
    admin_id = make_user("org-admin@example.com")
    viewer_id = make_user("org-viewer@example.com")
    add_membership(admin_id, org_id, role="admin")
    add_membership(viewer_id, org_id, role="viewer")
    return {
        "id": org_id, "admin_id": admin_id, "viewer_id": viewer_id,
        "admin": auth_header("org-admin@example.com"), "viewer": auth_header("org-viewer@example.com"),
    }


@pytest.fixture
def stranger(make_org, make_user, add_membership, auth_header):
    """Администратор другой организации."""
    add_membership(make_user("other-admin@example.com"), make_org("Other Org"), role="admin")
    return auth_header("other-admin@example.com")


# ============================== политики ==============================

def policies(org_id):
    return f"/api/organizations/{org_id}/policies"


def test_admin_manages_policies_and_members_can_read(client, org):
    created = client.post(policies(org["id"]), json={"name": "  Парольная политика  ", "scope": "Все серверы", "status": "active"}, headers=org["admin"])
    assert created.status_code == 201
    policy = created.json()
    assert (policy["name"], policy["status"], policy["scope"]) == ("Парольная политика", "active", "Все серверы")

    listed = client.get(policies(org["id"]), headers=org["viewer"]).json()
    assert [p["id"] for p in listed] == [policy["id"]]

    patched = client.patch(f"{policies(org['id'])}/{policy['id']}", json={"status": "review", "owner_name": "ИБ"}, headers=org["admin"]).json()
    assert (patched["status"], patched["owner_name"], patched["name"]) == ("review", "ИБ", "Парольная политика")
    assert patched["updated_at"] >= policy["updated_at"]

    assert client.delete(f"{policies(org['id'])}/{policy['id']}", headers=org["admin"]).status_code == 204
    assert client.get(policies(org["id"]), headers=org["viewer"]).json() == []


def test_viewer_cannot_change_policies(client, org):
    assert client.post(policies(org["id"]), json={"name": "x"}, headers=org["viewer"]).status_code == 403
    policy = client.post(policies(org["id"]), json={"name": "x"}, headers=org["admin"]).json()
    assert client.patch(f"{policies(org['id'])}/{policy['id']}", json={"status": "active"}, headers=org["viewer"]).status_code == 403
    assert client.delete(f"{policies(org['id'])}/{policy['id']}", headers=org["viewer"]).status_code == 403


def test_other_organization_cannot_see_or_touch_policies(client, org, stranger):
    policy = client.post(policies(org["id"]), json={"name": "x"}, headers=org["admin"]).json()
    assert client.get(policies(org["id"]), headers=stranger).status_code == 403
    assert client.patch(f"{policies(org['id'])}/{policy['id']}", json={"name": "взлом"}, headers=stranger).status_code == 403


def test_policy_of_another_org_via_own_org_url_is_404(client, org, make_org, make_user, add_membership, auth_header):
    """Админ своей организации не может править чужую политику, подставив её id в свой URL."""
    foreign_org = make_org("Foreign Org")
    add_membership(make_user("foreign-admin@example.com"), foreign_org, role="admin")
    foreign = client.post(policies(foreign_org), json={"name": "чужая"}, headers=auth_header("foreign-admin@example.com")).json()

    assert client.patch(f"{policies(org['id'])}/{foreign['id']}", json={"name": "взлом"}, headers=org["admin"]).status_code == 404
    assert client.delete(f"{policies(org['id'])}/{foreign['id']}", headers=org["admin"]).status_code == 404


@pytest.mark.parametrize("body", [
    {"name": "   "},
    {"name": "x", "status": "deleted"},
    {"name": "x", "organization_id": str(uuid.uuid4())},  # лишние поля запрещены
    {},
])
def test_policy_validation(client, org, body):
    assert client.post(policies(org["id"]), json=body, headers=org["admin"]).status_code == 422


def test_policy_patch_cannot_blank_the_name_or_inject_columns(client, org):
    policy = client.post(policies(org["id"]), json={"name": "x"}, headers=org["admin"]).json()
    url = f"{policies(org['id'])}/{policy['id']}"
    assert client.patch(url, json={"name": None}, headers=org["admin"]).status_code == 422
    assert client.patch(url, json={"organization_id": str(uuid.uuid4())}, headers=org["admin"]).status_code == 422


# ============================== участники ==============================

def members(org_id):
    return f"/api/organizations/{org_id}/users"


def test_admin_lists_adds_changes_and_removes_members(client, org, make_user):
    new_id = make_user("new-member@example.com")

    added = client.post(members(org["id"]), json={"email": "New-Member@Example.com", "role": "auditor"}, headers=org["admin"])
    assert added.status_code == 201 and added.json()["role"] == "auditor"

    listed = {m["email"]: m["role"] for m in client.get(members(org["id"]), headers=org["admin"]).json()}
    assert listed == {"org-admin@example.com": "admin", "org-viewer@example.com": "viewer", "new-member@example.com": "auditor"}

    assert client.patch(f"{members(org['id'])}/{new_id}", json={"role": "viewer"}, headers=org["admin"]).status_code == 200
    assert client.delete(f"{members(org['id'])}/{new_id}", headers=org["admin"]).status_code == 204
    assert "new-member@example.com" not in {m["email"] for m in client.get(members(org["id"]), headers=org["admin"]).json()}


def test_viewer_cannot_see_or_manage_members(client, org):
    assert client.get(members(org["id"]), headers=org["viewer"]).status_code == 403
    assert client.post(members(org["id"]), json={"email": "x@example.com"}, headers=org["viewer"]).status_code == 403
    # в т.ч. повысить самого себя
    assert client.patch(f"{members(org['id'])}/{org['viewer_id']}", json={"role": "admin"}, headers=org["viewer"]).status_code == 403


def test_other_organization_admin_cannot_manage_members(client, org, stranger):
    assert client.get(members(org["id"]), headers=stranger).status_code == 403
    assert client.delete(f"{members(org['id'])}/{org['viewer_id']}", headers=stranger).status_code == 403


def test_last_admin_cannot_be_removed_or_demoted(client, org, make_user, add_membership):
    url = f"{members(org['id'])}/{org['admin_id']}"
    assert client.patch(url, json={"role": "viewer"}, headers=org["admin"]).status_code == 409
    assert client.delete(url, headers=org["admin"]).status_code == 409

    # со вторым админом — можно
    add_membership(make_user("second-admin@example.com"), org["id"], role="admin")
    assert client.patch(url, json={"role": "viewer"}, headers=org["admin"]).status_code == 200


def test_cannot_touch_users_outside_the_organization(client, org, make_user):
    outsider = make_user("outsider@example.com")
    assert client.patch(f"{members(org['id'])}/{outsider}", json={"role": "admin"}, headers=org["admin"]).status_code == 404
    assert client.delete(f"{members(org['id'])}/{outsider}", headers=org["admin"]).status_code == 404


def test_adding_unknown_blocked_or_duplicate_users(client, db, org, make_user):
    assert client.post(members(org["id"]), json={"email": "nobody@example.com"}, headers=org["admin"]).status_code == 404

    blocked = make_user("blocked@example.com")
    db.execute(text("UPDATE users SET account_status = 'blocked' WHERE id = :id"), {"id": blocked})
    db.commit()
    assert client.post(members(org["id"]), json={"email": "blocked@example.com"}, headers=org["admin"]).status_code == 404

    assert client.post(members(org["id"]), json={"email": "org-viewer@example.com"}, headers=org["admin"]).status_code == 409
    assert client.post(members(org["id"]), json={"email": "x@example.com", "role": "owner"}, headers=org["admin"]).status_code == 422


def test_superadmin_manages_any_organization(client, org, make_user, auth_header):
    make_user("root@example.com", is_superadmin=True)
    headers = auth_header("root@example.com")
    assert client.get(members(org["id"]), headers=headers).status_code == 200
    assert client.post(policies(org["id"]), json={"name": "от суперадмина"}, headers=headers).status_code == 201
