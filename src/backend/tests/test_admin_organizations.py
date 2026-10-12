"""Создание организации суперадмином: появляется в списке, дубли и пустые названия отклоняются."""


def test_superadmin_creates_organization(client, make_user, auth_header):
    make_user("root@example.com", is_superadmin=True)
    headers = auth_header("root@example.com")

    resp = client.post("/api/admin/organizations", json={"name": "  ООО   Ромашка ", "industry": "Энергетика", "country": " "}, headers=headers)
    assert resp.status_code == 201, resp.text
    org = resp.json()
    assert org["name"] == "ООО Ромашка" and org["industry"] == "Энергетика" and org["country"] is None

    names = [o["name"] for o in client.get("/api/organizations", headers=headers).json()]
    assert "ООО Ромашка" in names
    # организация пригодна для дальнейшей работы: ключ агента для неё выдаётся
    assert client.post(f"/api/organizations/{org['id']}/agent-keys", json={"name": "site-1"}, headers=headers).status_code == 201


def test_duplicate_and_empty_names_are_rejected(client, make_user, auth_header, make_org):
    make_org("ООО Ромашка")
    make_user("root@example.com", is_superadmin=True)
    headers = auth_header("root@example.com")

    assert client.post("/api/admin/organizations", json={"name": "ооо  ромашка"}, headers=headers).status_code == 409
    assert client.post("/api/admin/organizations", json={"name": "   "}, headers=headers).status_code == 422


def test_regular_user_cannot_create_organization(client, make_user, auth_header):
    make_user("user@example.com")
    resp = client.post("/api/admin/organizations", json={"name": "Чужая"}, headers=auth_header("user@example.com"))
    assert resp.status_code == 403
