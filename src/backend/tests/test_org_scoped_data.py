"""Эндпоинты /organizations/{id}/{environments,software,hardening,snapshots,reports}
и /assets/{id}/{software,hardening} — добавлены вслед за движком харденинга,
чтобы страницы фронтенда (Hardening, SoftwareInventory, Scans, Report, Project)
получали реальные данные вместо пустых состояний."""


def _ingest(client, agent_key, hostname="host-01", facts=None, software=None):
    payload = {
        "environment": "prod",
        "asset": {"hostname": hostname, "os": "Ubuntu 24.04", "asset_type": "server"},
        "software": software if software is not None else [{"name": "nginx", "version": "1.27.0", "vendor": "nginx"}],
        "facts": facts or {"ssh": {"permit_root_login": "no"}},
    }
    resp = client.post("/api/ingest", json=payload, headers={"X-Agent-Api-Key": agent_key})
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_environments_by_organization_is_scoped(client, make_org, make_agent_key, make_user, add_membership, auth_header):
    own_org = make_org("Env Org")
    other_org = make_org("Env Org Other")
    agent_key = make_agent_key(own_org)
    _ingest(client, agent_key)

    member = make_user("env-member@example.com", "secret123")
    add_membership(member, own_org, role="viewer")
    headers = auth_header("env-member@example.com", "secret123")

    resp = client.get(f"/api/organizations/{own_org}/environments", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 1
    assert body[0]["name"] == "prod"
    assert body[0]["assets_count"] == 1

    resp_denied = client.get(f"/api/organizations/{other_org}/environments", headers=headers)
    assert resp_denied.status_code == 403


def test_software_by_organization_includes_asset(client, make_org, make_agent_key, make_user, add_membership, auth_header):
    org_id = make_org("Software Org")
    agent_key = make_agent_key(org_id)
    _ingest(client, agent_key, hostname="db-01")

    member = make_user("sw-member@example.com", "secret123")
    add_membership(member, org_id, role="viewer")
    headers = auth_header("sw-member@example.com", "secret123")

    resp = client.get(f"/api/organizations/{org_id}/software", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["name"] == "nginx"
    assert body["items"][0]["asset"]["hostname"] == "db-01"
    assert body["summary"] == {"programs": 1, "categories": 0, "hosts": ["db-01"]}


def test_software_search_filter_sort_and_pages(client, make_org, make_agent_key, make_user, add_membership, auth_header):
    org_id = make_org("Software Paging Org")
    other = make_org("Software Paging Other")
    agent_key = make_agent_key(org_id)
    _ingest(client, agent_key, hostname="web-01", software=[
        {"name": "nginx", "version": "1.27.0", "vendor": "F5", "category": "web"},
        {"name": "openssl", "version": "3.0.13", "vendor": "OpenSSL"},
        {"name": "lib50%_off", "version": "1.0"},
    ])
    _ingest(client, agent_key, hostname="db-01", software=[
        {"name": "postgresql-15", "version": "15.8", "vendor": "PGDG", "category": "db"},
        {"name": "openssl", "version": "3.0.2", "vendor": "OpenSSL"},
    ])
    _ingest(client, make_agent_key(other), hostname="foreign-01", software=[{"name": "openssl", "version": "9.9"}])
    add_membership(make_user("sw-pager@example.com", "secret123"), org_id, role="viewer")
    headers = auth_header("sw-pager@example.com", "secret123")
    url = f"/api/organizations/{org_id}/software"

    def get(**params):
        resp = client.get(url, params=params, headers=headers)
        assert resp.status_code == 200, resp.text
        return resp.json()

    full = get()
    assert full["total"] == 5
    assert full["summary"] == {"programs": 5, "categories": 2, "hosts": ["db-01", "web-01"]}
    assert [i["name"] for i in full["items"]] == ["lib50%_off", "nginx", "openssl", "openssl", "postgresql-15"]

    # поиск без учёта регистра по названию, версии, производителю, хосту; чужая организация не видна
    assert {(i["name"], i["asset"]["hostname"]) for i in get(q="OPENSSL")["items"]} == {("openssl", "web-01"), ("openssl", "db-01")}
    assert [i["name"] for i in get(q="15.8")["items"]] == ["postgresql-15"]
    assert [i["name"] for i in get(q="f5")["items"]] == ["nginx"]
    assert get(q="db-0")["total"] == 2
    # % и _ в запросе — обычные символы, а не шаблон LIKE
    assert [i["name"] for i in get(q="50%_")["items"]] == ["lib50%_off"]
    assert get(q="%")["total"] == 1

    # фильтр по хосту; итоги — по всей организации, а не по фильтру
    by_host = get(host="db-01")
    assert by_host["total"] == 2 and by_host["summary"]["programs"] == 5
    assert get(host="foreign-01")["total"] == 0

    # сортировка и страницы
    assert [i["version"] for i in get(sort="version", dir="desc")["items"]][:2] == ["3.0.2", "3.0.13"]
    assert [i["asset"]["hostname"] for i in get(sort="host")["items"]] == ["db-01", "db-01", "web-01", "web-01", "web-01"]
    page1, page2, page3 = get(limit=2), get(limit=2, offset=2), get(limit=2, offset=4)
    names = [i["id"] for p in (page1, page2, page3) for i in p["items"]]
    assert len(names) == len(set(names)) == 5 and page3["total"] == 5

    for bad in ({"limit": 0}, {"limit": 501}, {"offset": -1}, {"sort": "id; DROP TABLE software"}, {"dir": "up"}):
        assert client.get(url, params=bad, headers=headers).status_code == 422
    assert client.get(f"/api/organizations/{other}/software", headers=headers).status_code == 403


def test_hardening_by_organization_includes_rule_and_asset(client, make_org, make_agent_key, make_user, add_membership, auth_header):
    org_id = make_org("Hardening Org")
    agent_key = make_agent_key(org_id)
    _ingest(client, agent_key, hostname="web-01", facts={"ssh": {"permit_root_login": "no"}})

    member = make_user("hard-member@example.com", "secret123")
    add_membership(member, org_id, role="viewer")
    headers = auth_header("hard-member@example.com", "secret123")

    resp = client.get(f"/api/organizations/{org_id}/hardening", headers=headers)
    assert resp.status_code == 200
    body = resp.json()["items"]
    assert len(body) == 14  # весь стартовый набор правил
    passed = [item for item in body if item["status"] == "pass"]
    assert len(passed) == 1
    assert passed[0]["rule"]["rule_code"] == "ssh.permit_root_login"
    assert passed[0]["asset"]["hostname"] == "web-01"


def test_hardening_by_asset_denied_for_non_member(client, make_org, make_agent_key, make_user, add_membership, auth_header):
    org_id = make_org("Asset Hardening Org")
    other_org = make_org("Asset Hardening Org Other")
    agent_key = make_agent_key(org_id)
    result = _ingest(client, agent_key, hostname="asset-hardening-host")

    outsider = make_user("outsider-hard@example.com", "secret123")
    add_membership(outsider, other_org, role="viewer")
    headers = auth_header("outsider-hard@example.com", "secret123")

    resp = client.get(f"/api/assets/{result['asset_id']}/hardening", headers=headers)
    assert resp.status_code == 403


def test_snapshots_and_reports_by_organization(client, make_org, make_agent_key, make_user, add_membership, auth_header):
    org_id = make_org("Snapshot Org")
    agent_key = make_agent_key(org_id)
    _ingest(client, agent_key, hostname="snap-01")

    member = make_user("snap-member@example.com", "secret123")
    add_membership(member, org_id, role="viewer")
    headers = auth_header("snap-member@example.com", "secret123")

    snapshots = client.get(f"/api/organizations/{org_id}/snapshots", headers=headers)
    assert snapshots.status_code == 200
    body = snapshots.json()
    assert body["total"] == 1 and len(body["items"]) == 1
    assert body["items"][0]["scan_number"] == 1
    assert body["summary"]["latest"]["scan_number"] == 1

    reports = client.get(f"/api/organizations/{org_id}/reports", headers=headers)
    assert reports.status_code == 200
    assert len(reports.json()) == 1
    assert reports.json()[0]["total_checks"] == 14
