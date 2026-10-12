"""Охват: список ожидаемых хостов (выгрузка AD, CSV) против хостов, которые отчитываются."""
from sqlalchemy import text

AD_EXPORT = (
    '#TYPE Selected.Microsoft.ActiveDirectory.Management.ADComputer\n'
    '"Name","DNSHostName","OperatingSystem","LastLogonDate","Enabled"\n'
    '"PC-001","pc-001.corp.local","Windows 11 Pro","10/10/2026 09:12:00","True"\n'
    '"PC-002","pc-002.corp.local","Windows 10 Pro","01/02/2026 08:00:00","True"\n'
    '"PC-003","pc-003.corp.local","Windows 11 Pro","10/11/2026 10:00:00","True"\n'
    '"PC-004","pc-004.corp.local","Windows 11 Pro","","True"\n'
    '"OLD-PC","old-pc.corp.local","Windows 7","01/01/2020 08:00:00","False"\n'
    '"pc-001","pc-001.corp.local","Windows 11 Pro","","True"\n'
)


def upload(client, org_id, headers, content, name="computers.csv"):
    return client.post(f"/api/organizations/{org_id}/expected-hosts", files={"file": (name, content, "text/csv")}, headers=headers)


def report(client, key, hostname):
    payload = {"environment": "office", "asset": {"hostname": hostname, "asset_type": "workstation"}}
    assert client.post("/api/ingest", json=payload, headers={"X-Agent-Api-Key": key}).status_code == 200


def test_coverage_against_ad_export(client, make_org, make_user, add_membership, auth_header, make_agent_key, db):
    org_id = make_org("Coverage Org")
    add_membership(make_user("cov-admin@example.com"), org_id, role="admin")
    headers = auth_header("cov-admin@example.com")
    key = make_agent_key(org_id)

    loaded = upload(client, org_id, headers, AD_EXPORT.encode("utf-8-sig"))
    assert loaded.status_code == 200, loaded.text
    assert loaded.json() == {"imported": 4, "duplicates": 1, "skipped_disabled": 1}

    report(client, key, "PC-001")            # отчитался сейчас (имя NetBIOS, в AD — DNS)
    report(client, key, "pc-003")            # отчитался, но давно — ниже сдвигаем время
    report(client, key, "SRV-UNLISTED")      # отчитывается, но в списке нет
    db.execute(text("UPDATE hardening_checks SET checked_at = now() - interval '20 days' "
                    "WHERE asset_id IN (SELECT id FROM assets WHERE hostname = 'pc-003')"))
    db.commit()
    enrolled = client.post("/api/agent/enroll", json={"hostname": "PC-004"},
                           headers={"X-Agent-Api-Key": make_agent_key(org_id, direct_use=False)})
    assert enrolled.status_code == 201       # зарегистрирован, отчёта ещё нет

    body = client.get(f"/api/organizations/{org_id}/coverage?days=7", headers=headers).json()
    status = {h["hostname"]: h["status"] for h in body["hosts"]}
    assert status == {"PC-001": "reporting", "PC-002": "not_installed", "PC-003": "stale", "PC-004": "stale"}
    assert body["summary"] == {"reporting": 1, "stale": 2, "revoked": 0, "not_installed": 1, "unexpected": 1}
    assert [h["hostname"] for h in body["unexpected"]] == ["SRV-UNLISTED"]
    assert body["list"]["total"] == 4 and body["list"]["source"] == "computers.csv"


def test_plain_list_semicolons_cp1251_and_replacement(client, make_org, make_user, add_membership, auth_header):
    org_id = make_org("List Org")
    add_membership(make_user("list-admin@example.com"), org_id, role="admin")
    headers = auth_header("list-admin@example.com")
    assert upload(client, org_id, headers, b"ws-1\nws-2\n\nws-3\n").json()["imported"] == 3
    excel = "Имя;ОС\nБУХ-01;Windows 10\nБУХ-02;Windows 11\n".encode("cp1251")  # Excel на русской Windows
    assert upload(client, org_id, headers, excel).json()["imported"] == 2   # список заменён
    hosts = client.get(f"/api/organizations/{org_id}/coverage", headers=headers).json()["hosts"]
    assert [(h["hostname"], h["os"]) for h in hosts] == [("БУХ-01", "Windows 10"), ("БУХ-02", "Windows 11")]
    assert upload(client, org_id, headers, b"a,b\n1,2\n").status_code == 422  # нет колонки с именем
    assert client.delete(f"/api/organizations/{org_id}/expected-hosts", headers=headers).status_code == 204
    assert client.get(f"/api/organizations/{org_id}/coverage", headers=headers).json()["list"] is None


def test_only_admin_uploads_list_members_see_coverage(client, make_org, make_user, add_membership, auth_header):
    org_id = make_org("Roles Org")
    add_membership(make_user("cov-viewer@example.com"), org_id, role="viewer")
    viewer = auth_header("cov-viewer@example.com")
    assert upload(client, org_id, viewer, b"ws-1\n").status_code == 403
    assert client.get(f"/api/organizations/{org_id}/coverage", headers=viewer).status_code == 200
    other = make_org("Foreign Org")
    assert client.get(f"/api/organizations/{other}/coverage", headers=viewer).status_code == 403
