"""Регистрация хостов: ключ площадки ставится на все хосты (GPO, Ansible), каждый хост при первом запуске
получает свой ключ — отчёт по нему принимается только с именем этого хоста."""
import json
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import text

AGENT_DIR = Path(__file__).resolve().parents[3] / "agent"
if not (AGENT_DIR / "collector.py").exists():
    pytest.skip("каталог agent/ недоступен", allow_module_level=True)
sys.path.insert(0, str(AGENT_DIR))

import collector  # noqa: E402


@pytest.fixture
def site(make_org, make_user, add_membership, auth_header, client):
    """Организация, её администратор и новый ключ площадки (как из интерфейса)."""
    org_id = make_org("Hosts Org")
    add_membership(make_user("hosts-admin@example.com"), org_id, role="admin")
    headers = auth_header("hosts-admin@example.com")
    key = client.post(f"/api/organizations/{org_id}/agent-keys", json={"name": "Москва, офис"}, headers=headers).json()
    return org_id, headers, key


def enroll(client, key, hostname, ip="198.51.100.10"):
    return client.post("/api/agent/enroll", json={"hostname": hostname, "os": "Windows 11"},
                       headers={"X-Agent-Api-Key": key, "X-Real-IP": ip})


def ingest(client, key, hostname):
    payload = {"environment": "office", "asset": {"hostname": hostname, "asset_type": "workstation"}}
    return client.post("/api/ingest", json=payload, headers={"X-Agent-Api-Key": key})


def hosts(client, org_id, headers):
    return client.get(f"/api/organizations/{org_id}/agent-keys", headers=headers).json()["hosts"]


def test_each_host_gets_its_own_key_bound_to_its_name(client, site):
    org_id, headers, site_key = site
    pc1, pc2 = enroll(client, site_key["key"], "PC-001"), enroll(client, site_key["key"], "PC-002")
    assert pc1.status_code == pc2.status_code == 201
    k1, k2 = pc1.json()["key"], pc2.json()["key"]
    assert k1.startswith("yah_") and k1 != k2 and k1 != site_key["key"]

    assert ingest(client, k1, "PC-001").status_code == 200
    assert ingest(client, k1, "pc-001").status_code == 200  # имя без учёта регистра
    foreign = ingest(client, k1, "PC-002")
    assert foreign.status_code == 403 and "PC-001" in foreign.text  # ключ одного хоста не годится для другого
    assert ingest(client, site_key["key"], "PC-003").status_code == 403  # ключ площадки — только регистрация

    listed = hosts(client, org_id, headers)
    assert [h["hostname"] for h in listed] == ["PC-001", "PC-002"]
    assert listed[0]["enrollment_key"] == "Москва, офис" and listed[0]["os"] == "Windows 11"
    assert listed[0]["enrolled_ip"] == "198.51.100.10" and listed[0]["status"] == "active"
    assert all("key" not in h and "key_hash" not in h for h in listed)


def test_host_key_also_fetches_manifests_and_cannot_enroll_again(client, site):
    _, _, site_key = site
    host_key = enroll(client, site_key["key"], "srv-01").json()["key"]
    for key in (site_key["key"], host_key):
        assert client.get("/api/agent/manifests?transport=local", headers={"X-Agent-Api-Key": key}).status_code == 200
    assert enroll(client, host_key, "srv-02").status_code == 409


def test_name_of_a_host_on_line_cannot_be_taken(client, site):
    _, _, site_key = site
    first = enroll(client, site_key["key"], "DC-01").json()["key"]
    again = enroll(client, site_key["key"], "dc-01")
    assert again.status_code == 409 and "удалите прежнюю регистрацию" in again.text
    assert ingest(client, first, "DC-01").status_code == 200  # прежний хост работает


def test_silent_host_name_is_taken_by_a_new_install(client, site, db):
    org_id, headers, site_key = site
    old = enroll(client, site_key["key"], "PC-777").json()["key"]
    db.execute(text("UPDATE agent_hosts SET last_seen_at = now() - interval '8 days'"))
    db.commit()
    new = enroll(client, site_key["key"], "PC-777")
    assert new.status_code == 201
    assert ingest(client, old, "PC-777").status_code == 401  # прежняя установка отключена
    assert ingest(client, new.json()["key"], "PC-777").status_code == 200
    assert [h["hostname"] for h in hosts(client, org_id, headers)] == ["PC-777"]  # заменённая не показывается


def test_revoked_host_stays_blocked_until_its_registration_is_deleted(client, site):
    org_id, headers, site_key = site
    host = enroll(client, site_key["key"], "laptop-5")
    host_id, host_key = host.json()["host_id"], host.json()["key"]
    revoked = client.post(f"/api/organizations/{org_id}/agent-hosts/{host_id}/revoke", headers=headers)
    assert revoked.status_code == 200 and revoked.json()["status"] == "revoked"
    assert ingest(client, host_key, "laptop-5").status_code == 401
    blocked = enroll(client, site_key["key"], "laptop-5")
    assert blocked.status_code == 409 and "отозвана" in blocked.text  # по ключу площадки не обойти

    assert client.delete(f"/api/organizations/{org_id}/agent-hosts/{host_id}", headers=headers).status_code == 204
    assert ingest(client, host_key, "laptop-5").status_code == 401
    assert enroll(client, site_key["key"], "laptop-5").status_code == 201


def test_hosts_are_managed_only_by_admin_of_their_organization(client, site, make_org, make_user, add_membership, auth_header):
    org_id, _, site_key = site
    host_id = enroll(client, site_key["key"], "pc-9").json()["host_id"]
    add_membership(make_user("hosts-viewer@example.com"), org_id, role="viewer")
    viewer = auth_header("hosts-viewer@example.com")
    assert client.post(f"/api/organizations/{org_id}/agent-hosts/{host_id}/revoke", headers=viewer).status_code == 403
    other_org = make_org("Other Hosts Org")
    add_membership(make_user("other-admin@example.com"), other_org, role="admin")
    other = auth_header("other-admin@example.com")
    assert client.post(f"/api/organizations/{other_org}/agent-hosts/{host_id}/revoke", headers=other).status_code == 404
    assert client.delete(f"/api/organizations/{other_org}/agent-hosts/{uuid.uuid4()}", headers=other).status_code == 404
    assert client.delete(f"/api/organizations/{other_org}/agent-hosts/not-a-uuid", headers=other).status_code == 404


def test_legacy_key_still_reports_directly(client, make_org, make_agent_key):
    """Ключи до регистрации хостов (direct_use) работают: установленные агенты не ломаются."""
    key = make_agent_key(make_org("Legacy Org"))
    assert ingest(client, key, "old-agent-host").status_code == 200


def _file_report(key, hostname, collected_at=None):
    payload = {"environment": "isolated", "asset": {"hostname": hostname, "asset_type": "server"},
               "run_id": str(uuid.uuid4()), "collected_at": (collected_at or datetime.now(UTC)).isoformat(timespec="seconds")}
    return collector.sign_report(payload, key)


def _upload(client, org_id, headers, report):
    files = {"file": ("report.json", json.dumps(report, ensure_ascii=False).encode(), "application/json")}
    return client.post(f"/api/organizations/{org_id}/agent-reports", files=files, headers=headers)


def test_file_report_signed_by_host_key_only_for_that_host(client, site):
    org_id, headers, site_key = site
    host = enroll(client, site_key["key"], "asu-07").json()
    assert _upload(client, org_id, headers, _file_report(host["key"], "asu-07")).status_code == 200
    other = _upload(client, org_id, headers, _file_report(host["key"], "asu-08"))
    assert other.status_code == 422 and "asu-07" in other.text
    client.post(f"/api/organizations/{org_id}/agent-hosts/{host['host_id']}/revoke", headers=headers)
    late = _file_report(host["key"], "asu-07", datetime.now(UTC) + timedelta(minutes=1))
    assert "после отзыва" in _upload(client, org_id, headers, late).text
