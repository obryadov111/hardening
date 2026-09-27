import pytest
from sqlalchemy import text

from app.api.deps import get_pack_registry
from app.core.config import settings
from app.main import app
from app.services.packs.manifest import verify_manifest
from app.services.packs.models import Pack
from app.services.packs.registry import PackRegistry
from tests.test_packs import BASE_PACK, make_pack

SSH_PACK = make_pack(
    pack="cisco-test",
    transport="ssh",
    tags=["network-device", "cisco-ios"],
    asset_type="network-device",
    detect=[{"probe": {"type": "cli_config", "cmd": "show version", "match": "Cisco"}, "equals": "Cisco"}],
    checks=[{
        "id": "cisco_ios.http_server_disabled", "title": "HTTP-сервер выключен",
        "probe": {"type": "cli_config", "cmd": "show running-config", "match": "^ip http server"},
        "assert": {"op": "absent"},
    }],
)


@pytest.fixture
def pack_registry():
    registry = PackRegistry([Pack.model_validate(BASE_PACK), Pack.model_validate(SSH_PACK)])
    app.dependency_overrides[get_pack_registry] = lambda: registry
    yield registry
    app.dependency_overrides.pop(get_pack_registry, None)


@pytest.fixture
def agent_key(make_org, make_agent_key):
    return make_agent_key(make_org("Pack Org"))


def pack_payload(**overrides):
    payload = {
        "environment": "prod",
        "asset": {"hostname": "web-01", "asset_type": "linux-server", "criticality": "high"},
        "platform_tags": ["linux-server", "debian-family", "ubuntu"],
        "pack": {"id": "ubuntu-test", "version": "1.0.0"},
        "probe_results": {
            "ssh.permit_root_login": {"found": True, "value": "yes", "evidence": "PermitRootLogin yes"},
            "ssh.max_auth_tries": {"found": True, "value": "3", "evidence": "MaxAuthTries 3"},
        },
    }
    payload.update(overrides)
    return payload


# ---------- выдача манифестов агенту ----------

def test_manifests_require_agent_key(client, pack_registry):
    assert client.get("/api/agent/manifests").status_code == 401


def test_manifests_are_signed_and_filtered_by_transport(client, pack_registry, agent_key):
    resp = client.get("/api/agent/manifests?transport=local", headers={"X-Agent-Api-Key": agent_key})

    assert resp.status_code == 200, resp.text
    items = resp.json()["manifests"]
    assert [i["manifest"]["pack"] for i in items] == ["ubuntu-test"]
    assert verify_manifest(items[0]["manifest"], items[0]["signature"], settings.PACK_SIGNING_KEY)


def test_manifests_reject_unknown_transport(client, pack_registry, agent_key):
    resp = client.get("/api/agent/manifests?transport=telnet", headers={"X-Agent-Api-Key": agent_key})
    assert resp.status_code == 422


def test_manifests_unavailable_without_signing_key(client, pack_registry, agent_key, monkeypatch):
    monkeypatch.setattr(settings, "PACK_SIGNING_KEY", None)
    resp = client.get("/api/agent/manifests", headers={"X-Agent-Api-Key": agent_key})
    assert resp.status_code == 503


# ---------- ingest по паку ----------

def test_ingest_with_pack_evaluates_on_server_and_records_versions(client, db, pack_registry, agent_key):
    resp = client.post("/api/ingest", json=pack_payload(), headers={"X-Agent-Api-Key": agent_key})

    assert resp.status_code == 200, resp.text
    body = resp.json()
    # Только проверки пака: 14 старых правил против пустых facts не запускаются.
    assert body["checks"] == {"total": 2, "passed": 1, "failed": 1, "errors": 0}
    assert body["compliance_score"] == 50.0
    assert body["coverage"] == {"total": 2, "evaluated": 2, "errors": 0, "ratio": 100.0}

    rows = db.execute(
        text("SELECT check_id, pack_id, pack_version, status, evidence, rule_id FROM scan_check_results ORDER BY check_id")
    ).mappings().all()
    assert [(r["check_id"], r["pack_id"], r["pack_version"], r["status"]) for r in rows] == [
        ("ssh.max_auth_tries", "ubuntu-test", "1.0.0", "pass"),
        ("ssh.permit_root_login", "ubuntu-test", "1.0.0", "fail"),
    ]
    assert rows[1]["evidence"] == "PermitRootLogin yes" and rows[1]["rule_id"] is None

    current = db.execute(text("SELECT check_id, pack_version, status FROM hardening_checks ORDER BY check_id")).all()
    assert current == [("ssh.max_auth_tries", "1.0.0", "pass"), ("ssh.permit_root_login", "1.0.0", "fail")]

    asset = db.execute(text("SELECT platform_tags FROM assets WHERE hostname = 'web-01'")).scalar()
    assert asset == ["linux-server", "debian-family", "ubuntu"]

    stored = db.execute(text("SELECT collected_data FROM agent_collections")).scalar()
    assert stored["packs"][0]["id"] == "ubuntu-test" and stored["packs"][0]["version"] == "1.0.0"
    assert stored["packs"][0]["probe_results"]["ssh.permit_root_login"]["value"] == "yes"


def test_pack_check_without_probe_result_is_error_and_lowers_coverage(client, pack_registry, agent_key):
    payload = pack_payload(probe_results={"ssh.max_auth_tries": {"found": True, "value": "3"}})

    body = client.post("/api/ingest", json=payload, headers={"X-Agent-Api-Key": agent_key}).json()

    assert body["checks"] == {"total": 2, "passed": 1, "failed": 0, "errors": 1}
    assert body["compliance_score"] == 100.0  # score не видит error — поэтому нужен coverage
    assert body["coverage"]["ratio"] == 50.0


def test_dashboard_shows_not_evaluated_checks_separately_from_passed(
    client, pack_registry, make_org, make_agent_key, make_user, add_membership, auth_header
):
    org_id = make_org("Dashboard Org")
    key = make_agent_key(org_id)
    payload = pack_payload(probe_results={"ssh.max_auth_tries": {"found": True, "value": "3"}})
    assert client.post("/api/ingest", json=payload, headers={"X-Agent-Api-Key": key}).status_code == 200
    user_id = make_user("dash-viewer@example.com")
    add_membership(user_id, org_id)

    body = client.get(f"/api/organizations/{org_id}/dashboard", headers=auth_header("dash-viewer@example.com")).json()

    # раньше фронт считал passed = checksCount - failedChecks, и error шёл в «пройдено»
    assert (body["checksCount"], body["passedChecks"], body["failedChecks"], body["notEvaluatedChecks"]) == (2, 1, 0, 1)
    assert body["coverage"] == 50.0


def test_dashboard_coverage_is_none_without_checks(client, make_org, make_user, add_membership, auth_header):
    org_id = make_org("Empty Org")
    add_membership(make_user("empty-viewer@example.com"), org_id)
    body = client.get(f"/api/organizations/{org_id}/dashboard", headers=auth_header("empty-viewer@example.com")).json()
    assert body["checksCount"] == 0 and body["coverage"] is None


def test_probe_that_could_not_run_is_recorded_as_error(client, pack_registry, agent_key):
    payload = pack_payload(probe_results={
        "ssh.permit_root_login": {"found": False, "error": "не удалось прочитать /etc/ssh/sshd_config"},
        "ssh.max_auth_tries": {"found": True, "value": "3"},
    })
    body = client.post("/api/ingest", json=payload, headers={"X-Agent-Api-Key": agent_key}).json()
    assert body["checks"]["errors"] == 1


def test_ingest_rejects_unknown_pack_without_creating_anything(client, db, pack_registry, agent_key):
    for pack_ref in ({"id": "nope", "version": "1.0.0"}, {"id": "ubuntu-test", "version": "9.9.9"}):
        resp = client.post("/api/ingest", json=pack_payload(pack=pack_ref), headers={"X-Agent-Api-Key": agent_key})
        assert resp.status_code == 422
        assert "Неизвестный пак" in resp.json()["detail"]
    assert db.execute(text("SELECT COUNT(*) FROM assets")).scalar() == 0
    assert db.execute(text("SELECT COUNT(*) FROM ingestion_batches")).scalar() == 0


def test_network_pack_ingest(client, pack_registry, agent_key):
    payload = {
        "environment": "net",
        "asset": {"hostname": "sw-core-01", "asset_type": "network-device"},
        "platform_tags": ["network-device", "cisco-ios"],
        "pack": {"id": "cisco-test", "version": "1.0.0"},
        "probe_results": {"cisco_ios.http_server_disabled": {"found": True, "value": None}},
    }
    body = client.post("/api/ingest", json=payload, headers={"X-Agent-Api-Key": agent_key}).json()
    assert body["checks"] == {"total": 1, "passed": 1, "failed": 0, "errors": 0}


def test_pack_results_appear_in_current_state_api_without_a_rule_row(client, db, pack_registry, agent_key, make_org):
    # data.py связывает hardening_checks с правилами через LEFT JOIN — результаты пака без rule_id не ломают выборки.
    client.post("/api/ingest", json=pack_payload(), headers={"X-Agent-Api-Key": agent_key})
    rows = db.execute(
        text("SELECT hc.status, r.id FROM hardening_checks hc LEFT JOIN hardening_rules r ON r.id = hc.rule_id")
    ).all()
    assert len(rows) == 2 and all(row[1] is None for row in rows)


def test_inventory_pack_gives_no_score_instead_of_a_misleading_100(client, db, agent_key):
    inventory = Pack.model_validate(make_pack(pack="astra-test", maturity="inventory", checks=[], tags=["astra-se"]))
    registry = PackRegistry([inventory])
    app.dependency_overrides[get_pack_registry] = lambda: registry
    try:
        payload = pack_payload(pack={"id": "astra-test", "version": "1.0.0"}, probe_results={})
        body = client.post("/api/ingest", json=payload, headers={"X-Agent-Api-Key": agent_key}).json()
    finally:
        app.dependency_overrides.pop(get_pack_registry, None)

    assert body["checks"]["total"] == 0
    assert body["compliance_score"] is None
    assert body["coverage"] == {"total": 0, "evaluated": 0, "errors": 0, "ratio": None}


# ---------- прежний путь не затронут ----------

def test_legacy_ingest_still_uses_hardening_rules_and_reports_coverage(client, pack_registry, agent_key):
    payload = {"environment": "prod", "asset": {"hostname": "old-01", "asset_type": "server"},
               "facts": {"ssh": {"permit_root_login": "no"}}}

    body = client.post("/api/ingest", json=payload, headers={"X-Agent-Api-Key": agent_key}).json()

    assert body["checks"]["total"] == 14
    assert body["coverage"] == {"total": 14, "evaluated": 1, "errors": 13, "ratio": 7.14}


def test_ingest_with_facts_and_pack_runs_both_paths(client, pack_registry, agent_key):
    payload = pack_payload(facts={"ssh": {"permit_root_login": "no"}})
    body = client.post("/api/ingest", json=payload, headers={"X-Agent-Api-Key": agent_key}).json()
    assert body["checks"]["total"] == 14 + 2


def test_platform_tags_are_kept_when_a_later_run_omits_them(client, db, pack_registry, agent_key):
    client.post("/api/ingest", json=pack_payload(), headers={"X-Agent-Api-Key": agent_key})
    legacy = {"environment": "prod", "asset": {"hostname": "web-01", "asset_type": "linux-server"}, "facts": {}}
    client.post("/api/ingest", json=legacy, headers={"X-Agent-Api-Key": agent_key})
    tags = db.execute(text("SELECT platform_tags FROM assets WHERE hostname = 'web-01'")).scalar()
    assert tags == ["linux-server", "debian-family", "ubuntu"]


# ---------- метаданные результатов пака в API (интерфейс читает их без изменений) ----------

def _viewer_headers(make_user, add_membership, auth_header, org_id):
    user_id = make_user("viewer@example.com")
    add_membership(user_id, org_id, "viewer")
    return auth_header("viewer@example.com")


def test_hardening_api_shows_pack_results_with_title_severity_evidence_and_pack(
    client, make_org, make_agent_key, make_user, add_membership, auth_header, pack_registry
):
    org_id = make_org("API Org")
    key = make_agent_key(org_id)
    client.post("/api/ingest", json=pack_payload(), headers={"X-Agent-Api-Key": key})

    resp = client.get(f"/api/organizations/{org_id}/hardening", headers=_viewer_headers(make_user, add_membership, auth_header, org_id))

    assert resp.status_code == 200, resp.text
    by_code = {item["rule"]["rule_code"]: item for item in resp.json()}
    item = by_code["ssh.permit_root_login"]
    assert item["rule"]["title"] == "Запрет root по SSH"
    assert item["rule"]["severity"] == "critical"
    assert item["rule"]["id"] is None  # строки в hardening_rules нет — данные из самой записи
    assert item["status"] == "fail" and item["actual_value"] == "yes"
    assert item["expected_value"] == "одно из: no, prohibit-password"
    assert item["evidence"] == "PermitRootLogin yes"
    assert item["pack"] == {"id": "ubuntu-test", "version": "1.0.0"}
    assert by_code["ssh.max_auth_tries"]["rule"]["title"] == "Число попыток"


def test_hardening_api_still_serves_legacy_results_from_the_rules_table(
    client, make_org, make_agent_key, make_user, add_membership, auth_header, pack_registry
):
    org_id = make_org("Legacy API Org")
    key = make_agent_key(org_id)
    legacy = {"environment": "prod", "asset": {"hostname": "old-01", "asset_type": "server"},
              "facts": {"ssh": {"permit_root_login": "yes"}}}
    client.post("/api/ingest", json=legacy, headers={"X-Agent-Api-Key": key})

    resp = client.get(f"/api/organizations/{org_id}/hardening", headers=_viewer_headers(make_user, add_membership, auth_header, org_id))

    by_code = {item["rule"]["rule_code"]: item for item in resp.json()}
    item = by_code["ssh.permit_root_login"]
    assert item["rule"]["title"] == "Запрет входа по SSH под root" and item["rule"]["severity"] == "critical"
    assert item["rule"]["remediation"] and item["rule"]["id"] is not None
    assert item["pack"] is None and item["evidence"] is None


def test_scan_history_keeps_check_metadata_snapshot(client, db, pack_registry, agent_key):
    client.post("/api/ingest", json=pack_payload(), headers={"X-Agent-Api-Key": agent_key})
    row = db.execute(
        text("SELECT title, severity, remediation FROM scan_check_results WHERE check_id = 'ssh.permit_root_login'")
    ).one()
    assert row[0] == "Запрет root по SSH" and row[1] == "critical"


# ---------- настоящий пак, без подмены реестра ----------

def test_shipped_pack_is_served_to_agents_and_evaluated_end_to_end(client, db, agent_key):
    from tests import test_ubuntu_pack_regression as regression

    MANIFEST, PACK = regression.MANIFEST, regression.PACK
    resp = client.get("/api/agent/manifests?transport=local", headers={"X-Agent-Api-Key": agent_key})
    served = {m["manifest"]["pack"]: m for m in resp.json()["manifests"]}
    assert served["ubuntu-server"]["manifest"] == MANIFEST  # реестр по умолчанию отдаёт тот же пак, что лежит в репозитории

    raw = regression.probes.run_manifest(regression.make_host(), MANIFEST)
    payload = {
        "environment": "prod",
        "asset": {"hostname": "ubuntu-01", "asset_type": "linux-server"},
        "platform_tags": MANIFEST["tags"],
        "pack": {"id": PACK.pack, "version": PACK.version},
        "probe_results": raw,
    }
    body = client.post("/api/ingest", json=payload, headers={"X-Agent-Api-Key": agent_key}).json()

    assert body["checks"] == {"total": 14, "passed": 14, "failed": 0, "errors": 0}  # эталонно защищённый хост (Samba — отдельный пак с 1.2.0)
    assert body["compliance_score"] == 100.0 and body["coverage"]["ratio"] == 100.0
