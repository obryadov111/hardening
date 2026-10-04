"""Покрытие методики ФСТЭК от 25.11.2025 по пунктам: каталог, статусы пунктов по результатам проверок."""
from app.api.deps import get_pack_registry
from app.services.fstec.catalog import CATALOG, SOURCE
from tests import test_ubuntu_pack_regression as regression

CODES = {item.code for section in CATALOG for item in section.items}


def test_every_pack_reference_points_to_a_catalog_item():
    """Опечатка в номере пункта (СУД.1.1 → СУД1.1) молча выпала бы из отчёта — ловим здесь."""
    unknown = {
        (pack.pack, check.id, ref.id)
        for pack in get_pack_registry().latest()
        for check in pack.checks
        for ref in check.refs
        if ref.source == SOURCE and ref.id and ref.id not in CODES
    }
    assert unknown == set()


def test_catalog_codes_are_unique_and_out_items_explain_why():
    codes = [item.code for section in CATALOG for item in section.items]
    assert len(codes) == len(set(codes))
    assert all(item.note for section in CATALOG for item in section.items if item.kind == "out")


def _ingest_ubuntu(client, key, sshd_config=None):
    host = regression.make_host({"/etc/ssh/sshd_config": sshd_config} if sshd_config else None)
    raw = regression.probes.run_manifest(host, regression.MANIFEST)
    payload = {
        "environment": "prod",
        "asset": {"hostname": "ubuntu-01", "asset_type": "linux-server"},
        "platform_tags": regression.MANIFEST["tags"],
        "pack": {"id": regression.PACK.pack, "version": regression.PACK.version},
        "probe_results": raw,
    }
    resp = client.post("/api/ingest", json=payload, headers={"X-Agent-Api-Key": key})
    assert resp.status_code == 200, resp.text
    return resp.json()


def _items(body):
    return {item["code"]: item for section in body["sections"] for item in section["items"]}


def test_coverage_reflects_check_results_and_accepted_risk(client, make_org, make_agent_key, make_user, add_membership, auth_header):
    org_id = make_org("FSTEC Org")
    key = make_agent_key(org_id)
    add_membership(make_user("fstec-admin@example.com"), org_id, role="admin")
    headers = auth_header("fstec-admin@example.com")
    weak_ssh = regression.HARDENED_FILES["/etc/ssh/sshd_config"].replace("PasswordAuthentication no", "PasswordAuthentication yes")
    _ingest_ubuntu(client, key, weak_ssh)

    items = _items(client.get(f"/api/organizations/{org_id}/fstec-coverage", headers=headers).json())

    # Вход по паролю в SSH нарушает и ОПС.1.10, и СУД.1.1 — проверка ссылается на оба пункта.
    assert items["ОПС.1.10"]["status"] == "violated" and items["СУД.1.1"]["status"] == "violated"
    failed = [c for c in items["СУД.1.1"]["checks"] if c["status"] == "fail"]
    assert [c["check_id"] for c in failed] == ["ssh.password_authentication"]
    assert items["ОПС.1.11"]["status"] == "passed"           # auditd работает
    assert items["ОПС.1.5"]["status"] == "out" and items["ОПС.1.5"]["note"]
    assert items["СУБД.1.1"]["status"] == "not_applied"       # пак postgresql есть, PostgreSQL на хосте нет
    assert items["ОПС.2"]["status"] == "not_checked"         # копия БДУ не загружена
    assert items["УСИ.1"]["status"] == "not_applied"         # ПО сетевого оборудования на активах нет

    # Принятый риск по нарушению: пункт — «риск принят», а не «нарушено».
    resp = client.post(f"/api/organizations/{org_id}/risk-exceptions", headers=headers,
                       json={"check_key": "ssh.password_authentication", "reason": "Вход по ключам ещё не настроен у подрядчика"})
    assert resp.status_code == 201
    body = client.get(f"/api/organizations/{org_id}/fstec-coverage", headers=headers).json()
    items = _items(body)
    assert items["СУД.1.1"]["status"] == "accepted"
    assert sum(body["summary"].values()) == len(CODES)


def test_coverage_requires_organization_access(client, make_org, make_user, auth_header):
    org_id = make_org("Closed Org")
    make_user("outsider@example.com")
    assert client.get(f"/api/organizations/{org_id}/fstec-coverage", headers=auth_header("outsider@example.com")).status_code == 403
