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


def _ingest_ubuntu(client, key, sshd_config=None, hostname="ubuntu-01"):
    host = regression.make_host({"/etc/ssh/sshd_config": sshd_config} if sshd_config else None)
    raw = regression.probes.run_manifest(host, regression.MANIFEST)
    payload = {
        "environment": "prod",
        "asset": {"hostname": hostname, "asset_type": "linux-server"},
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


def test_many_hosts_give_counts_and_first_checks_with_violations_first(client, make_org, make_agent_key, make_user,
                                                                        add_membership, auth_header, monkeypatch):
    """На тысяче хостов по пункту — тысячи проверок: ответ — счётчики по всем и первые CHECKS_SHOWN, нарушения сначала."""
    from app.services.fstec import coverage
    monkeypatch.setattr(coverage, "CHECKS_SHOWN", 2)
    org_id = make_org("FSTEC Many Org")
    key = make_agent_key(org_id)
    add_membership(make_user("fstec-many@example.com"), org_id)
    headers = auth_header("fstec-many@example.com")
    hardened = regression.HARDENED_FILES["/etc/ssh/sshd_config"]
    for i, config in enumerate([hardened, hardened, hardened.replace("PasswordAuthentication no", "PasswordAuthentication yes")]):
        _ingest_ubuntu(client, key, config, hostname=f"ubuntu-{i:02d}")
    item = _items(client.get(f"/api/organizations/{org_id}/fstec-coverage", headers=headers).json())["СУД.1.1"]
    counts = item["check_counts"]
    assert counts["total"] == counts["fail"] + counts["pass"] + counts["accepted"] + counts["error"]
    assert counts["fail"] == 1 and counts["total"] > 2
    assert len(item["checks"]) == 2 and item["checks"][0]["status"] == "fail"


def test_usi1_covers_russian_network_device_firmware():
    """УСИ.1 (уязвимости ПО телекоммуникационного оборудования и МЭ) — по моделям и прошивкам из паков (поле firmware)."""
    from app.services.fstec.catalog import CATALOG
    from app.services.fstec.coverage import _item_product

    usi1 = next(item for section in CATALOG for item in section.items if item.code == "УСИ.1")
    for product in ("cisco ios", "esr-200", "vesr", "mes3124", "qsw-2800-28t-ac", "snr-s2985g-24t",
                    "vipnet coordinator hw1000", "pt ngfw", "usergate next-generation firewall (ngfw)",
                    "программный комплекс «infowatch arma стена»", "комплекс безопасности «континент». версия 4"):
        assert _item_product(usi1, product), product
    for product in ("openssh", "mesa", "esr", "postgresql"):
        assert not _item_product(usi1, product), product
