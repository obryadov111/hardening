"""Сквозная проверка: подписанный манифест сервера -> реальный агент (collector.py + probes.py)
-> POST /api/ingest -> оценка на сервере. Ловит расхождения между серверной и агентской
частью (каноническая подпись, формат проб), которые unit-тесты каждой стороны не видят."""
import copy
import json
import sys
from pathlib import Path

import pytest
from sqlalchemy import text

from app.api.deps import get_pack_registry
from app.core.config import settings
from app.main import app
from app.services.packs.models import Pack
from app.services.packs.registry import PackRegistry
from tests.test_packs import BASE_PACK, make_pack

AGENT_DIR = Path(__file__).resolve().parents[3] / "agent"
if not (AGENT_DIR / "probes.py").exists():
    pytest.skip("каталог agent/ недоступен (тесты запущены вне репозитория)", allow_module_level=True)
sys.path.insert(0, str(AGENT_DIR))

import collector  # noqa: E402
import probes  # noqa: E402

CISCO_RUNNING = "hostname sw-core-01\nip http server\nline vty 0 4\n transport input telnet\n"


@pytest.fixture
def agent_key(make_org, make_agent_key):
    return make_agent_key(make_org("Interop Org"))


@pytest.fixture
def host_files(tmp_path):
    (tmp_path / "os-release").write_text('ID=ubuntu\nPRETTY_NAME="Ubuntu Test"\n', encoding="utf-8")
    (tmp_path / "sshd_config").write_text("PermitRootLogin yes\nMaxAuthTries 3\n", encoding="utf-8")
    return tmp_path


@pytest.fixture
def local_pack(host_files):
    data = make_pack()
    data["detect"][0]["probe"]["path"] = str(host_files / "os-release")
    for check in data["checks"]:
        check["probe"]["path"] = str(host_files / "sshd_config")
    return data


def serve(registry):
    app.dependency_overrides[get_pack_registry] = lambda: registry


@pytest.fixture(autouse=True)
def _cleanup_override():
    yield
    app.dependency_overrides.pop(get_pack_registry, None)


def fetch_manifests_file(client, agent_key, tmp_path, transport):
    resp = client.get(f"/api/agent/manifests?transport={transport}", headers={"X-Agent-Api-Key": agent_key})
    assert resp.status_code == 200, resp.text
    path = tmp_path / f"manifests-{transport}.json"
    path.write_text(json.dumps(resp.json()), encoding="utf-8")
    return path


def agent_args(manifests_file, *extra, key=None):
    return collector.parse_args([
        "--api-url", "http://unused", "--environment", "prod", "--use-packs", "--dry-run",
        "--manifests-file", str(manifests_file), "--pack-key", key or settings.PACK_SIGNING_KEY, *extra,
    ])


@pytest.fixture(autouse=True)
def _no_real_software_scan(monkeypatch):
    monkeypatch.setattr(collector, "collect_software", lambda: [])


def test_local_agent_end_to_end(client, db, agent_key, local_pack, tmp_path):
    serve(PackRegistry([Pack.model_validate(local_pack)]))
    manifests = fetch_manifests_file(client, agent_key, tmp_path, "local")

    payload = collector.build_pack_payload(agent_args(manifests), probes)

    assert [(r["id"], r["version"]) for r in payload["packs"]] == [("ubuntu-test", "1.0.0")]
    assert payload["platform_tags"] == ["linux-server", "debian-family", "ubuntu"]
    assert "facts" not in payload and "pack" not in payload
    assert payload["packs"][0]["probe_results"]["ssh.permit_root_login"]["value"] == "yes"

    resp = client.post("/api/ingest", json=payload, headers={"X-Agent-Api-Key": agent_key})

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["checks"] == {"total": 2, "passed": 1, "failed": 1, "errors": 0}
    row = db.execute(
        text("SELECT status, evidence, pack_version FROM scan_check_results WHERE check_id = 'ssh.permit_root_login'")
    ).one()
    assert tuple(row) == ("fail", "PermitRootLogin yes", "1.0.0")


def test_tampered_manifest_is_rejected_by_the_agent(client, agent_key, local_pack, tmp_path):
    serve(PackRegistry([Pack.model_validate(local_pack)]))
    manifests = fetch_manifests_file(client, agent_key, tmp_path, "local")
    data = json.loads(manifests.read_text(encoding="utf-8"))
    data["manifests"][0]["manifest"]["checks"][0]["probe"]["path"] = "/etc/shadow"
    manifests.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(SystemExit, match="Ошибка безопасности"):
        collector.build_pack_payload(agent_args(manifests), probes)


def test_wrong_pack_key_is_rejected(client, agent_key, local_pack, tmp_path):
    serve(PackRegistry([Pack.model_validate(local_pack)]))
    manifests = fetch_manifests_file(client, agent_key, tmp_path, "local")

    with pytest.raises(SystemExit, match="Ошибка безопасности"):
        collector.build_pack_payload(agent_args(manifests, key="not-the-server-key"), probes)


def test_unrecognized_platform_sends_nothing(client, agent_key, local_pack, host_files, tmp_path):
    (host_files / "os-release").write_text("ID=astra\n", encoding="utf-8")
    serve(PackRegistry([Pack.model_validate(local_pack)]))
    manifests = fetch_manifests_file(client, agent_key, tmp_path, "local")

    with pytest.raises(SystemExit, match="не распознана"):
        collector.build_pack_payload(agent_args(manifests), probes)


def test_several_matching_packs_are_all_run_and_sent_in_one_payload(client, db, agent_key, local_pack, tmp_path):
    second = copy.deepcopy(local_pack)
    second["pack"] = "ubuntu-extra"
    second["tags"] = ["extra-tag"]
    serve(PackRegistry([Pack.model_validate(local_pack), Pack.model_validate(second)]))
    manifests = fetch_manifests_file(client, agent_key, tmp_path, "local")

    payload = collector.build_pack_payload(agent_args(manifests), probes)

    assert [r["id"] for r in payload["packs"]] == ["ubuntu-extra", "ubuntu-test"]
    assert payload["platform_tags"] == ["extra-tag", "linux-server", "debian-family", "ubuntu"]  # объединение, без повторов
    body = client.post("/api/ingest", json=payload, headers={"X-Agent-Api-Key": agent_key}).json()
    assert body["checks"]["total"] == 4  # по 2 проверки от каждого пака, один прогон
    assert {p["id"]: p["total"] for p in body["packs"]} == {"ubuntu-extra": 2, "ubuntu-test": 2}
    assert db.execute(text("SELECT COUNT(*) FROM scan_snapshots")).scalar() == 1  # один снимок, а не по одному на пак


def test_pack_option_restricts_the_run_to_one_pack(client, agent_key, local_pack, tmp_path):
    second = copy.deepcopy(local_pack)
    second["pack"] = "ubuntu-extra"
    serve(PackRegistry([Pack.model_validate(local_pack), Pack.model_validate(second)]))
    manifests = fetch_manifests_file(client, agent_key, tmp_path, "local")

    payload = collector.build_pack_payload(agent_args(manifests, "--pack", "ubuntu-extra"), probes)

    assert [r["id"] for r in payload["packs"]] == ["ubuntu-extra"]


def test_missing_pack_key_is_reported(client, agent_key, local_pack, tmp_path):
    serve(PackRegistry([Pack.model_validate(local_pack)]))
    manifests = fetch_manifests_file(client, agent_key, tmp_path, "local")
    args = agent_args(manifests)
    args.pack_key = None
    with pytest.raises(SystemExit, match="pack-key"):
        collector.build_pack_payload(args, probes)


def test_network_device_over_ssh_end_to_end(client, db, agent_key, tmp_path, monkeypatch):
    cisco = make_pack(
        pack="cisco-test", transport="ssh", tags=["network-device", "cisco-ios"], asset_type="network-device",
        detect=[{"probe": {"type": "cli_config", "cmd": "show version", "match": r"(Cisco IOS)"}, "equals": "Cisco IOS"}],
        checks=[
            {"id": "cisco_ios.http_server_disabled", "title": "HTTP выключен",
             "probe": {"type": "cli_config", "cmd": "show running-config", "match": "^ip http server"},
             "assert": {"op": "absent"}, "severity": "medium"},
            {"id": "cisco_ios.vty_ssh_only", "title": "VTY только SSH",
             "probe": {"type": "cli_config", "cmd": "show running-config", "section": r"^line vty 0 4",
                       "match": r"transport input (\w+)"},
             "assert": {"op": "eq", "value": "ssh"}},
        ],
    )
    serve(PackRegistry([Pack.model_validate(cisco), Pack.model_validate(BASE_PACK)]))
    manifests = fetch_manifests_file(client, agent_key, tmp_path, "ssh")
    commands = []

    def fake_ssh(argv, **kwargs):
        command = argv[-1]
        commands.append(command)
        out = "Cisco IOS Software, Version 15.2" if command == "show version" else CISCO_RUNNING
        return type("P", (), {"stdout": out, "stderr": "", "returncode": 0})()

    monkeypatch.setattr(probes.subprocess, "run", fake_ssh)
    args = agent_args(manifests, "--ssh-host", "10.0.0.1", "--ssh-user", "audit")

    payload = collector.build_pack_payload(args, probes)

    assert payload["asset"] == {"hostname": "10.0.0.1", "ip_address": None, "os": None,
                                "asset_type": "network-device", "criticality": "medium"}
    assert payload["software"] == [] and [r["id"] for r in payload["packs"]] == ["cisco-test"]
    assert set(commands) == {"show version", "show running-config"}  # только команды на чтение

    body = client.post("/api/ingest", json=payload, headers={"X-Agent-Api-Key": agent_key}).json()
    assert body["checks"] == {"total": 2, "passed": 0, "failed": 2, "errors": 0}
    evidence = db.execute(text("SELECT evidence FROM scan_check_results WHERE check_id = 'cisco_ios.vty_ssh_only'")).scalar()
    assert evidence == "transport input telnet"


# ---------- выгрузка конфигурации вместо живого устройства ----------

def _offline_cisco_pack():
    return make_pack(
        pack="cisco-test", transport="ssh", tags=["network-device", "cisco-ios"], asset_type="network-device",
        detect=[{"probe": {"type": "cli_config", "cmd": "show version", "match": r"(Cisco IOS)"}, "equals": "Cisco IOS"}],
        checks=[
            {"id": "cisco_ios.http_server_disabled", "title": "HTTP выключен",
             "probe": {"type": "cli_config", "cmd": "show running-config", "match": "^ip http server"},
             "assert": {"op": "absent"}, "severity": "medium"},
            {"id": "cisco_ios.snmp_no_public", "title": "Нет community public",
             "probe": {"type": "cli_config", "cmd": "show running-config", "match": r"^(snmp-server community .*)"},
             "assert": {"op": "absent"}, "severity": "high"},
        ],
    )


@pytest.fixture
def offline_dir(tmp_path):
    export = tmp_path / "export-sw-core-01"
    export.mkdir()
    (export / "show_running-config.txt").write_text(
        CISCO_RUNNING + "snmp-server community S3cr3tComm RO\n", encoding="utf-8")
    return export


def test_offline_config_end_to_end_is_marked_as_export_in_snapshot_and_report(
        client, db, agent_key, offline_dir, tmp_path, monkeypatch):
    (offline_dir / "show_version.txt").write_text("Cisco IOS Software, Version 15.2\n", encoding="utf-8")
    serve(PackRegistry([Pack.model_validate(_offline_cisco_pack()), Pack.model_validate(BASE_PACK)]))
    manifests = fetch_manifests_file(client, agent_key, tmp_path, "ssh")
    monkeypatch.setattr(probes.subprocess, "run", lambda *a, **k: pytest.fail("по выгрузке ничего не выполняется"))
    args = agent_args(manifests, "--offline-dir", str(offline_dir), "--hostname", "sw-core-01")

    payload = collector.build_pack_payload(args, probes)

    assert payload["asset"]["hostname"] == "sw-core-01" and payload["asset"]["asset_type"] == "network-device"
    collection = payload["collection"]
    assert collection["source"] == "offline-config" and collection["declared_pack"] is False
    assert [f["file"] for f in collection["files"]] == ["show_running-config.txt", "show_version.txt"]
    assert all(len(f["sha256"]) == 64 and f["modified"].endswith("Z") for f in collection["files"])

    body = client.post("/api/ingest", json=payload, headers={"X-Agent-Api-Key": agent_key}).json()
    assert body["checks"] == {"total": 2, "passed": 0, "failed": 2, "errors": 0}
    evidence = db.execute(text("SELECT evidence FROM scan_check_results WHERE check_id = 'cisco_ios.snmp_no_public'")).scalar()
    assert "S3cr3tComm" not in evidence  # секреты маскируются так же, как по SSH
    stored = db.execute(text("SELECT collection FROM scan_snapshots WHERE id = :id"), {"id": body["snapshot_id"]}).scalar()
    assert stored["source"] == "offline-config" and len(stored["files"]) == 2

    from app.services.snapshot_export import load_snapshot_report, source_label
    report = load_snapshot_report(db, body["snapshot_id"])
    assert source_label(report.collection).startswith("Выгрузка конфигурации от ")
    assert "не живое устройство" in source_label(report.collection)


def test_offline_config_without_detect_output_needs_explicit_pack(client, agent_key, offline_dir, tmp_path):
    serve(PackRegistry([Pack.model_validate(_offline_cisco_pack())]))
    manifests = fetch_manifests_file(client, agent_key, tmp_path, "ssh")
    args = agent_args(manifests, "--offline-dir", str(offline_dir), "--hostname", "sw-core-01")
    with pytest.raises(SystemExit, match="--pack"):
        collector.build_pack_payload(args, probes)


def test_offline_config_with_declared_pack_is_marked_as_unconfirmed(client, agent_key, offline_dir, tmp_path):
    serve(PackRegistry([Pack.model_validate(_offline_cisco_pack())]))
    manifests = fetch_manifests_file(client, agent_key, tmp_path, "ssh")
    args = agent_args(manifests, "--offline-dir", str(offline_dir), "--hostname", "sw-core-01", "--pack", "cisco-test")

    payload = collector.build_pack_payload(args, probes)

    assert payload["collection"]["declared_pack"] is True
    resp = client.post("/api/ingest", json=payload, headers={"X-Agent-Api-Key": agent_key})
    assert resp.status_code == 200, resp.text
    from app.services.snapshot_export import source_label
    assert "платформа по выгрузке не подтверждена" in source_label(payload["collection"])


def test_declared_pack_does_not_override_contradicting_export(client, agent_key, offline_dir, tmp_path):
    (offline_dir / "show_version.txt").write_text("Huawei Versatile Routing Platform\n", encoding="utf-8")
    serve(PackRegistry([Pack.model_validate(_offline_cisco_pack())]))
    manifests = fetch_manifests_file(client, agent_key, tmp_path, "ssh")
    args = agent_args(manifests, "--offline-dir", str(offline_dir), "--hostname", "sw-core-01", "--pack", "cisco-test")
    with pytest.raises(SystemExit, match="не распознана"):
        collector.build_pack_payload(args, probes)


def test_offline_config_needs_hostname_and_excludes_ssh(client, agent_key, offline_dir, tmp_path):
    serve(PackRegistry([Pack.model_validate(_offline_cisco_pack())]))
    manifests = fetch_manifests_file(client, agent_key, tmp_path, "ssh")
    with pytest.raises(SystemExit, match="--hostname"):
        collector.build_pack_payload(agent_args(manifests, "--offline-dir", str(offline_dir)), probes)
    with pytest.raises(SystemExit, match="взаимоисключающие"):
        collector.build_pack_payload(agent_args(manifests, "--offline-dir", str(offline_dir), "--hostname", "x",
                                                "--ssh-host", "10.0.0.1"), probes)


def test_ingest_rejects_unknown_collection_source(client, agent_key):
    resp = client.post("/api/ingest", headers={"X-Agent-Api-Key": agent_key}, json={
        "environment": "prod", "asset": {"hostname": "h"}, "collection": {"source": "rumors"}})
    assert resp.status_code == 422
