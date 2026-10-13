"""Загрузка выгрузки конфигурации через интерфейс: сервер выполняет пробы агента по файлам
и записывает обычный снимок с источником «выгрузка конфигурации»."""
import pytest
from sqlalchemy import text

from app.api.deps import get_pack_registry
from app.main import app
from app.services.packs.models import Pack
from app.services.packs.registry import PackRegistry
from tests.test_packs import BASE_PACK, make_pack

RUNNING = "hostname sw-core-01\nip http server\nsnmp-server community S3cr3tComm RO\nline vty 0 4\n transport input ssh\nend\n"


def _cisco_pack():
    return make_pack(
        pack="cisco-test", transport="ssh", tags=["network-device", "cisco-ios"], asset_type="network-device",
        detect=[{"probe": {"type": "cli_config", "cmd": "show version", "match": r"(Cisco IOS)"}, "equals": "Cisco IOS"}],
        checks=[
            {"id": "cisco_ios.http_server_disabled", "title": "HTTP выключен",
             "probe": {"type": "cli_config", "cmd": "show running-config", "match": "^ip http server"},
             "assert": {"op": "absent"}, "severity": "medium"},
            {"id": "cisco_ios.snmp_no_community", "title": "Нет community в открытом виде",
             "probe": {"type": "cli_config", "cmd": "show running-config", "match": r"^snmp-server community (\S+)"},
             "assert": {"op": "absent"}, "severity": "high"},
            {"id": "cisco_ios.vty_ssh", "title": "VTY только SSH",
             "probe": {"type": "cli_config", "cmd": "show running-config", "section": r"^line vty",
                       "match": r"transport input (\w+)"},
             "assert": {"op": "eq", "value": "ssh"}, "severity": "high"},
        ],
    )


@pytest.fixture(autouse=True)
def registry():
    reg = PackRegistry([Pack.model_validate(_cisco_pack()), Pack.model_validate(BASE_PACK)])
    app.dependency_overrides[get_pack_registry] = lambda: reg
    yield reg
    app.dependency_overrides.pop(get_pack_registry, None)


@pytest.fixture
def org(make_org, make_user, add_membership, auth_header):
    org_id = make_org("Offline Org")
    add_membership(make_user("offline-admin@example.com"), org_id, role="admin")
    add_membership(make_user("offline-viewer@example.com"), org_id, role="viewer")
    return {"id": org_id, "admin": auth_header("offline-admin@example.com"),
            "viewer": auth_header("offline-viewer@example.com")}


def upload(client, org, files, headers=None, **form):
    data = {"hostname": "sw-core-01", "commands": [c for c, _ in files], **form}
    return client.post(
        f"/api/organizations/{org['id']}/offline-scans", headers=headers or org["admin"], data=data,
        files=[("files", (f"{c.replace(' ', '_')}.txt", body.encode("utf-8") if isinstance(body, str) else body, "text/plain"))
               for c, body in files],
    )


def test_packs_list_shows_needed_files(client, org):
    resp = client.get(f"/api/organizations/{org['id']}/offline-scans/packs", headers=org["viewer"])
    assert resp.status_code == 200, resp.text
    packs = resp.json()["packs"]
    assert [p["pack"] for p in packs] == ["cisco-test"]  # только сетевые (ssh) паки
    assert packs[0]["commands"] == [
        {"command": "show version", "file": "show_version.txt", "detect": True, "checks": False},
        {"command": "show running-config", "file": "show_running-config.txt", "detect": False, "checks": True},
    ]


def test_upload_creates_snapshot_marked_as_export(client, db, org):
    resp = upload(client, org, [("show version", "Cisco IOS Software, Version 15.2"), ("show running-config", RUNNING)],
                  exported_at="2026-10-01T08:00:00Z", scan_label="выгрузка из бэкапа")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["checks"] == {"total": 3, "passed": 1, "failed": 2, "errors": 0}

    snap = db.execute(text("SELECT collection, snapshot_label FROM scan_snapshots WHERE id = :id"),
                      {"id": body["snapshot_id"]}).mappings().one()
    collection = snap["collection"]
    assert collection["source"] == "offline-config" and collection["declared_pack"] is False
    assert collection["uploaded_by"] == "offline-admin@example.com"
    assert {f["modified"] for f in collection["files"]} == {"2026-10-01T08:00:00Z"}
    assert {f["uploaded_name"] for f in collection["files"]} == {"show_version.txt", "show_running-config.txt"}
    assert snap["snapshot_label"] == "выгрузка из бэкапа"

    asset = db.execute(text("SELECT asset_type, platform_tags FROM assets WHERE id = :id"), {"id": body["asset_id"]}).one()
    assert asset.asset_type == "network-device" and "cisco-ios" in asset.platform_tags
    source = db.execute(text("SELECT source FROM ingestion_batches WHERE id = :id"), {"id": body["batch_id"]}).scalar()
    assert source == "offline-upload"
    stored = db.execute(text("SELECT actual_value, evidence FROM scan_check_results WHERE check_id = 'cisco_ios.snmp_no_community'")).one()
    assert "S3cr3tComm" not in (stored.actual_value or "") + (stored.evidence or "")

    listed = client.get(f"/api/organizations/{org['id']}/snapshots", headers=org["viewer"]).json()["items"]
    assert listed[0]["collection"]["source"] == "offline-config"


def test_running_config_only_needs_explicit_pack(client, org):
    resp = upload(client, org, [("show running-config", RUNNING)])
    assert resp.status_code == 422 and "выберите пак" in resp.json()["detail"]

    resp = upload(client, org, [("show running-config", RUNNING)], pack="cisco-test")
    assert resp.status_code == 200, resp.text


def test_contradicting_export_is_rejected_even_with_pack(client, org):
    resp = upload(client, org, [("show version", "Huawei Versatile Routing Platform"), ("show running-config", RUNNING)],
                  pack="cisco-test")
    assert resp.status_code == 422 and "не похожа" in resp.json()["detail"]


def test_viewer_cannot_upload(client, org):
    assert upload(client, org, [("show running-config", RUNNING)], headers=org["viewer"], pack="cisco-test").status_code == 403


def test_other_organization_admin_cannot_upload(client, org, make_org, make_user, add_membership, auth_header):
    other = make_org("Other Org")
    add_membership(make_user("other-offline@example.com"), other, role="admin")
    resp = upload(client, org, [("show running-config", RUNNING)], headers=auth_header("other-offline@example.com"), pack="cisco-test")
    assert resp.status_code == 403


@pytest.mark.parametrize("files, form, detail", [
    ([("reload", "x")], {"pack": "cisco-test"}, "не используется ни одним паком"),
    ([("show running-config", RUNNING), ("show running-config", RUNNING)], {}, "дважды"),
    ([("show running-config", "\n  \n")], {"pack": "cisco-test"}, None),  # пустая выгрузка — проверки error, не pass
    ([("show running-config", RUNNING)], {"pack": "linux-test"}, "нет пака"),
    ([("show running-config", RUNNING)], {"pack": "cisco-test", "exported_at": "2099-01-01T00:00:00Z"}, "в будущем"),
    ([("show running-config", RUNNING)], {"pack": "cisco-test", "criticality": "extreme"}, "Критичность"),
])
def test_bad_uploads(client, org, files, form, detail):
    resp = upload(client, org, files, **form)
    if detail is None:
        assert resp.status_code == 200, resp.text
        assert resp.json()["checks"]["passed"] == 0 and resp.json()["checks"]["errors"] == 3
    else:
        assert resp.status_code in (413, 422) and detail in resp.json()["detail"], resp.text


def test_commands_and_files_must_pair(client, org):
    resp = client.post(f"/api/organizations/{org['id']}/offline-scans", headers=org["admin"],
                       data={"hostname": "sw", "commands": ["show version", "show running-config"]},
                       files=[("files", ("a.txt", b"x", "text/plain"))])
    assert resp.status_code == 422


def test_too_large_file_is_rejected(client, org, monkeypatch):
    import app.api.routes.offline_scans as route
    monkeypatch.setattr(route, "MAX_FILE_BYTES", 10)
    resp = upload(client, org, [("show running-config", RUNNING)], pack="cisco-test")
    assert resp.status_code == 413
