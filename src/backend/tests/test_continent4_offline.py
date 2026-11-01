"""Выгрузка JSON ЦУС Континент 4 проходит тем же путём, что и текстовые show-файлы."""
from pathlib import Path

from app.services.offline_scan import run_offline
from app.services.packs.registry import load_registry

ROOT = Path(__file__).resolve().parents[3]
FIX = ROOT / "agent" / "tests" / "fixtures" / "continent4"
REGISTRY = load_registry(ROOT / "src" / "backend" / "app" / "packs")


def _run(export_name, cgw_name):
    files = {
        "export-config-for-cgw.json": (FIX / export_name).read_bytes(),
        "cgw.json": (FIX / cgw_name).read_bytes(),
    }
    return run_offline(REGISTRY, files, "kontinent-4")


def _value(result, check_id):
    for pack, raw in result.packs:
        if pack.pack == "kontinent-4":
            return raw[check_id]["value"]
    raise AssertionError("пак kontinent-4 не выполнен")


def test_export_json_upload_differs_before_and_after_and_feeds_firmware():
    changed = _run("export-for-cgw-4210001.json", "cgw.json")
    initial = _run("export-for-cgw-4210001-initial.json", "cgw-initial.json")
    assert _value(changed, "kontinent4.personal_admin_accounts") == 2
    assert _value(initial, "kontinent4.personal_admin_accounts") == 0
    assert changed.software == initial.software
    assert changed.software[0]["version"] == "4.2.1-653"
    assert changed.software[0]["name"] == "комплекс безопасности «континент». версия 4"
    assert changed.collection["source"] == "offline-config"
    names = {item["file"] for item in changed.collection["files"]}
    assert "export-config-for-cgw.json" in names
