"""Один файл выгрузки даёт те же проверки, что набор файлов, на фикстуре каждого ssh-пака."""
import importlib.util
import io
import json
import zipfile
from pathlib import Path

import pytest
import yaml

from app.services.offline_scan import preview_bundle, run_offline, run_offline_bundle
from app.services.packs.authoring import AGENT_DIR, FIXTURES_DIR, load_agent_probes
from app.services.packs.registry import load_registry

ROOT = Path(__file__).resolve().parents[3]
REGISTRY = load_registry(ROOT / "src" / "backend" / "app" / "packs")
PROBES = load_agent_probes()
PACKS = (
    "cisco-ios", "dionis-nx", "eltex-esr", "eltex-mes", "infowatch-arma-ngfw", "kontinent-4",
    "pt-ngfw", "qtech-qsw", "s-terra-gate", "snr-switch", "usergate-ngfw", "vipnet-coordinator",
)


def _splitter():
    path = AGENT_DIR / "offline_split.py"
    spec = importlib.util.spec_from_file_location("offline_split_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SPLITTER = _splitter()


def _cli(spec):
    raw = (spec.get("base") or {}).get("cli") or {}
    out = {}
    for command, value in raw.items():
        if isinstance(value, dict):
            value = value.get("stdout") or ""
        if value:
            out[command] = value if str(value).endswith("\n") else str(value) + "\n"
    return out


def _commands():
    found = []
    for pack in PACKS:
        spec = yaml.safe_load((FIXTURES_DIR / f"{pack}.yaml").read_text(encoding="utf-8"))
        for command in _cli(spec):
            if command not in found:
                found.append(command)
    return found


COMMANDS = _commands()


def _signature(run):
    probes = {
        pack.pack: {check_id: (row["found"], row.get("value")) for check_id, row in results.items()}
        for pack, results in run.packs
    }
    software = [(item["name"], item["version"]) for item in run.software]
    return probes, software


def _typed(command, abbreviate):
    if not abbreviate:
        return command
    short = " ".join(token[:3] for token in command.split())
    if SPLITTER.match_command(short, COMMANDS) == command:
        return short
    return command


def _session(cli, abbreviate=False):
    parts = ["sw-core-01# terminal length 0\n"]
    for command, text in cli.items():
        parts.append("sw-core-01# {0} | no-more\n".format(_typed(command, abbreviate)))
        parts.append(text)
        parts.append("--More--\x08\x08\x08\x08\x08\x08\x08\x08\n")
    parts.append("sw-core-01#\n")
    return "".join(parts).encode("utf-8")


def _zip(cli):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        for command, text in cli.items():
            archive.writestr("export/" + PROBES.offline_file_name(command), text.encode("utf-8"))
    return buf.getvalue()


def test_offline_file_name_matches_agent():
    assert SPLITTER.offline_file_name("show running-config") == PROBES.offline_file_name("show running-config")
    assert SPLITTER.offline_file_name("show network zone Untrusted") == "show_network_zone_Untrusted.txt"


@pytest.mark.parametrize("pack", PACKS)
def test_session_archive_and_abbreviations_match_multifile(pack):
    spec = yaml.safe_load((FIXTURES_DIR / f"{pack}.yaml").read_text(encoding="utf-8"))
    cli = _cli(spec)
    assert cli, pack
    direct = run_offline(REGISTRY, {command: text.encode("utf-8") for command, text in cli.items()}, None)
    assert direct.packs, pack
    expect = _signature(direct)
    assert _signature(run_offline_bundle(REGISTRY, _session(cli), "session.log", None)) == expect
    assert _signature(run_offline_bundle(REGISTRY, _session(cli, abbreviate=True), "short.log", None)) == expect
    archived = run_offline_bundle(REGISTRY, _zip(cli), "export.zip", None)
    assert _signature(archived) == expect
    assert archived.collection["bundle_format"] == "archive"


@pytest.mark.parametrize("pack, auto", [
    ("cisco-ios", True),
    ("s-terra-gate", True),
    ("eltex-esr", True),
    ("eltex-mes", True),
    ("dionis-nx", True),
    ("infowatch-arma-ngfw", True),
    ("qtech-qsw", False),
    ("snr-switch", False),
])
def test_config_only_matches_declared_multifile(pack, auto):
    spec = yaml.safe_load((FIXTURES_DIR / f"{pack}.yaml").read_text(encoding="utf-8"))
    cli = _cli(spec)
    command = "show running-config" if "show running-config" in cli else "show configuration commands"
    direct = run_offline(REGISTRY, {command: cli[command].encode("utf-8")}, pack)
    bundled = run_offline_bundle(
        REGISTRY, cli[command].encode("utf-8"), "cfg.txt", None if auto else pack,
    )
    assert _signature(bundled)[0] == _signature(direct)[0]
    assert bundled.collection["recognized_by"] == ("config" if auto else "declared")
    assert bundled.collection["declared_pack"] is (False if auto else True)


def test_qtech_config_without_version_asks_for_pack():
    spec = yaml.safe_load((FIXTURES_DIR / "qtech-qsw.yaml").read_text(encoding="utf-8"))
    raw = _cli(spec)["show running-config"].encode("utf-8")
    preview = preview_bundle(REGISTRY, raw, "cfg.txt", None)
    assert preview["needs_declared"] is True
    assert set(preview["ambiguous_packs"]) == {"qtech-qsw", "snr-switch"}
    assert "show running-config" in preview["found"]


def test_continent_json_bundle_and_archive_match_two_files():
    fix = ROOT / "agent" / "tests" / "fixtures" / "continent4"
    export = (fix / "export-for-cgw-4210001.json").read_bytes()
    cgw = (fix / "cgw.json").read_bytes()
    direct = run_offline(REGISTRY, {"export-config-for-cgw.json": export, "cgw.json": cgw}, None)
    raw = json.dumps({"export": json.loads(export), "cgw": json.loads(cgw)}).encode("utf-8")
    assert _signature(run_offline_bundle(REGISTRY, raw, "bundle.json", None)) == _signature(direct)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        archive.writestr("export-for-cgw-4210001.json", export)
        archive.writestr("cgw.json", cgw)
    assert _signature(run_offline_bundle(REGISTRY, buf.getvalue(), "c4.zip", None)) == _signature(direct)


def test_oxidized_comments_match_cisco_files():
    spec = yaml.safe_load((FIXTURES_DIR / "cisco-ios.yaml").read_text(encoding="utf-8"))
    cli = _cli(spec)
    commented = ["! " + line if line else "!" for line in cli["show version"].splitlines()]
    text = "\n".join(commented + ["!"] + cli["show running-config"].splitlines()) + "\n"
    direct = run_offline(REGISTRY, {command: body.encode("utf-8") for command, body in cli.items()}, None)
    bundled = run_offline_bundle(REGISTRY, text.encode("utf-8"), "oxidized.cfg", None)
    assert _signature(bundled) == _signature(direct)
