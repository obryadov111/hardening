"""Разбор одного файла выгрузки: сокращения, журнал, бэкап, архив, мусор терминала."""
import io
import stat
import tarfile
import zipfile
from pathlib import Path

import pytest

import offline_split
from offline_split import SplitError, match_command, split_bytes

FIX = Path(__file__).resolve().parent / "fixtures" / "usergate"
COMMANDS = [
    "show version",
    "show running-config",
    "show system",
    "show configuration",
    "show configuration commands",
    "show system version",
    "show settings administrators general",
    "show network zone",
    "show network zone Untrusted",
    "show network zone Management",
    "show network-policy firewall",
    "show logs logs-export",
    "show continent version",
    "version",
    "inet show snmp community",
    "iplir option get antispoofing",
]


def test_abbreviations_ignore_pipes_and_spaces():
    assert match_command("sh ver", COMMANDS) == "show version"
    assert match_command("SH   RUN", COMMANDS) == "show running-config"
    assert match_command("show running-config | no-more", COMMANDS) == "show running-config"
    assert match_command("sh run | exclude ^!", COMMANDS) == "show running-config"
    assert match_command("terminal length 0", COMMANDS) is None
    assert match_command("sh", COMMANDS) is None  # неоднозначно
    assert match_command("show network zone", COMMANDS) == "show network zone"
    assert match_command("sh net zone Untr", COMMANDS) == "show network zone Untrusted"
    assert match_command("sh conf com", COMMANDS) == "show configuration commands"
    assert match_command("sh configuration", COMMANDS) == "show configuration"
    assert match_command("inet sh snmp com", COMMANDS) == "inet show snmp community"


def test_session_log_strips_more_and_backspace():
    log = (
        "sw-core-01#terminal length 0\n"
        "sw-core-01# sh ver | no-more\n"
        "Cisco IOS Software, C2960 Software, Version 15.2\n"
        "--More--\n"
        "sw-core-01#sh run\n"
        "version 15.2\n"
        "hostname sw\n"
        "end\n"
        "sw-core-01#\n"
    )
    # backspace: оператор стёр «sho» и набрал команду заново
    raw = "sw-core-01# sho\x08\x08\x08sh ver\nCisco IOS Software\nsw-core-01#\n"
    wiped = split_bytes(raw.encode("utf-8"), COMMANDS)
    assert wiped.found == ["show version"]
    assert b"Cisco IOS Software" in wiped.files["show version"]

    split = split_bytes(log.encode("utf-8"), COMMANDS)
    assert split.kind == "session"
    assert split.found == ["show version", "show running-config"]
    assert b"--More--" not in split.files["show version"]
    assert split.recognized_pack == "cisco-ios"
    assert b"hostname sw" in split.files["show running-config"]


def test_linux_prompt_and_usergate_echo():
    log = "admin@fw:~$ show version\nCisco IOS Software, Version 15.2\nadmin@fw:~$\n"
    split = split_bytes(log.encode("utf-8"), COMMANDS)
    assert split.files["show version"].decode("utf-8").startswith("Cisco IOS Software")

    echoed = (
        "Admin@node#show settings administrators general"
        "Admin@node# show settings administrators general\n"
        "num-auth-attempts    : 10\n"
        "Admin@node#\n"
    )
    split = split_bytes(echoed.encode("utf-8"), COMMANDS)
    assert split.found == ["show settings administrators general"]
    assert b"num-auth-attempts" in split.files["show settings administrators general"]


def test_real_usergate_sessions_keep_pack_commands():
    wanted = {
        "show system version",
        "show settings administrators general",
        "show network zone",
        "show network zone Untrusted",
        "show network zone Management",
        "show network-policy firewall",
        "show logs logs-export",
    }
    clean = split_bytes((FIX / "session-h1000.clean.txt").read_bytes(), COMMANDS, filename="session.txt")
    raw = split_bytes((FIX / "session-h1000.raw").read_bytes(), COMMANDS, filename="session.raw")
    assert wanted <= set(clean.found)
    assert wanted <= set(raw.found)
    assert b"num-auth-attempts" in clean.files["show settings administrators general"]
    assert b"UGOS NGFW" in raw.files["show system version"]
    assert clean.recognized_pack == "usergate-ngfw"


def test_oxidized_and_rancid_markers():
    oxidized = (
        "! Command: show version\n"
        "Cisco IOS Software, Version 15.2\n"
        "! Command: sh run | no-more\n"
        "version 15.2\n"
        "end\n"
    )
    split = split_bytes(oxidized.encode("utf-8"), COMMANDS)
    assert split.kind == "oxidized"
    assert set(split.found) == {"show version", "show running-config"}

    commented = (
        "! Cisco IOS Software, C2960 Software, Version 15.0\n"
        "! ROM: Bootstrap\n"
        "!\n"
        "version 15.2\n"
        "hostname sw\n"
        "end\n"
    )
    split = split_bytes(commented.encode("utf-8"), COMMANDS)
    assert split.kind == "oxidized"
    assert b"Cisco IOS Software" in split.files["show version"]
    assert b"hostname sw" in split.files["show running-config"]

    rancid = (
        "!RANCID-CONTENT-TYPE: cisco\n"
        "!\n"
        "!Chassis type: WS-C2960\n"
        "version 15.2\n"
        "hostname sw\n"
        "end\n"
    )
    split = split_bytes(rancid.encode("utf-8"), COMMANDS)
    assert split.kind == "rancid"
    assert split.found == ["show running-config"]
    assert split.recognized_pack == "cisco-ios"


def test_config_fingerprint_distinguishes_cisco_stera_and_ambiguous_dcn():
    cisco = "version 15.2\nhostname sw\nend\n"
    split = split_bytes(cisco.encode("utf-8"), COMMANDS)
    assert split.recognized_pack == "cisco-ios"
    assert split.found == ["show running-config"]

    stera = "version 12.4\ncrypto isakmp policy 10\n encr gost341215k\nend\n"
    split = split_bytes(stera.encode("utf-8"), COMMANDS)
    assert split.recognized_pack == "s-terra-gate"

    dcn = "hostname sw\nno telnet-server enable\nauthentication securityip 10.0.0.1\nend\n"
    split = split_bytes(dcn.encode("utf-8"), COMMANDS)
    assert split.recognized_pack is None
    assert split.ambiguous_packs == ["qtech-qsw", "snr-switch"]
    assert split.found == ["show running-config"]


def test_detect_blob_is_the_command_itself():
    split = split_bytes(b"Product: ViPNet Coordinator HW1000\nSoftware version: 4.3.2\n", COMMANDS)
    assert split.found == ["version"]
    assert split.recognized_pack == "vipnet-coordinator"


def test_json_command_bundle_and_continent_export():
    bundle = b'{"sh ver": "Cisco IOS Software, Version 15.2\\n", "show running-config": "version 15.2\\nend\\n"}'
    split = split_bytes(bundle, COMMANDS, filename="bundle.json")
    assert split.kind == "json-commands"
    assert set(split.found) == {"show version", "show running-config"}

    continent = b'{"hwserial": 1, "type": "full", "objects": [{"type": "passwordpolicy"}]}'
    split = split_bytes(continent, COMMANDS)
    assert split.mode == "json" and split.kind == "json"
    assert "bundle.json" in split.files

    with pytest.raises(SplitError, match="JSON не похож"):
        split_bytes(b'{"hello": "world"}', COMMANDS)


def test_zip_roundtrip_and_nested_name():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("export/show_version.txt", b"Cisco IOS Software, Version 15.2\n")
        zf.writestr("show_running-config.txt", b"version 15.2\nhostname sw\nend\n")
    split = split_bytes(buf.getvalue(), COMMANDS, filename="cfg.zip")
    assert split.kind == "archive"
    assert set(split.found) == {"show version", "show running-config"}


def test_zip_slip_symlink_and_limits(monkeypatch):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../evil.txt", b"secret")
    with pytest.raises(SplitError, match="небезопасный путь"):
        split_bytes(buf.getvalue(), COMMANDS)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        info = zipfile.ZipInfo("link.txt")
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        info.compress_type = zipfile.ZIP_STORED
        zf.writestr(info, b"/etc/passwd")
    with pytest.raises(SplitError, match="символическ"):
        split_bytes(buf.getvalue(), COMMANDS)

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        info = tarfile.TarInfo("link")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        tf.addfile(info)
    with pytest.raises(SplitError, match="символическ"):
        split_bytes(buf.getvalue(), COMMANDS)

    monkeypatch.setattr(offline_split, "MAX_ARCHIVE_ENTRIES", 1)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("show_version.txt", b"Cisco IOS Software\n")
        zf.writestr("show_running-config.txt", b"end\n")
    with pytest.raises(SplitError, match="слишком много файлов"):
        split_bytes(buf.getvalue(), COMMANDS)


def test_tar_gz_and_single_gzipped_log():
    payload = b"sw# show version\nCisco IOS Software, Version 15.2\nsw#\n"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        info = tarfile.TarInfo("show_version.txt")
        info.size = len(b"Cisco IOS Software, Version 15.2\n")
        tf.addfile(info, io.BytesIO(b"Cisco IOS Software, Version 15.2\n"))
    split = split_bytes(buf.getvalue(), COMMANDS, filename="a.tar.gz")
    assert split.found == ["show version"]

    import gzip
    gz = gzip.compress(payload)
    split = split_bytes(gz, COMMANDS, filename="session.gz")
    assert split.found == ["show version"]


def test_empty_binary_and_fallback():
    with pytest.raises(SplitError, match="пустой"):
        split_bytes(b" \n\t", COMMANDS)
    with pytest.raises(SplitError, match="двоичный"):
        split_bytes(b"\x00\x01\x02" * 50, COMMANDS)
    with pytest.raises(SplitError, match="больше"):
        split_bytes(b"a" * (offline_split.MAX_TEXT_BYTES + 1), COMMANDS)
    split = split_bytes(b"hostname sw\nno commands here\n", COMMANDS, fallback_command="show running-config")
    assert split.kind == "fallback"
    assert split.found == ["show running-config"]


def test_cp1251_roundtrip():
    text = "sw# show running-config\nversion 15.2\ndescription Коммутатор\nend\nsw#\n"
    split = split_bytes(text.encode("cp1251"), COMMANDS)
    assert "Коммутатор" in split.files["show running-config"].decode("utf-8")
