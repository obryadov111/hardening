"""Сбор фактов агентом: встроенные проверки старого режима, ПО, ОС, адрес; режим паков без сервера
(--manifests-file с --dry-run и --out) и сообщения об ошибках запуска. Файлы и команды хоста подменены."""
import copy
import hashlib
import hmac
import json
import subprocess
import sys

import pytest

import collector
import probes


@pytest.fixture
def host(monkeypatch):
    """Подменённый хост: files — содержимое файлов, commands — вывод команд (None — команда не выполнилась)."""
    state = {"files": {}, "commands": {}}
    monkeypatch.setattr(collector, "read_file", lambda path: state["files"].get(path))
    monkeypatch.setattr(collector, "run", lambda cmd: state["commands"].get(tuple(cmd)))
    return state


# ---------- read_file и run на настоящей системе ----------

def test_read_file_returns_none_for_missing_file(tmp_path):
    assert collector.__dict__["read_file"](str(tmp_path / "нет")) is None
    path = tmp_path / "f"
    path.write_bytes(b"ok \xff")  # битые байты не роняют чтение
    assert collector.read_file(str(path)) == "ok �"


def test_run_returns_none_on_error_exit_missing_binary_and_timeout(monkeypatch):
    assert collector.run([sys.executable, "-c", "print('hi')"]) == "hi\n"
    assert collector.run([sys.executable, "-c", "import sys; sys.exit(3)"]) is None
    assert collector.run(["/нет/такой/команды"]) is None

    def slow(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], 15)
    monkeypatch.setattr(collector.subprocess, "run", slow)
    assert collector.run(["sleep", "100"]) is None


# ---------- SSH ----------

def test_sshd_config_defaults_comments_case_and_values():
    facts = collector.parse_sshd_config(
        "# PermitRootLogin yes\n"
        "PERMITROOTLOGIN Prohibit-Password  # комментарий в строке\n"
        "MaxAuthTries 3\n"
        "PasswordAuthentication\n"  # без значения — не меняет умолчание
        "Unknown option\n"
    )
    assert facts == {
        "permit_root_login": "prohibit-password", "password_authentication": "yes",
        "permit_empty_passwords": "no", "x11_forwarding": "no", "max_auth_tries": "3",
    }


def test_ssh_facts_absent_without_sshd_config(host):
    assert collector.collect_ssh_facts() == {}
    host["files"]["/etc/ssh/sshd_config"] = "PermitRootLogin yes\n"
    assert collector.collect_ssh_facts()["permit_root_login"] == "yes"


# ---------- файрвол ----------

def test_firewall_from_config_files_when_ufw_cannot_run(host):
    host["files"]["/etc/ufw/ufw.conf"] = "ENABLED=yes\n"
    host["files"]["/etc/default/ufw"] = 'DEFAULT_INPUT_POLICY="DROP"\n'
    assert collector.collect_firewall_facts() == {"ufw_enabled": "true", "default_incoming_policy": "drop"}


def test_firewall_status_output_wins_over_files(host):
    host["files"]["/etc/ufw/ufw.conf"] = "ENABLED=yes\n"
    host["commands"][("ufw", "status", "verbose")] = "Status: inactive\nDefault: allow (incoming), allow (outgoing)\n"
    assert collector.collect_firewall_facts() == {"ufw_enabled": "false", "default_incoming_policy": "allow"}


def test_firewall_unknown_without_any_source(host):
    assert collector.collect_firewall_facts() == {}
    host["files"]["/etc/ufw/ufw.conf"] = "# пусто\n"
    assert collector.collect_firewall_facts() == {}


# ---------- обновления, пароли, ядро ----------

@pytest.mark.parametrize(("content", "expected"), [
    ('APT::Periodic::Unattended-Upgrade "1";\n', {"unattended_upgrades_enabled": "true"}),
    ('APT::Periodic::Unattended-Upgrade "0";\n', {"unattended_upgrades_enabled": "false"}),
    ('APT::Periodic::Update-Package-Lists "1";\n', {}),
    (None, {}),
])
def test_unattended_upgrades(host, content, expected):
    if content is not None:
        host["files"]["/etc/apt/apt.conf.d/20auto-upgrades"] = content
    assert collector.collect_updates_facts() == expected


def test_password_policy_values_and_lockout_variants(host):
    host["files"]["/etc/login.defs"] = "# PASS_MAX_DAYS 1\nPASS_MAX_DAYS\t90\n"
    host["files"]["/etc/security/pwquality.conf"] = "# minlen = 1\nminlen = 14\n"
    host["files"]["/etc/pam.d/common-auth"] = "auth required pam_unix.so\n"
    assert collector.collect_password_policy_facts() == {"pass_max_days": "90", "pass_min_len": "14", "lockout_on_failure": "false"}

    host["files"]["/etc/pam.d/common-auth"] = "auth required pam_tally2.so deny=5\n"
    assert collector.collect_password_policy_facts()["lockout_on_failure"] == "true"
    host["files"]["/etc/pam.d/common-auth"] = "auth required pam_unix.so\n"
    host["files"]["/etc/security/faillock.conf"] = "deny = 5\n"
    assert collector.collect_password_policy_facts()["lockout_on_failure"] == "true"


def test_password_policy_without_pam_does_not_guess_lockout(host):
    host["files"]["/etc/security/faillock.conf"] = "deny = 5\n"
    assert "lockout_on_failure" not in collector.collect_password_policy_facts()


def test_kernel_ip_forward(host):
    assert collector.collect_kernel_facts() == {}
    host["files"]["/proc/sys/net/ipv4/ip_forward"] = "1\n"
    assert collector.collect_kernel_facts() == {"ip_forward": "1"}


# ---------- Docker ----------

def test_docker_not_available_no_containers_and_privileged(host):
    assert collector.collect_docker_facts() == {}  # docker не установлен или нет прав
    host["commands"][("docker", "ps", "-q")] = "\n"
    assert collector.collect_docker_facts() == {"no_privileged_containers": "true"}

    host["commands"][("docker", "ps", "-q")] = "aaa\nbbb\n"
    inspect = ("docker", "inspect", "--format", "{{.HostConfig.Privileged}}", "aaa", "bbb")
    assert collector.collect_docker_facts() == {}  # inspect не выполнился — не «нарушений нет»
    host["commands"][inspect] = "false\nfalse\n"
    assert collector.collect_docker_facts() == {"no_privileged_containers": "true"}
    host["commands"][inspect] = "false\ntrue\n"
    assert collector.collect_docker_facts() == {"no_privileged_containers": "false"}


# ---------- ПО, ОС, адрес ----------

DPKG = ("dpkg-query", "-W", "-f=${Package}\t${Version}\t${Source}\n")
RPM = ("rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n")


def test_software_from_dpkg_skips_broken_lines(host):
    host["commands"][DPKG] = "openssh-server\t1:9.6p1-3ubuntu13\topenssh\nbash\t\t\n\t1.0\t\nbroken-line\n"
    assert collector.collect_software() == [
        {"name": "openssh-server", "version": "1:9.6p1-3ubuntu13", "vendor": None, "category": "os-package", "type": "package"},
        {"name": "bash", "version": None, "vendor": None, "category": "os-package", "type": "package"},
    ]


def test_software_falls_back_to_rpm_then_empty(host):
    host["commands"][RPM] = "openssh-server\t8.7p1-38.el9\n\nkernel\t5.14.0-427.el9\n"
    assert [(i["name"], i["version"]) for i in collector.collect_software()] == [
        ("openssh-server", "8.7p1-38.el9"), ("kernel", "5.14.0-427.el9"),
    ]
    del host["commands"][RPM]
    assert collector.collect_software() == []


def test_os_pretty_name(host):
    assert collector.get_os_pretty_name() is None
    host["files"]["/etc/os-release"] = 'NAME="Ubuntu"\nPRETTY_NAME="Ubuntu 24.04.1 LTS"\n'
    assert collector.get_os_pretty_name() == "Ubuntu 24.04.1 LTS"
    host["files"]["/etc/os-release"] = "PRETTY_NAME=Astra Linux\n"  # без кавычек
    assert collector.get_os_pretty_name() == "Astra Linux"
    host["files"]["/etc/os-release"] = "NAME=x\n"
    assert collector.get_os_pretty_name() is None


def test_primary_ip_without_network_is_none(monkeypatch):
    class NoNetwork:
        def __init__(self, *args):
            raise OSError("сеть недоступна")
    monkeypatch.setattr(collector.socket, "socket", NoNetwork)
    assert collector.get_primary_ip() is None


def test_collect_facts_keeps_only_found_categories_and_payload_fields(host, monkeypatch):
    host["files"]["/proc/sys/net/ipv4/ip_forward"] = "0\n"
    host["files"]["/etc/ssh/sshd_config"] = "PermitRootLogin no\n"
    assert set(collector.collect_facts()) == {"kernel", "ssh"}

    monkeypatch.setattr(collector, "get_primary_ip", lambda: "10.0.0.5")
    host["files"]["/etc/os-release"] = 'PRETTY_NAME="Debian GNU/Linux 12"\n'
    args = collector.parse_args(["--api-url", "https://s", "--environment", "prod", "--hostname", "web-01",
                                 "--criticality", "high", "--scan-label", "до харденинга"])
    payload = collector.build_payload(args)
    assert payload["environment"] == "prod" and payload["scan_label"] == "до харденинга"
    assert payload["asset"] == {"hostname": "web-01", "ip_address": "10.0.0.5", "os": "Debian GNU/Linux 12",
                                "asset_type": "server", "criticality": "high"}
    assert payload["facts"]["ssh"]["permit_root_login"] == "no"


# ---------- запуск без сервера ----------

def _signed(manifest, key="pack-key"):
    return hmac.new(key.encode(), probes.canonical_json(manifest), hashlib.sha256).hexdigest()


@pytest.fixture
def pack_files(tmp_path):
    """Пак распознаёт «хост» по файлу в tmp_path и проверяет в нём параметр; манифест подписан HMAC."""
    release = tmp_path / "release"
    release.write_text("ID=e2e-os\nHARDENED=yes\n", encoding="utf-8")
    manifest = {
        "schema": 1, "pack": "e2e-pack", "version": "1.0.0", "maturity": "draft", "tags": ["e2e-os"],
        "transport": "local", "asset_type": "linux-server",
        "detect": [{"probe": {"type": "file_kv", "path": str(release), "key": "ID", "separator": "equals"}, "equals": "e2e-os"}],
        "checks": [{"id": "e2e.hardened", "probe": {"type": "file_kv", "path": str(release), "key": "HARDENED", "separator": "equals"}}],
    }
    path = tmp_path / "manifests.json"
    path.write_text(json.dumps({"manifests": [{"manifest": manifest, "signature": _signed(manifest)}]}), encoding="utf-8")
    return {"manifest": manifest, "path": path, "release": release, "dir": tmp_path}


def _pack_args(pack_files, *extra):
    return ["--api-url", "https://audit.example.ru", "--environment", "prod", "--hostname", "web-01",
            "--use-packs", "--pack-key", "pack-key", "--manifests-file", str(pack_files["path"]), *extra]


def test_dry_run_with_manifests_file_needs_no_server(pack_files, capsys):
    assert collector.main(_pack_args(pack_files, "--dry-run")) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["packs"] == [{"id": "e2e-pack", "version": "1.0.0",
                                 "probe_results": {"e2e.hardened": {"found": True, "value": "yes", "evidence": "HARDENED=yes"}}}]
    assert payload["platform_tags"] == ["e2e-os"] and payload["asset"]["asset_type"] == "linux-server"
    assert payload["run_id"] and payload["collected_at"].endswith("+00:00")


def test_out_writes_private_report_signed_with_site_key(pack_files, capsys):
    out = pack_files["dir"] / "report.json"
    assert collector.main(_pack_args(pack_files, "--out", str(out), "--api-key", "site-key", "--state-dir", str(pack_files["dir"] / "state"))) == 0
    assert "Отчёт сохранён" in capsys.readouterr().out
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["format"] == "hardening-agent-report" and report["version"] == 1
    assert report == collector.sign_report(report["payload"], "site-key")
    if sys.platform != "win32":
        assert out.stat().st_mode & 0o777 == 0o600


def test_legacy_dry_run_prints_payload(host, capsys, monkeypatch):
    monkeypatch.setattr(collector, "get_primary_ip", lambda: None)
    host["files"]["/etc/ssh/sshd_config"] = "PermitRootLogin yes\n"
    assert collector.main(["--api-url", "https://s", "--environment", "prod", "--hostname", "h", "--dry-run"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["facts"]["ssh"]["permit_root_login"] == "yes" and "packs" not in payload


@pytest.mark.parametrize(("change", "message"), [
    (lambda m: m["checks"][0].update(id="подменено"), "Ошибка безопасности"),
    (lambda m: m["detect"][0].update(equals="other-os"), "Платформа не распознана ни одним паком"),
])
def test_pack_mode_refuses_tampered_or_foreign(pack_files, change, message):
    data = json.loads(pack_files["path"].read_text(encoding="utf-8"))
    manifest = copy.deepcopy(data["manifests"][0]["manifest"])
    change(manifest)
    signature = data["manifests"][0]["signature"] if message == "Ошибка безопасности" else _signed(manifest)
    pack_files["path"].write_text(json.dumps({"manifests": [{"manifest": manifest, "signature": signature}]}), encoding="utf-8")
    with pytest.raises(SystemExit, match=message):
        collector.main(_pack_args(pack_files, "--dry-run"))


def test_pack_filter_and_wrong_pack_key(pack_files):
    with pytest.raises(SystemExit, match="Платформа не распознана"):
        collector.main(_pack_args(pack_files, "--dry-run", "--pack", "другой-пак"))
    args = _pack_args(pack_files, "--dry-run")
    args[args.index("pack-key")] = "чужой-ключ"
    with pytest.raises(SystemExit, match="Ошибка безопасности"):
        collector.main(args)


@pytest.mark.parametrize(("extra", "message"), [
    (["--offline-dir", "/tmp", "--ssh-host", "10.0.0.1"], "взаимоисключающие"),
])
def test_offline_dir_conflicts(pack_files, extra, message):
    with pytest.raises(SystemExit, match=message):
        collector.main(_pack_args(pack_files, "--dry-run", *extra))


def test_offline_dir_needs_hostname(pack_files):
    args = ["--api-url", "https://s", "--environment", "prod", "--use-packs", "--pack-key", "pack-key",
            "--manifests-file", str(pack_files["path"]), "--dry-run", "--offline-dir", str(pack_files["dir"])]
    with pytest.raises(SystemExit, match="нужен --hostname"):
        collector.main(args)


def test_pack_mode_without_signing_key_is_refused(pack_files):
    args = [a for a in _pack_args(pack_files, "--dry-run") if a not in ("--pack-key", "pack-key")]
    with pytest.raises(SystemExit, match="открытый ключ подписи паков"):
        collector.main(args)


def test_without_any_key_a_real_run_explains_what_is_needed(tmp_path, capsys):
    code = collector.main(["--api-url", "https://audit.example.ru", "--environment", "prod", "--state-dir", str(tmp_path)])
    assert code == 1 and "нужен ключ площадки --api-key" in capsys.readouterr().err


def test_windows_requires_packs(monkeypatch, capsys):
    monkeypatch.setattr(collector, "_utf8_console", lambda: None)
    monkeypatch.setattr(collector.os, "name", "nt")
    code = collector.main(["--api-url", "https://s", "--environment", "prod", "--dry-run"])
    assert code == 1 and "только с паками" in capsys.readouterr().err
