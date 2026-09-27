import copy
import os

import pytest

import probes
from probes import (
    CmdOutput,
    LocalTransport,
    ManifestError,
    ProbeError,
    SshTransport,
    is_readonly_cli,
    load_verified_manifests,
    matches_detect,
    redact,
    run_manifest,
    run_probe,
    select_manifests,
    verify_manifest,
)

SSHD_CONFIG = """\
# sshd
Port 22
PermitRootLogin prohibit-password
permitrootlogin yes
MaxAuthTries 3
PasswordAuthentication no

Match User backup
    PermitRootLogin yes
    MaxAuthTries 10
"""

CISCO_CONFIG = """\
hostname sw-core-01
enable secret 5 $1$abcd$hashedvalue
snmp-server community public RO
ip http server
!
line vty 0 4
 transport input ssh
 access-class 10 in
line vty 5 15
 transport input telnet
"""


class FakeTransport:
    """Транспорт с заранее заданными ответами: пробы проверяются без реальных команд."""

    def __init__(self, name="local", outputs=None, cli=""):
        self.name, self.outputs, self.cli, self.calls = name, outputs or {}, cli, []

    def run(self, argv):
        self.calls.append(argv)
        return CmdOutput(self.outputs.get(" ".join(argv), ""), "", 0)

    def run_cli(self, command):
        self.calls.append(command)
        return CmdOutput(self.cli, "", 0)


def write(tmp_path, name, content):
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return str(path)


# ---------- file_kv ----------

def test_file_kv_first_match_wins_and_is_case_insensitive(tmp_path):
    path = write(tmp_path, "sshd_config", SSHD_CONFIG)
    result = run_probe(LocalTransport(), {"type": "file_kv", "path": path, "key": "PermitRootLogin"})
    assert result["found"] and result["value"] == "prohibit-password"
    assert result["evidence"] == "PermitRootLogin prohibit-password"


def test_file_kv_ignores_match_blocks(tmp_path):
    # MaxAuthTries 10 внутри Match — не глобальное значение; глобальное 3.
    path = write(tmp_path, "sshd_config", SSHD_CONFIG)
    assert run_probe(LocalTransport(), {"type": "file_kv", "path": path, "key": "MaxAuthTries"})["value"] == "3"


def test_file_kv_uses_default_when_key_absent(tmp_path):
    path = write(tmp_path, "sshd_config", SSHD_CONFIG)
    probe = {"type": "file_kv", "path": path, "key": "X11Forwarding", "default": "no"}
    result = run_probe(LocalTransport(), probe)
    assert result["value"] == "no" and result["evidence"] == "(значение по умолчанию)"


def test_file_kv_absent_key_without_default_is_none_not_error(tmp_path):
    path = write(tmp_path, "sshd_config", SSHD_CONFIG)
    result = run_probe(LocalTransport(), {"type": "file_kv", "path": path, "key": "Nope"})
    assert result["found"] and result["value"] is None


def test_file_kv_equals_separator_strips_quotes_and_supports_last_match(tmp_path):
    path = write(tmp_path, "os-release", 'NAME="Ubuntu"\nID=ubuntu\nID="debian"\n')
    probe = {"type": "file_kv", "path": path, "key": "ID", "separator": "equals"}
    assert run_probe(LocalTransport(), probe)["value"] == "ubuntu"
    assert run_probe(LocalTransport(), {**probe, "match": "last"})["value"] == "debian"


def test_missing_file_is_probe_failure_not_exception(tmp_path):
    result = run_probe(LocalTransport(), {"type": "file_kv", "path": str(tmp_path / "nope"), "key": "a"})
    assert result["found"] is False and "не удалось прочитать" in result["error"]


# ---------- file_regex / file_stat ----------

def test_file_regex_returns_group_or_none(tmp_path):
    path = write(tmp_path, "auto-upgrades", 'APT::Periodic::Unattended-Upgrade "1";\n')
    probe = {"type": "file_regex", "path": path, "pattern": r'Unattended-Upgrade\s+"(\d)"'}
    assert run_probe(LocalTransport(), probe)["value"] == "1"
    assert run_probe(LocalTransport(), {**probe, "pattern": "nomatch"})["value"] is None


def test_file_stat_reports_mode_without_reading_content(tmp_path):
    path = write(tmp_path, "secret", "x")
    os.chmod(path, 0o640)
    assert run_probe(LocalTransport(), {"type": "file_stat", "path": path, "field": "mode"})["value"] == "640"
    assert run_probe(LocalTransport(), {"type": "file_stat", "path": path, "field": "uid"})["value"] == os.stat(path).st_uid


def test_file_stat_is_allowed_on_shadow_even_though_reading_is_not():
    # Права /etc/shadow проверять можно (нужно для аудита), содержимое — нет.
    if not os.path.exists("/etc/shadow"):
        pytest.skip("нет /etc/shadow")
    assert run_probe(LocalTransport(), {"type": "file_stat", "path": "/etc/shadow"})["found"] is True


# ---------- запреты на чтение секретов ----------

@pytest.mark.parametrize("path", [
    "/etc/shadow", "/etc/gshadow", "/etc/ssh/ssh_host_rsa_key", "/root/.ssh/id_rsa",
    "/home/alice/.ssh/authorized_keys", "/srv/app/tls/server.key", "/etc/ssl/private/cert.pem",
])
def test_secret_paths_are_never_read(path):
    result = run_probe(LocalTransport(), {"type": "file_kv", "path": path, "key": "x"})
    assert result["found"] is False and "запрещено" in result["error"]


def test_symlink_to_secret_does_not_bypass_the_denylist(tmp_path):
    link = tmp_path / "innocent.conf"
    link.symlink_to("/etc/shadow")
    result = run_probe(LocalTransport(), {"type": "file_regex", "path": str(link), "pattern": "root"})
    assert result["found"] is False and "запрещено" in result["error"]


# ---------- команды ----------

@pytest.mark.parametrize("argv", [
    ["rm", "-rf", "/"],
    ["sh", "-c", "id"],
    ["systemctl", "stop", "ssh"],
    ["systemctl", "is-active", "ssh; reboot"],
    ["ufw", "disable"],
    ["sysctl", "-w", "net.ipv4.ip_forward=1"],
    ["docker", "run", "alpine"],
    ["dpkg-query", "-W", "-f=x", "a b"],
])
def test_commands_outside_allowlist_are_refused(argv):
    with pytest.raises(ProbeError, match="вне белого списка"):
        LocalTransport().run(argv)


def test_allowed_command_runs_without_shell_and_with_safe_path(monkeypatch):
    captured = {}

    def fake_run(argv, **kwargs):
        captured.update(argv=argv, kwargs=kwargs)
        return type("P", (), {"stdout": "active\n", "stderr": "", "returncode": 0})()

    monkeypatch.setattr(probes.shutil, "which", lambda name, path=None: f"/usr/bin/{name}")
    monkeypatch.setattr(probes.subprocess, "run", fake_run)

    out = LocalTransport().run(["systemctl", "is-active", "ssh"])

    assert out.stdout == "active\n"
    assert captured["argv"] == ["/usr/bin/systemctl", "is-active", "ssh"]
    assert not captured["kwargs"].get("shell")
    assert captured["kwargs"]["env"]["PATH"] == probes.SAFE_PATH


def test_missing_executable_is_probe_failure(monkeypatch):
    monkeypatch.setattr(probes.shutil, "which", lambda name, path=None: None)
    result = run_probe(LocalTransport(), {"type": "service_state", "service": "ssh"})
    assert result["found"] is False and "не найдена" in result["error"]


def test_cli_config_is_not_available_locally():
    result = run_probe(LocalTransport(), {"type": "cli_config", "cmd": "show version", "match": "x"})
    assert result["found"] is False


def test_unknown_probe_type_is_refused():
    result = run_probe(LocalTransport(), {"type": "shell", "cmd": "id"})
    assert result["found"] is False and "не поддерживается" in result["error"]


# ---------- cmd_regex / service_state / pkg_version ----------

def test_cmd_regex_and_service_state_via_transport():
    t = FakeTransport(outputs={"getenforce": "Enforcing\n", "systemctl is-active auditd": "inactive\n",
                               "systemctl is-enabled auditd": "enabled\n"})
    assert run_probe(t, {"type": "cmd_regex", "cmd": ["getenforce"], "pattern": "(Enforcing|Permissive)"})["value"] == "Enforcing"
    assert run_probe(t, {"type": "service_state", "service": "auditd"})["value"] == "inactive"
    assert run_probe(t, {"type": "service_state", "service": "auditd", "field": "enabled"})["value"] == "enabled"


def test_pkg_version_dpkg_installed_and_not_installed(monkeypatch):
    monkeypatch.setattr(probes.shutil, "which", lambda name, path=None: "/usr/bin/dpkg-query")
    installed = FakeTransport(outputs={"dpkg-query -W -f=${Status}|${Version} openssh-server": "install ok installed|1:9.6p1\n"})
    removed = FakeTransport(outputs={"dpkg-query -W -f=${Status}|${Version} openssh-server": "deinstall ok config-files|1:9.6p1\n"})
    probe = {"type": "pkg_version", "package": "openssh-server"}
    assert run_probe(installed, probe)["value"] == "1:9.6p1"
    assert run_probe(removed, probe)["value"] is None


def test_pkg_version_rpm_fallback(monkeypatch):
    monkeypatch.setattr(probes.shutil, "which", lambda name, path=None: None)
    t = FakeTransport(outputs={"rpm -q --qf %{VERSION}-%{RELEASE} openssh": "8.7p1-38.el9",
                               "rpm -q --qf %{VERSION}-%{RELEASE} nginx": "package nginx is not installed"})
    assert run_probe(t, {"type": "pkg_version", "package": "openssh"})["value"] == "8.7p1-38.el9"
    assert run_probe(t, {"type": "pkg_version", "package": "nginx"})["value"] is None


# ---------- cli_config и маскирование ----------

def test_cli_config_line_and_section():
    t = FakeTransport("ssh", cli=CISCO_CONFIG)
    http = {"type": "cli_config", "cmd": "show running-config", "match": "^ip http server"}
    assert run_probe(t, http)["value"] == "ip http server"
    assert run_probe(t, {**http, "match": "^ip https? secure-server"})["value"] is None

    vty = {"type": "cli_config", "cmd": "show running-config", "section": r"^line vty 0 4", "match": r"transport input (\w+)"}
    assert run_probe(t, vty)["value"] == "ssh"  # первый vty-блок, а не второй с telnet


def test_evidence_masks_secrets_but_keeps_context():
    t = FakeTransport("ssh", cli=CISCO_CONFIG)
    for pattern, expected in (("^enable secret", "enable secret ***"), ("^snmp-server community", "snmp-server community ***")):
        result = run_probe(t, {"type": "cli_config", "cmd": "show running-config", "match": pattern})
        assert result["evidence"] == expected
        assert "$1$" not in result["evidence"] and "public" not in result["evidence"]


def test_redact_does_not_mangle_harmless_directives():
    assert redact("PasswordAuthentication no") == "PasswordAuthentication no"
    assert redact("PermitRootLogin prohibit-password") == "PermitRootLogin prohibit-password"
    assert redact("service password-encryption") == "service password-encryption"
    assert redact("Enable  PASSWORD 7 0822455D0A16") == "Enable  PASSWORD ***"
    assert redact("enable password 7 0822455D0A16") == "enable password ***"
    assert redact("radius-server key MySecret") == "radius-server key MySecret"  # 'key' отдельно не маскируется
    assert redact("x" * 500) == "x" * 300


@pytest.mark.parametrize("command, allowed", [
    ("show running-config", True),
    ("show running-config | include ^ip http", True),
    ("show running-config | section line vty", True),
    ("display current-configuration", True),
    ("/export", True),
    ("/ip service print", True),
    ("show version | include Cisco | count", True),
    ("reload", False),
    ("configure terminal", False),
    ("show version; reload", False),
    ("show version && reboot", False),
    ("show version | sh", False),
    ("show version | tee /tmp/x", False),
    ("show $(id)", False),
    ("show x\nreload", False),
    ("/system reboot", False),
    ("/user add name=x", False),
    ("show " + "a" * 300, False),
])
def test_is_readonly_cli(command, allowed):
    assert is_readonly_cli(command) is allowed


# ---------- SSH ----------

class RecordingRunner:
    def __init__(self, stdout="", code=0, stderr=""):
        self.calls, self._result = [], (stdout, code, stderr)

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        stdout, code, stderr = self._result
        return type("P", (), {"stdout": stdout, "stderr": stderr, "returncode": code})()


def test_ssh_command_line_is_strict_and_uses_no_shell():
    runner = RecordingRunner(stdout="cfg")
    t = SshTransport("10.0.0.1", "audit", 2222, "/keys/audit", runner=runner)

    out = t.run_cli("show running-config")

    argv, kwargs = runner.calls[0]
    assert out.stdout == "cfg"
    assert argv[:1] == ["ssh"] and "StrictHostKeyChecking=yes" in argv and "BatchMode=yes" in argv
    assert argv[-3:] == ["--", "audit@10.0.0.1", "show running-config"]
    assert ["-p", "2222"] == argv[argv.index("-p"):argv.index("-p") + 2] and "/keys/audit" in argv
    assert not kwargs.get("shell")


def test_ssh_refuses_modifying_command_before_connecting():
    runner = RecordingRunner()
    t = SshTransport("10.0.0.1", "audit", runner=runner)
    with pytest.raises(ProbeError, match="только команды на чтение"):
        t.run_cli("reload")
    assert runner.calls == []


@pytest.mark.parametrize("host, user", [("-oProxyCommand=id", "u"), ("host;id", "u"), ("host", "-oX=y"), ("host", "a b")])
def test_ssh_rejects_option_injection_in_host_or_user(host, user):
    with pytest.raises(ValueError):
        SshTransport(host, user)


def test_ssh_connection_failure_becomes_probe_failure():
    t = SshTransport("10.0.0.1", "audit", runner=RecordingRunner(code=255, stderr="Host key verification failed."))
    result = run_probe(t, {"type": "cli_config", "cmd": "show version", "match": "x"})
    assert result["found"] is False and "Host key verification failed" in result["error"]


def test_ssh_transport_has_no_file_access():
    result = run_probe(SshTransport("10.0.0.1"), {"type": "file_kv", "path": "/etc/passwd", "key": "root"})
    assert result["found"] is False


def test_cmd_regex_over_ssh_is_joined_and_checked():
    runner = RecordingRunner(stdout="Cisco IOS Software, Version 15.2")
    t = SshTransport("10.0.0.1", "audit", runner=runner)
    assert run_probe(t, {"type": "cmd_regex", "cmd": ["show", "version"], "pattern": "Cisco IOS"})["value"] == "Cisco IOS"
    assert run_probe(t, {"type": "cmd_regex", "cmd": ["reload"], "pattern": "x"})["found"] is False


# ---------- подпись манифеста ----------

def signed(manifest, key="k"):
    import hashlib
    import hmac
    return hmac.new(key.encode(), probes.canonical_json(manifest), hashlib.sha256).hexdigest()


MANIFEST = {
    "schema": 1, "pack": "ubuntu-test", "version": "1.0.0", "maturity": "baseline", "tags": ["ubuntu"],
    "transport": "local", "asset_type": None,
    "detect": [{"probe": {"type": "file_kv", "path": "/tmp/x", "key": "ID", "separator": "equals"}, "equals": "ubuntu"}],
    "checks": [{"id": "a.b", "probe": {"type": "file_kv", "path": "/tmp/x", "key": "ID", "separator": "equals"}}],
}


def test_valid_signature_is_accepted():
    response = {"manifests": [{"manifest": MANIFEST, "signature": signed(MANIFEST)}]}
    assert load_verified_manifests(response, "k") == [MANIFEST]


def test_tampered_manifest_stops_everything():
    tampered = copy.deepcopy(MANIFEST)
    tampered["checks"][0]["probe"]["path"] = "/etc/shadow"
    response = {"manifests": [{"manifest": tampered, "signature": signed(MANIFEST)}]}
    with pytest.raises(ManifestError, match="Подпись"):
        load_verified_manifests(response, "k")


def test_wrong_key_and_missing_signature_are_rejected():
    with pytest.raises(ManifestError):
        load_verified_manifests({"manifests": [{"manifest": MANIFEST, "signature": signed(MANIFEST, "other")}]}, "k")
    with pytest.raises(ManifestError):
        load_verified_manifests({"manifests": [{"manifest": MANIFEST}]}, "k")
    assert verify_manifest(MANIFEST, "", "k") is False


def test_unsupported_schema_version_is_rejected():
    future = {**MANIFEST, "schema": 2}
    with pytest.raises(ManifestError, match="схема"):
        load_verified_manifests({"manifests": [{"manifest": future, "signature": signed(future)}]}, "k")


# ---------- detect и выполнение ----------

def test_detect_requires_all_conditions_and_selects_by_transport(tmp_path):
    path = write(tmp_path, "os-release", "ID=ubuntu\n")
    manifest = copy.deepcopy(MANIFEST)
    manifest["detect"][0]["probe"]["path"] = path
    local = LocalTransport()

    assert matches_detect(local, manifest["detect"])
    assert select_manifests(local, [manifest]) == [manifest]
    assert select_manifests(FakeTransport("ssh"), [manifest]) == []  # пак local не подходит ssh-транспорту

    manifest["detect"][0]["equals"] = "astra"
    assert not matches_detect(local, manifest["detect"])
    manifest["detect"] = [{"probe": manifest["detect"][0]["probe"], "regex": "^ub"}]
    assert matches_detect(local, manifest["detect"])


def test_detect_fails_when_probe_cannot_run(tmp_path):
    manifest = copy.deepcopy(MANIFEST)
    manifest["detect"][0]["probe"]["path"] = str(tmp_path / "missing")
    assert not matches_detect(LocalTransport(), manifest["detect"])


def test_run_manifest_logs_every_probe(tmp_path):
    path = write(tmp_path, "os-release", "ID=ubuntu\n")
    manifest = copy.deepcopy(MANIFEST)
    manifest["checks"][0]["probe"]["path"] = path
    log = []

    results = run_manifest(LocalTransport(), manifest, log=log.append)

    assert results["a.b"]["value"] == "ubuntu"
    assert log[0]["check"] == "a.b" and log[0]["probe"] == "file_kv" and log[0]["found"] is True


# ---------- file_kv: follow_include ----------

def make_ssh_tree(tmp_path, main, dropins=None):
    (tmp_path / "sshd_config.d").mkdir()
    for name, content in (dropins or {}).items():
        (tmp_path / "sshd_config.d" / name).write_text(content, encoding="utf-8")
    return write(tmp_path, "sshd_config", main)


def kv(path, key, **extra):
    return {"type": "file_kv", "path": path, "key": key, "follow_include": True, **extra}


def test_include_is_off_by_default(tmp_path):
    path = make_ssh_tree(tmp_path, "Include sshd_config.d/*.conf\n", {"a.conf": "PermitRootLogin no\n"})
    plain = {"type": "file_kv", "path": path, "key": "PermitRootLogin"}
    assert run_probe(LocalTransport(), plain)["value"] is None
    assert run_probe(LocalTransport(), kv(path, "PermitRootLogin"))["value"] == "no"


def test_include_first_match_wins_across_files_in_lexical_order(tmp_path):
    path = make_ssh_tree(
        tmp_path, "Include sshd_config.d/*.conf\nPermitRootLogin yes\n",
        {"60-cloud.conf": "PermitRootLogin prohibit-password\n", "50-hardening.conf": "PermitRootLogin no\n"},
    )
    result = run_probe(LocalTransport(), kv(path, "PermitRootLogin"))
    assert result["value"] == "no" and result["evidence"] == "PermitRootLogin no"  # 50-* раньше 60-*, и оба раньше основного файла


def test_directive_after_include_is_used_when_dropins_are_silent(tmp_path):
    path = make_ssh_tree(tmp_path, "Include sshd_config.d/*.conf\nMaxAuthTries 3\n", {"a.conf": "X11Forwarding no\n"})
    assert run_probe(LocalTransport(), kv(path, "MaxAuthTries"))["value"] == "3"


def test_match_block_ends_with_its_file_and_does_not_leak_into_the_next_dropin(tmp_path):
    # sshd: Match действует до конца файла; следующий включаемый файл снова глобальный
    path = make_ssh_tree(
        tmp_path, "Include sshd_config.d/*.conf\n",
        {"10-a.conf": "Match User backup\n    PermitRootLogin yes\n", "20-b.conf": "PermitRootLogin no\n"},
    )
    assert run_probe(LocalTransport(), kv(path, "PermitRootLogin"))["value"] == "no"


def test_absolute_include_path_and_missing_glob_are_handled(tmp_path):
    other = tmp_path / "extra"
    other.mkdir()
    (other / "x.conf").write_text("PasswordAuthentication no\n", encoding="utf-8")
    path = write(tmp_path, "sshd_config", f"Include {other}/*.conf\nInclude /nonexistent/*.conf\n")
    assert run_probe(LocalTransport(), kv(path, "PasswordAuthentication"))["value"] == "no"


def test_self_including_file_terminates(tmp_path):
    path = tmp_path / "sshd_config"
    path.write_text(f"Include {path}\nMaxAuthTries 3\n", encoding="utf-8")
    result = run_probe(LocalTransport(), kv(str(path), "MaxAuthTries"))
    assert result["found"] and result["value"] == "3"


def test_include_cannot_pull_in_denied_files(tmp_path):
    link = tmp_path / "sneaky.conf"
    link.symlink_to("/etc/shadow")
    path = write(tmp_path, "sshd_config", f"Include {tmp_path}/sneaky.conf\nMaxAuthTries 3\n")
    result = run_probe(LocalTransport(), kv(path, "root"))
    assert result["found"] and result["value"] is None  # запрещённый файл молча пропущен, не прочитан


def test_unreadable_include_does_not_cancel_the_rest(tmp_path):
    path = make_ssh_tree(tmp_path, "Include sshd_config.d/*.conf\nMaxAuthTries 3\n", {"a.conf": "X\n"})
    (tmp_path / "sshd_config.d" / "a.conf").chmod(0)
    try:
        assert run_probe(LocalTransport(), kv(path, "MaxAuthTries"))["value"] == "3"
    finally:
        (tmp_path / "sshd_config.d" / "a.conf").chmod(0o644)


# ---------- first_of ----------

def first_of(*subs):
    return {"type": "first_of", "probes": list(subs)}


def test_first_of_takes_the_first_source_that_has_a_value(tmp_path):
    a = write(tmp_path, "a.conf", "OTHER=1\n")
    b = write(tmp_path, "b.conf", "ENABLED=yes\n")
    probe = first_of({"type": "file_kv", "path": a, "key": "ENABLED", "separator": "equals"},
                     {"type": "file_kv", "path": b, "key": "ENABLED", "separator": "equals"})
    result = run_probe(LocalTransport(), probe)
    assert result["value"] == "yes" and result["evidence"] == "ENABLED=yes"


def test_first_of_prefers_the_earlier_source_and_skips_unavailable_ones(tmp_path):
    a = write(tmp_path, "a.conf", "ENABLED=no\n")
    b = write(tmp_path, "b.conf", "ENABLED=yes\n")
    missing = str(tmp_path / "missing")
    kvp = lambda path: {"type": "file_kv", "path": path, "key": "ENABLED", "separator": "equals"}  # noqa: E731
    assert run_probe(LocalTransport(), first_of(kvp(a), kvp(b)))["value"] == "no"
    assert run_probe(LocalTransport(), first_of(kvp(missing), kvp(b)))["value"] == "yes"


def test_first_of_distinguishes_nothing_found_from_nothing_readable(tmp_path):
    a = write(tmp_path, "a.conf", "OTHER=1\n")
    kvp = lambda path: {"type": "file_kv", "path": path, "key": "ENABLED", "separator": "equals"}  # noqa: E731
    readable_empty = run_probe(LocalTransport(), first_of(kvp(a), kvp(a)))
    assert readable_empty["found"] is True and readable_empty["value"] is None
    unreadable = run_probe(LocalTransport(), first_of(kvp(str(tmp_path / "x")), kvp(str(tmp_path / "y"))))
    assert unreadable["found"] is False and "не удалось прочитать" in unreadable["error"]


def test_first_of_with_command_then_file_like_ufw(tmp_path):
    conf = write(tmp_path, "ufw.conf", "ENABLED=yes\n")
    t = FakeTransport(outputs={"ufw status verbose": "ERROR: need root"})
    t.read_file = LocalTransport().read_file
    t.glob = LocalTransport().glob
    probe = first_of({"type": "cmd_regex", "cmd": ["ufw", "status", "verbose"], "pattern": "(?i)Status:\\s*(active|inactive)"},
                     {"type": "file_kv", "path": conf, "key": "ENABLED", "separator": "equals"})
    assert run_probe(t, probe)["value"] == "yes"  # status без root ничего не дал — взят файл
    t.outputs["ufw status verbose"] = "Status: active\n"
    assert run_probe(t, probe)["value"] == "active"


def test_first_of_cannot_be_nested():
    inner = first_of({"type": "file_kv", "path": "/etc/a", "key": "k"}, {"type": "file_kv", "path": "/etc/b", "key": "k"})
    result = run_probe(LocalTransport(), first_of(inner, {"type": "file_kv", "path": "/etc/c", "key": "k"}))
    assert result["found"] is False and "first_of" in result["error"]


# ---------- cmd_foreach (docker) ----------

FOREACH = {
    "type": "cmd_foreach", "list_cmd": ["docker", "ps", "-q"],
    "item_cmd": ["docker", "inspect", "--format", "{{.HostConfig.Privileged}}"], "pattern": "^true$",
}


class DockerFake:
    """Транспорт с командами и кодами возврата: docker ps / docker inspect."""

    name = "local"

    def __init__(self, containers=None, list_code=0, inspect_code=0):
        self.containers, self.list_code, self.inspect_code, self.calls = containers or {}, list_code, inspect_code, []

    def run(self, argv):
        self.calls.append(argv)
        if argv[:2] == ["docker", "ps"]:
            return CmdOutput("\n".join(self.containers) + ("\n" if self.containers else ""), "permission denied" if self.list_code else "", self.list_code)
        return CmdOutput(self.containers.get(argv[-1], "false") + "\n", "", self.inspect_code)


def test_foreach_counts_matching_items_and_calls_each_separately():
    t = DockerFake({"aaa111bbb222": "false", "ccc333ddd444": "true", "eee555fff666": "true"})
    result = run_probe(t, FOREACH)
    assert result["value"] == 2 and result["evidence"] == "2 из 3"
    inspect_calls = [c for c in t.calls if c[1] == "inspect"]
    assert len(inspect_calls) == 3 and all(c[-1] in t.containers for c in inspect_calls)  # id — отдельный аргумент


def test_foreach_empty_list_is_zero_not_failure():
    assert run_probe(DockerFake({}), FOREACH)["value"] == 0


def test_foreach_command_failure_is_probe_failure_never_zero():
    # недоступный docker не должен выглядеть как «привилегированных контейнеров нет»
    result = run_probe(DockerFake({"aaa111bbb222": "false"}, list_code=1), FOREACH)
    assert result["found"] is False and "permission denied" in result["error"]
    result = run_probe(DockerFake({"aaa111bbb222": "true"}, inspect_code=1), FOREACH)
    assert result["found"] is False


def test_foreach_respects_max_items():
    t = DockerFake({f"{i:012x}": "false" for i in range(5)})
    result = run_probe(t, {**FOREACH, "max_items": 3})
    assert result["found"] is False and "больше допустимых" in result["error"]


@pytest.mark.parametrize("argv", [
    ["docker", "run", "alpine"], ["docker", "exec", "abc123def456"], ["docker", "rm", "abc123def456"],
    ["docker", "inspect", "--format", "{{.Config.Env}}", "abc123def456"],  # другое поле inspect — секреты окружения
    ["docker", "inspect", "--format", "{{.HostConfig.Privileged}}", "abc; rm -rf /"],
    ["docker", "ps", "-a"],
    # поля 1.1.0 — тоже не любое поле inspect, а именно то, что разрешено (проверка неполного совпадения):
    ["docker", "inspect", "--format", "{{.HostConfig.Env}}", "0123456789ab"],
    ["docker", "inspect", "--format", "{{.Config.Cmd}}", "0123456789ab"],
])
def test_docker_commands_outside_allowlist_are_refused(argv):
    with pytest.raises(ProbeError, match="вне белого списка"):
        LocalTransport().run(argv)


def test_allowed_docker_commands_pass_the_policy(monkeypatch):
    monkeypatch.setattr(probes.shutil, "which", lambda name, path=None: "/usr/bin/docker")
    monkeypatch.setattr(probes.subprocess, "run", lambda argv, **kw: type("P", (), {"stdout": "", "stderr": "", "returncode": 0})())
    LocalTransport().run(["docker", "ps", "-q"])
    LocalTransport().run(["docker", "inspect", "--format", "{{.HostConfig.Privileged}}", "0123456789ab"])
    # поля, добавленные в 1.1.0 (СКО.1.2/1.3/1.5/1.6 методики ФСТЭК) — тоже должны проходить политику
    for field in (
        "HostConfig.Binds", "Config.User", "HostConfig.Memory", "HostConfig.NanoCpus",
        "HostConfig.NetworkMode", "HostConfig.PidMode",
    ):
        LocalTransport().run(["docker", "inspect", "--format", "{{." + field + "}}", "0123456789ab"])



# ---------- service_state: только известные состояния systemctl ----------

class Systemctl:
    name, platform = "local", "posix"

    def __init__(self, stdout, stderr="", code=0):
        self.out = CmdOutput(stdout, stderr, code)

    def run(self, argv):
        assert argv[0] == "systemctl"
        return self.out


@pytest.mark.parametrize(("stdout", "stderr", "code", "expected"), [
    ("active\n", "", 0, "active"),
    ("inactive\n", "", 3, "inactive"),
    ("failed\n", "", 3, "failed"),
    ("", "Unit auditd.service could not be found.\n", 4, "not-found"),
])
def test_service_state_known_states(stdout, stderr, code, expected):
    assert run_probe(Systemctl(stdout, stderr, code), {"type": "service_state", "service": "auditd"})["value"] == expected


@pytest.mark.parametrize("stderr", [
    "System has not been booted with systemd as init system (PID 1). Can't operate.\nFailed to connect to bus: Host is down\n",
    "Failed to connect to bus: No such file or directory\n",
])
def test_service_state_systemctl_failure_is_not_a_value(stderr):
    """Текст ошибки systemctl — не состояние: иначе «Telnet не активен» засчитывался бы как соблюдённый."""
    result = run_probe(Systemctl("", stderr, 1), {"type": "service_state", "service": "telnet.socket"})
    assert result["found"] is False and "не получено" in result["error"]


def test_service_state_enabled_values():
    assert run_probe(Systemctl("disabled\n", "", 1), {"type": "service_state", "service": "x", "field": "enabled"})["value"] == "disabled"
    missing = Systemctl("", "Failed to get unit file state for x.timer: No such file or directory\n", 1)
    assert run_probe(missing, {"type": "service_state", "service": "x.timer", "field": "enabled"})["value"] == "not-found"
