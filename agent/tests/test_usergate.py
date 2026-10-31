"""Три способа доступа к UserGate на лабораторных снимках 7.4.1: разбор, запасной переход, ошибки, маскировка.

Живого устройства здесь нет. Сырые сеансы, exec и ответы XML-RPC лежат в fixtures/usergate
(секреты уже замаскированы; пароль теста — выдуманный).
"""
import json
import os
import subprocess
import sys
import threading
import time
import xmlrpc.client
from pathlib import Path

import pytest

import probes
import usergate

FIX = Path(__file__).resolve().parent / "fixtures" / "usergate"
PASSWORD = "S3cret-Value"
TOKEN = "session-token-xyz"
PIN = "SHOULD-NOT-LEAK-PIN"
METHODS = [
    "v2.core.login", "v2.core.logout", "v2.core.administrator.config.get",
    "v1.netmanager.zones.list", "v1.firewall.rules.list",
]


def _read(name):
    return (FIX / name).read_bytes()


def _json(name):
    return json.loads((FIX / name).read_text(encoding="utf-8"))


def _secret(tmp_path, mode=0o600, text=PASSWORD + "\n"):
    path = tmp_path / "usergate.pass"
    path.write_text(text, encoding="utf-8")
    os.chmod(path, mode)
    return path


def _config(tmp_path, **extra):
    data = {
        "host": "10.77.0.20", "user": "Admin", "hostname": "adlab-ug1",
        "password_file": str(_secret(tmp_path)), "ssh_port": 2200, "xmlrpc_port": 4040,
        "methods": ["xmlrpc", "ssh-exec", "ssh-interactive"],
        "command_timeout": 3, "connect_timeout": 2,
    }
    data.update(extra)
    return data


def _bind(transport):
    transport.bind_manifests([{"xmlrpc_methods": METHODS}])


class _Pipe:
    def __init__(self, data=b""):
        self.buf = data
        self.cv = threading.Condition()
        self.closed = False

    def push(self, data):
        if isinstance(data, str):
            data = data.encode("utf-8")
        with self.cv:
            self.buf += data
            self.cv.notify_all()

    def read(self, n):
        with self.cv:
            while not self.buf and not self.closed:
                self.cv.wait(0.05)
            chunk = self.buf[:n]
            self.buf = self.buf[n:]
            return chunk

    def close(self):
        with self.cv:
            self.closed = True
            self.cv.notify_all()

    def flush(self):
        pass


class ExecProc:
    """stdout отдаёт снимок, только если stdin ещё открыт — как CLI UserGate при раннем EOF."""

    def __init__(self, payload):
        self.payload = payload
        self.events = []
        self.stdin_closed = False
        self.stdout = self
        self.stderr = _Pipe()
        self.stderr.close()
        self.returncode = None
        self._buf = None

    def write(self, data):
        return len(data)

    def flush(self):
        pass

    def close(self):
        self.stdin_closed = True

    @property
    def stdin(self):
        return self

    def read(self, n):
        if self._buf is None:
            self.events.append(("read", self.stdin_closed))
            self._buf = b"" if self.stdin_closed else self.payload
            self.returncode = 255
        chunk = self._buf[:n]
        self._buf = self._buf[n:]
        return chunk

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        return 255

    def kill(self):
        self.returncode = -9


class ScriptedSSH:
    """Интерактивный ssh: на запись отвечает следующим куском снимка сеанса."""

    def __init__(self, steps):
        self.steps = list(steps)
        self.stdout = _Pipe()
        self.stderr = _Pipe()
        self.stderr.close()
        self.writes = []
        self.closed = False
        self.returncode = None
        self._emit(None)

    def _emit(self, text):
        while self.steps and self.steps[0][0] == text:
            self.stdout.push(self.steps.pop(0)[1])

    def write(self, data):
        text = data.decode("utf-8") if isinstance(data, bytes) else data
        self.writes.append(text)
        key = text if text == " " else text.strip()
        self._emit(key)
        return len(data)

    def flush(self):
        pass

    def close(self):
        self.closed = True

    @property
    def stdin(self):
        return self

    def poll(self):
        return None

    def wait(self, timeout=None):
        return 0

    def kill(self):
        self.returncode = -9


class PopenLog:
    def __init__(self, exec_payloads, interactive=None):
        self.exec_payloads = exec_payloads
        self.interactive = interactive
        self.argv = []
        self.envs = []
        self.procs = []

    def __call__(self, argv, stdin=None, stdout=None, stderr=None, env=None):
        self.argv.append(list(argv))
        self.envs.append(dict(env or {}))
        if "-tt" in argv:
            proc = self.interactive
        else:
            proc = ExecProc(self.exec_payloads.get(argv[-1], b""))
        self.procs.append(proc)
        return proc


def _rpc_factory(fail_login=False):
    calls = []

    def call(method, args):
        calls.append((method, tuple(args)))
        if method == "v2.core.login":
            if fail_login:
                raise xmlrpc.client.Fault(1, "login failed for " + PASSWORD)
            return {"auth_token": TOKEN, "version": "7.4.1.341220R", "pin_code": PIN}
        if method == "v2.core.logout":
            return True
        if method == "v2.core.administrator.config.get":
            return _json("xmlrpc/admin_config.json")
        if method == "v1.netmanager.zones.list":
            return _json("xmlrpc/zones.json")
        if method == "v1.firewall.rules.list":
            return _json("xmlrpc/firewall_rules.json")
        raise AssertionError(method)

    return call, calls


# ---------- разбор снимков ----------

def test_interactive_transcript_strips_ansi_pager_and_echo():
    raw = _read("session-h1000.raw")
    text = usergate.clean_terminal(raw.decode("utf-8", "replace"))
    assert "\x1b" not in text and "--more--" not in text and "CPR" not in text
    bodies = {}
    for command, body in usergate.iter_session_commands(text):
        bodies.setdefault(command, body.strip())
    admin = (FIX / "show_settings_administrators_general.txt").read_text(encoding="utf-8").strip()
    untrusted = (FIX / "show_network_zone_Untrusted.txt").read_text(encoding="utf-8").strip()
    assert bodies["show settings administrators general"] == admin
    assert bodies["show network zone Untrusted"] == untrusted
    assert bodies["show system version"] == "UGOS NGFW 7.4.1.341220R"
    # В configure та же команда — ошибка, а не версия.
    failed = [body for command, body in usergate.iter_session_commands(text) if command == "show system version"]
    assert usergate.command_failed(failed[-1])


def test_short_terminal_pager_is_removed_but_text_stays():
    text = usergate.clean_terminal(_read("session-h24.raw").decode("utf-8", "replace"))
    assert "--more--" not in text and "\x1b" not in text
    assert "Any ICMP" in text and "ha" in text and "allowed-addresses" in text


def test_pipe_reader_sees_a_short_prompt_before_the_child_exits():
    """Настоящий Popen: приглашение без перевода строки и без EOF. read(65536) ждал бы 64 КБ."""
    proc = subprocess.Popen(
        [sys.executable, "-c",
         "import sys,time; sys.stdout.buffer.write(b'Admin@lab>'); sys.stdout.buffer.flush(); time.sleep(60)"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    reader = usergate.PipeReader(proc.stdout)
    started = time.monotonic()
    try:
        data, eof = b"", False
        while time.monotonic() - started < 3 and not data and not eof:
            data, eof = reader.read_available(0.2)
        elapsed = time.monotonic() - started
    finally:
        proc.kill()
        proc.wait()
    assert data == b"Admin@lab>" and eof is False and elapsed < 3


def test_exec_capture_needs_open_stdin_and_error_line_is_a_failure():
    admin = (FIX / "show_settings_administrators_general.txt").read_text(encoding="utf-8").strip()
    got = usergate.normalize_exec_output(_read("openssh/J-exec-stdin-open-show_settings_administrators_general.raw")).strip()
    assert got == admin
    err = usergate.normalize_exec_output(_read("openssh/J-exec-stdin-open-show_system_version.raw"))
    assert usergate.command_failed(err) and "Error: show system version" in err
    # Ранний EOF на stdin — пустой вывод, даже если снимок команды у нас есть.
    proc = ExecProc(_read("openssh/J-exec-stdin-open-show_settings_administrators_general.raw"))
    proc.close()
    stdout, _stderr = usergate.read_ssh_stdout(proc, idle=0.2, overall=2)
    assert stdout == b"" and proc.events == [("read", True)]


def test_xmlrpc_render_matches_cli_service_names_and_factory_values():
    zones = _json("xmlrpc/zones.json")
    rendered = usergate.render_zones(zones)
    cli = (FIX / "exec/05.raw").read_text(encoding="utf-8").split("\n", 1)[1]
    import re

    def enabled(text, split_on):
        found = {}
        for block in re.split(split_on, text):
            name = re.search(r"name\s*:\s*(\S.*)", block)
            if not name:
                continue
            services = []
            for part in re.split(r"\n\s*service\s*:", block)[1:]:
                title = re.match(r"\s*(.+)", part)
                flag = re.search(r"enabled\s*:\s*(\S+)", part)
                if title and flag and flag.group(1) == "on":
                    services.append(title.group(1).strip())
            found[name.group(1).strip()] = services
        return found

    assert enabled(rendered, r"\n(?=\S)") == enabled(cli, r"\n(?=[A-Za-z])")
    admin = usergate.render_admin(_json("xmlrpc/admin_config.json"))
    assert "strong-password: off" in admin and "min-length: 7" in admin and "num-auth-attempts: 10" in admin
    firewall = usergate.render_firewall(_json("xmlrpc/firewall_rules.json")["items"], zones)
    assert "PASS \\" in firewall and "enabled(true)" not in firewall
    assert PIN not in admin and PIN not in rendered and TOKEN not in firewall


# ---------- транспорт: порядок, ошибки, маскировка ----------

def test_xmlrpc_is_tried_first_and_password_never_leaves_the_secret_file(tmp_path):
    call, calls = _rpc_factory()

    def boom(*_a, **_k):
        raise AssertionError("SSH не нужен, когда XML-RPC ответил")

    transport = usergate.UserGateTransport(_config(tmp_path, methods=["xmlrpc", "ssh-exec"]), rpc_call=call, popen=boom)
    _bind(transport)
    try:
        result = probes.run_probe(transport, {
            "type": "cli_config", "cmd": "show settings administrators general",
            "require": r"(?m)^\s*strong-password\s*:", "match": r"^\s*strong-password\s*:\s*(\S+)",
        })
        version = probes.run_probe(transport, {
            "type": "cli_config", "cmd": "show system version",
            "require": r"UGOS", "match": r"(\d+\.\d+\.\d+(?:\.\d+)*[A-Za-z0-9]*)",
        })
    finally:
        transport.close()
    assert result["value"] == "off"
    assert version["value"] == "7.4.1.341220R"
    assert calls[0][0] == "v2.core.login" and calls[0][1][1] == PASSWORD
    assert "v2.core.license.info" not in [name for name, _args in calls]
    blob = json.dumps([item for item in calls if item[0] != "v2.core.login"], ensure_ascii=False)
    assert PASSWORD not in blob and TOKEN not in result["evidence"] and PIN not in result["evidence"]
    assert calls[-1][0] == "v2.core.logout"


def test_fallback_order_is_xmlrpc_then_exec_then_interactive(tmp_path):
    call, calls = _rpc_factory(fail_login=True)
    admin = _read("openssh/J-exec-stdin-open-show_settings_administrators_general.raw")
    version_err = _read("openssh/J-exec-stdin-open-show_system_version.raw")
    interactive = ScriptedSSH([
        (None, b"Admin@lab>\r\n"),
        ("show system version", b"Admin@lab>show system versionAdmin@lab> show system version\r\nUGOS NGFW 7.4.1.341220R\r\nAdmin@lab>\r\n"),
    ])
    popen = PopenLog({
        "show settings administrators general": admin,
        "show system version": version_err,
    }, interactive=interactive)
    transport = usergate.UserGateTransport(_config(tmp_path), rpc_call=call, popen=popen)
    _bind(transport)
    try:
        settings = transport.run_cli("show settings administrators general")
        version = transport.run_cli("show system version")
        askpass = Path(popen.envs[0]["SSH_ASKPASS"]).read_text(encoding="utf-8")
    finally:
        transport.close()
    assert transport._mode == "ssh-exec"
    assert "strong-password" in settings.stdout and "Error:" not in settings.stdout
    assert "7.4.1.341220R" in version.stdout and "Error:" not in version.stdout
    assert calls[0][0] == "v2.core.login"
    assert popen.argv[0][1] == "-T"  # сначала exec, не интерактив
    assert any(item == "-tt" for argv in popen.argv for item in argv)
    joined = json.dumps({"argv": popen.argv, "env": popen.envs}, ensure_ascii=False)
    assert PASSWORD not in joined and TOKEN not in joined
    env = popen.envs[0]
    assert env["SSH_ASKPASS_REQUIRE"] == "force" and "SSH_ASKPASS" in env
    assert env["HARDENING_SSH_PASS_FILE"].endswith("usergate.pass")
    assert "StrictHostKeyChecking=yes" in popen.argv[0]
    assert "PreferredAuthentications=keyboard-interactive,password" in popen.argv[0]
    assert "BatchMode=yes" not in popen.argv[0]
    # stdin был открыт в момент чтения: иначе снимок команды пришёл бы пустым
    exec_proc = next(proc for proc in popen.procs if isinstance(proc, ExecProc))
    assert exec_proc.events[0] == ("read", False)
    assert PASSWORD not in askpass and "HARDENING_SSH_PASS_FILE" in askpass


def test_interactive_session_pages_with_space_and_waits_for_prompt():
    proc = ScriptedSSH([
        (None, b"Admin@lab#\r\n"),
        ("show network zone Untrusted",
         b"Admin@lab#show network zone UntrustedAdmin@lab# show network zone Untrusted\r\n"
         b"name: Untrusted\r\n--more--"),
        (" ", b"    enabled: on\r\nAdmin@lab#\r\n"),
    ])
    session = usergate.InteractiveSession(proc, timeout=3)
    text = session.run("show network zone Untrusted")
    assert "name: Untrusted" in text and "enabled: on" in text and "--more--" not in text
    assert " " in proc.writes


def test_unmapped_command_falls_through_to_ssh_when_xmlrpc_is_up(tmp_path):
    call, calls = _rpc_factory()
    logs = (FIX / "exec/12.raw").read_bytes().split(b"\n", 1)[1]
    popen = PopenLog({"show logs logs-export": logs})
    transport = usergate.UserGateTransport(_config(tmp_path), rpc_call=call, popen=popen)
    _bind(transport)
    try:
        output = transport.run_cli("show logs logs-export")
    finally:
        transport.close()
    assert "server-type" in output.stdout
    assert popen.argv and popen.argv[0][-1] == "show logs logs-export"
    assert all(name != "v1.dos.profiles.list" for name, _args in calls)


def test_write_method_and_undeclared_method_are_rejected(tmp_path):
    call, calls = _rpc_factory()
    transport = usergate.UserGateTransport(_config(tmp_path, methods=["xmlrpc"]), rpc_call=call, popen=None)
    transport.bind_manifests([{"xmlrpc_methods": METHODS + ["v2.core.administrator.add", "v1.firewall.rules.update"]}])
    assert "v2.core.administrator.add" not in transport._allowed
    with pytest.raises(usergate.UserGateError, match="белом списке"):
        transport._call("v2.core.administrator.add", (TOKEN, {}))
    assert calls == []
    with pytest.raises(usergate.UserGateError, match="только команды на чтение"):
        transport.run_cli("reboot")


def test_all_access_methods_down_is_an_error_without_the_password(tmp_path):
    call, _calls = _rpc_factory(fail_login=True)
    popen = PopenLog({}, interactive=ScriptedSSH([(None, b"")]))
    transport = usergate.UserGateTransport(_config(tmp_path), rpc_call=call, popen=popen)
    _bind(transport)
    try:
        with pytest.raises(usergate.UserGateError, match="ни один способ") as exc:
            transport.run_cli("show settings administrators general")
    finally:
        transport.close()
    assert PASSWORD not in str(exc.value)


def test_secret_file_permissions_and_config_reject_an_inline_password(tmp_path):
    loose = _secret(tmp_path, mode=0o644)
    with pytest.raises(ValueError, match="0600"):
        usergate.check_secret_file(str(loose))
    link = tmp_path / "link"
    link.symlink_to(loose)
    with pytest.raises(ValueError, match="ссылка"):
        usergate.check_secret_file(str(link))
    cfg = tmp_path / "ug.json"
    cfg.write_text(json.dumps({"host": "10.77.0.20", "password": PASSWORD, "password_file": str(loose)}), encoding="utf-8")
    with pytest.raises(ValueError, match="password_file"):
        usergate.load_config(str(cfg))
    nested = tmp_path / "ok"
    nested.mkdir()
    path = _secret(nested)
    cfg.write_text(json.dumps({
        "host": "10.77.0.20", "user": "Admin", "hostname": "adlab-ug1",
        "password_file": str(path), "ssh_port": 2200, "known_hosts": "/var/lib/hardening-agent/known_hosts",
    }), encoding="utf-8")
    loaded = usergate.load_config(str(cfg))
    assert loaded["host"] == "10.77.0.20" and loaded["ssh_port"] == 2200
    assert loaded["methods"] == ["xmlrpc", "ssh-exec", "ssh-interactive"]
    assert PASSWORD not in json.dumps(loaded)
