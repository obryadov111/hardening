"""Континент 4 без живого ЦУС: фикстуры 4.2.1-653, поддельный HTTPS и цепочка ГОСТ-TLS.

Пара export-for-cgw-4210001-initial.json / export-for-cgw-4210001.json — конфигурация до и после
изменений на стенде. Секреты в фикстурах уже заменены; рендер не должен вернуть REDACTED и хэши.
"""
import json
import os
import shutil
import ssl
import stat
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

import continent4
import probes

FIX = Path(__file__).resolve().parent / "fixtures" / "continent4"
PASSWORD = "not-the-real-lab-secret"


def _load(name):
    return json.loads((FIX / name).read_text(encoding="utf-8"))


def _secret(tmp_path, text=PASSWORD):
    path = tmp_path / "continent4.pass"
    path.write_text(text + "\n", encoding="utf-8")
    os.chmod(str(path), 0o600)
    return path


def _config(tmp_path, **overrides):
    data = {
        "host": "127.0.0.1",
        "port": 444,
        "user": "hardening-ro",
        "password_file": str(_secret(tmp_path)),
        "timeout": 5,
        "connect_timeout": 2,
        "tls": ["in-process", "python", "curl", "openssl"],
    }
    data.update(overrides)
    return data


def _offline(tmp_path, export_name, cgw_name="cgw.json"):
    directory = tmp_path / export_name
    directory.mkdir()
    (directory / "export-config-for-cgw.json").write_bytes((FIX / export_name).read_bytes())
    (directory / "cgw.json").write_bytes((FIX / cgw_name).read_bytes())
    (directory / "config.json").write_bytes((FIX / "config.json").read_bytes())
    return continent4.Continent4Transport.from_directory(str(directory))


def _statuses(transport):
    rows, version = continent4.evaluate_rendered(transport)
    return {row["id"]: row["status"] for row in rows}, {row["id"]: row["value"] for row in rows}, version


def test_sanitize_covers_password_typo_and_snmp_community():
    raw = {
        "password": "secret",
        "password_ssha": "hash",
        "pasword_ssha": "typo-hash",
        "pasword_sha512": "typo-hash-2",
        "password_auth": True,
        "passwords_diff": 5,
        "community_name": "public",
        "_auth_pass": "auth",
        "_old_passwords": ["a"],
        "sign": "ABCD",
        "pubkey": "KEY",
        "dbdata": "blob",
        "login": "auditor",
        "nested": {"confirm_password": "x", "min_length": 10},
    }
    clean = continent4.sanitize(raw)
    assert clean["pasword_ssha"] == "REDACTED"
    assert clean["pasword_sha512"] == "REDACTED"
    assert clean["community_name"] == "REDACTED"
    assert clean["_old_passwords"] == []
    assert clean["login"] == "auditor"
    assert clean["passwords_diff"] == 5
    assert clean["nested"]["min_length"] == 10
    assert clean["nested"]["confirm_password"] == "REDACTED"
    assert "typo-hash" not in json.dumps(clean)
    assert PASSWORD not in continent4.scrub_text('password is ' + PASSWORD, [PASSWORD])


def test_rendered_lab_pair_differs_and_keeps_secrets_out(tmp_path):
    changed = _offline(tmp_path, "export-for-cgw-4210001.json")
    initial = _offline(tmp_path, "export-for-cgw-4210001-initial.json", "cgw-initial.json")
    changed_status, changed_values, changed_version = _statuses(changed)
    initial_status, initial_values, initial_version = _statuses(initial)

    assert changed_version["value"] == "4.2.1-653"
    assert initial_version["value"] == "4.2.1-653"
    assert changed_status["kontinent4.personal_admin_accounts"] == "pass"
    assert initial_status["kontinent4.personal_admin_accounts"] == "fail"
    assert changed_values["kontinent4.personal_admin_accounts"] == 2
    assert initial_values["kontinent4.personal_admin_accounts"] == 0
    assert changed_status != initial_status

    # Общее для обеих фикстур стенда: пароль 10, блокировка включена, SSH и SNMP выключены, syslog нет.
    for status in (changed_status, initial_status):
        assert status["kontinent4.password_min_length"] == "pass"
        assert status["kontinent4.lockout_enabled"] == "pass"
        assert status["kontinent4.ssh_access_restricted"] == "pass"
        assert status["kontinent4.snmp_secure"] == "pass"
        assert status["kontinent4.remote_syslog"] == "fail"

    blob = []
    for transport in (changed, initial):
        for command in continent4.COMMANDS:
            assert probes.is_readonly_cli(command)
            blob.append(transport.run_cli(command).stdout)
    text = "\n".join(blob)
    for secret in ("REDACTED", "pasword_", "password_ssha", "community_name", "BEGIN CERTIFICATE"):
        assert secret not in text
    assert changed.describe()["source"] == "offline-config"
    assert {item["file"] for item in changed.describe()["files"]} >= {"export-config-for-cgw.json", "cgw.json"}


def test_mutated_export_flips_the_other_checks(tmp_path):
    export = _load("export-for-cgw-4210001.json")
    for item in export["objects"]:
        if item.get("type") == "passwordpolicy":
            item["min_length"] = 4
            item["wrong_try_count"] = 0
            item["wrong_try_block"] = 0
        elif item.get("type") == "sshaccesscomponent":
            item["is_enabled"] = True
        elif item.get("type") == "snmpcomponent":
            item["is_enabled"] = True
            item["protocol"] = "v2"
            item["community_name"] = "lab-community-should-not-appear"
    export["objects"].append({
        "type": "logserverremoteuplink",
        "is_enabled": True,
        "host": "10.1.1.8",
        "port": 514,
        "uuid": "syslog-1",
    })
    directory = tmp_path / "bad"
    directory.mkdir()
    (directory / "export-config-for-cgw.json").write_text(json.dumps(export), encoding="utf-8")
    (directory / "cgw.json").write_bytes((FIX / "cgw.json").read_bytes())
    transport = continent4.Continent4Transport.from_directory(str(directory))
    status, values, _version = _statuses(transport)
    assert status["kontinent4.password_min_length"] == "fail"
    assert values["kontinent4.password_min_length"] == "4"
    assert status["kontinent4.lockout_enabled"] == "fail"
    assert status["kontinent4.ssh_access_restricted"] == "fail"
    assert values["kontinent4.ssh_access_restricted"] == "включён без ограничения адресов"
    assert status["kontinent4.snmp_secure"] == "fail"
    assert status["kontinent4.remote_syslog"] == "pass"
    assert "lab-community-should-not-appear" not in transport.run_cli(continent4.CMD_SNMP).stdout


def test_two_exports_in_one_directory_are_refused(tmp_path):
    directory = tmp_path / "both"
    directory.mkdir()
    (directory / "a.json").write_bytes((FIX / "export-for-cgw-4210001.json").read_bytes())
    (directory / "b.json").write_bytes((FIX / "export-for-cgw-4210001-initial.json").read_bytes())
    with pytest.raises(ValueError, match="два файла"):
        continent4.Continent4Transport.from_directory(str(directory))


def test_write_paths_never_leave_the_whitelist(tmp_path):
    called = []

    def runner(argv, env, data, timeout):
        called.append(argv)
        return 1, b"", b"should not run"

    transport = continent4.Continent4Transport(_config(tmp_path), runner=runner)
    transport.bind_builtin()
    for path in (
        "/api-v1-server/config/active/install-policy",
        "/api-v1-server/config/active/set-password",
        "/api-v1-server/config/active/acquire-config-lock",
        "/api-v1-objects/config/fork",
        "/api-v1-server/config/active/export-config-for-cgw/4210001?view=short",
        "/api-v1-objects/config?x=1",
    ):
        with pytest.raises(continent4.Continent4Error, match="белом списке|недопустим"):
            transport._get(path)
    assert called == []
    transport.bind_manifests([{
        "c4_paths": [
            "/api-v1-objects/config",
            "/api-v1-server/config/active/install-policy",
            "/api-v1-server/config/active/export-config-for-cgw",
        ],
    }])
    assert transport._allowed == [
        "/api-v1-objects/config",
        "/api-v1-server/config/active/export-config-for-cgw",
    ]


def test_gost_chain_order_and_password_not_in_argv(tmp_path, monkeypatch):
    monkeypatch.setattr(continent4, "_process_has_gost", lambda: False)
    monkeypatch.setattr(continent4, "find_gost_engine", lambda explicit=None: None)
    seen = []

    def runner(argv, env, data, timeout):
        seen.append((list(argv), dict(env), data))
        return 1, b"", b"handshake failure: no shared cipher"

    transport = continent4.Continent4Transport(_config(tmp_path), runner=runner)
    transport.bind_builtin()
    with pytest.raises(continent4.Continent4Error, match="ГОСТ") as exc:
        transport._get("/api-v1-objects/config")
    assert "libengine-gost-openssl" in str(exc.value)
    assert PASSWORD not in str(exc.value)
    assert seen == []  # без gost.so curl/python/openssl не запускаются

    engine = tmp_path / "gost.so"
    engine.write_bytes(b"not-a-real-engine")
    monkeypatch.setattr(continent4, "find_gost_engine", lambda explicit=None: str(engine))
    seen.clear()

    def succeed(argv, env, data, timeout):
        seen.append((list(argv), dict(env), data))
        joined = " ".join(argv)
        assert PASSWORD not in joined
        assert all(PASSWORD not in str(value) for value in env.values())
        if argv[0] == "curl":
            conf = argv[argv.index("-K") + 1]
            secret_file = Path(conf).read_text(encoding="utf-8")
            assert PASSWORD in secret_file
            assert stat.S_IMODE(os.stat(conf).st_mode) == 0o600
            return 1, b"", b"ssl handshake failure"
        if argv[0] == "openssl":
            assert PASSWORD.encode() in data
            return 1, b"", b"handshake failure"
        job = json.loads(data.decode("utf-8"))
        assert job["password"] == PASSWORD
        assert job["path"] == "/api-v1-objects/config"
        body = json.dumps({"data": [{"type": "config", "uuid": "1"}]}).encode()
        payload = {
            "status": 200,
            "cert_sha256": "ab" * 32,
            "body_b64": __import__("base64").b64encode(body).decode("ascii"),
        }
        return 0, json.dumps(payload).encode("ascii"), b""

    transport = continent4.Continent4Transport(
        _config(tmp_path, pin_sha256="ab" * 32, tls=["python", "curl", "openssl"]),
        runner=succeed,
    )
    transport.bind_builtin()
    transport._password = PASSWORD
    body = transport._get("/api-v1-objects/config")
    assert json.loads(body)["data"][0]["type"] == "config"
    assert "python" in os.path.basename(seen[0][0][0])
    assert transport._tls_name == "python"
    assert len(seen) == 1  # curl и openssl не понадобились


def test_pin_mismatch_does_not_fall_through(tmp_path, monkeypatch):
    monkeypatch.setattr(continent4, "find_gost_engine", lambda explicit=None: str(tmp_path / "gost.so"))
    (tmp_path / "gost.so").write_bytes(b"x")
    calls = []

    def runner(argv, env, data, timeout):
        calls.append(argv[0])
        if argv[0] == "curl":
            return 0, b"{}\n__C4_200", b""
        payload = {"status": 200, "cert_sha256": "cd" * 32, "body_b64": "e30="}
        return 0, json.dumps(payload).encode("ascii"), b""

    transport = continent4.Continent4Transport(
        _config(tmp_path, pin_sha256="ab" * 32, tls=["python", "curl"]),
        runner=runner,
    )
    transport.bind_builtin()
    transport._password = PASSWORD
    with pytest.raises(continent4.Continent4Error, match="pin_sha256"):
        transport._get("/api-v1-objects/config")
    assert len(calls) == 1
    assert "curl" not in calls[0]


def test_secret_file_must_be_owner_only(tmp_path):
    loose = tmp_path / "loose"
    loose.write_text("secret\n", encoding="utf-8")
    os.chmod(str(loose), 0o644)
    with pytest.raises(ValueError, match="0600"):
        continent4.check_secret_file(str(loose))
    path = tmp_path / "target.json"
    path.write_text(json.dumps({
        "kind": "continent4", "host": "10.0.0.5", "user": "hardening-ro",
        "password_file": str(loose),
    }), encoding="utf-8")
    with pytest.raises(ValueError, match="0600"):
        continent4.load_config(str(path))
    path.write_text(json.dumps({
        "kind": "continent4", "host": "10.0.0.5", "user": "hardening-ro",
        "password": "inline", "password_file": str(_secret(tmp_path)),
    }), encoding="utf-8")
    with pytest.raises(ValueError, match="password_file"):
        continent4.load_config(str(path))


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.seen.append(("GET", self.path))
        body = self.server.routes.get(self.path)
        if body is None:
            self.send_response(404)
            self.end_headers()
            return
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        self.server.seen.append(("POST", self.path))
        self.send_response(403)
        self.end_headers()

    def log_message(self, fmt, *args):
        return


def _https_server(routes):
    if shutil.which("openssl") is None:
        pytest.skip("openssl нужен, чтобы поднять тестовый TLS")
    cert = Path(os.environ.get("TMPDIR") or "/tmp") / "c4-test-cert.pem"
    key = Path(os.environ.get("TMPDIR") or "/tmp") / "c4-test-key.pem"
    if not cert.exists():
        subprocess.check_call([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", str(key), "-out", str(cert),
            "-days", "1", "-nodes", "-subj", "/CN=localhost",
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    httpd = HTTPServer(("127.0.0.1", 0), _Handler)
    ctx = ssl.SSLContext(getattr(ssl, "PROTOCOL_TLS_SERVER", ssl.PROTOCOL_TLS))
    ctx.load_cert_chain(str(cert), str(key))
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    httpd.routes = routes
    httpd.seen = []
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd


def test_fake_https_fetches_only_the_three_gets(tmp_path, monkeypatch):
    export = (FIX / "export-for-cgw-4210001.json").read_bytes()
    routes = {
        "/api-v1-objects/config": (FIX / "config.json").read_bytes(),
        "/api-v1-objects/config/active/cgw": (FIX / "cgw.json").read_bytes(),
        "/api-v1-server/config/active/export-config-for-cgw/4210001?view=full": export,
    }
    httpd = _https_server(routes)
    host, port = httpd.server_address

    def local_get(host_, port_, path, user, password, timeout, connect_timeout, ciphers):
        assert password == PASSWORD
        assert ciphers  # агент просит ГОСТ; в тесте сервер говорит обычным TLS
        return continent4.http_get(host_, port_, path, user, password, timeout, connect_timeout, "DEFAULT")

    monkeypatch.setattr(continent4, "_process_has_gost", lambda: False)
    transport = continent4.Continent4Transport(
        _config(tmp_path, host=host, port=port, tls=["in-process"]),
        http_get=local_get,
    )
    # in-process без движка пропускается, поэтому подменяем проверку шифра и оставляем тот же HTTP-клиент.
    monkeypatch.setattr(continent4, "_process_has_gost", lambda: True)
    transport.bind_builtin()
    try:
        rows, version = continent4.evaluate_rendered(transport)
    finally:
        httpd.shutdown()
    assert version["value"] == "4.2.1-653"
    assert {row["id"]: row["status"] for row in rows}["kontinent4.personal_admin_accounts"] == "pass"
    methods = {item[0] for item in httpd.seen}
    paths = [item[1] for item in httpd.seen]
    assert methods == {"GET"}
    assert paths == [
        "/api-v1-objects/config",
        "/api-v1-objects/config/active/cgw",
        "/api-v1-server/config/active/export-config-for-cgw/4210001?view=full",
    ]


def test_device_config_kind_opens_continent_transport(tmp_path):
    import collector

    secret = _secret(tmp_path)
    path = tmp_path / "c4.json"
    path.write_text(json.dumps({
        "kind": "continent4", "host": "10.0.0.8", "user": "hardening-ro",
        "password_file": str(secret), "hwserial": "4210001",
    }), encoding="utf-8")
    transport = collector.open_device_transport(str(path))
    try:
        assert transport.host == "10.0.0.8"
        assert transport.config["hwserial"] == "4210001"
        assert transport.name == "ssh"
    finally:
        transport.close()


def test_cli_prints_results_without_the_password(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(continent4, "_process_has_gost", lambda: False)
    monkeypatch.setattr(continent4, "find_gost_engine", lambda explicit=None: None)
    secret = _secret(tmp_path)
    code = continent4.main([
        "--host", "127.0.0.1", "--user", "hardening-ro", "--password-file", str(secret),
        "--port", "9", "--connect-timeout", "1", "--timeout", "1",
    ])
    assert code == 2
    captured = capsys.readouterr()
    assert PASSWORD not in captured.out and PASSWORD not in captured.err
    assert "ГОСТ" in captured.err
    # Сбой чтения — одна строка и код 2, а не шесть проверок с тем же текстом.
    assert captured.out.strip() == ""
    assert "kontinent4." not in captured.err
    assert captured.err.count("Континент 4 ") == 1


def test_one_401_is_a_single_request_and_not_a_tls_fallback(tmp_path, monkeypatch):
    calls = []

    def http_get(host, port, path, user, password, timeout, connect_timeout, ciphers):
        calls.append(path)
        return 401, b'{"detail":"unauthorized"}', b"\x30"

    monkeypatch.setattr(continent4, "_process_has_gost", lambda: True)
    transport = continent4.Continent4Transport(
        _config(tmp_path, tls=["in-process", "curl"]),
        http_get=http_get,
        runner=lambda *args: (_ for _ in ()).throw(AssertionError("curl не должен вызываться после 401")),
    )
    transport.bind_builtin()
    rows, version = continent4.evaluate_rendered(transport)
    assert calls == ["/api-v1-objects/config"]
    assert all(row["status"] == "error" for row in rows)
    assert all("HTTP 401" in (row["error"] or "") for row in rows)
    assert "Повторная попытка не выполняется" in rows[0]["error"]
    assert version.get("found") is False
    assert "HTTP 401" in (version.get("error") or "")


def test_python_network_error_does_not_fall_through_to_curl(tmp_path, monkeypatch):
    engine = tmp_path / "gost.so"
    engine.write_bytes(b"x")
    monkeypatch.setattr(continent4, "find_gost_engine", lambda explicit=None: str(engine))
    calls = []

    def runner(argv, env, data, timeout):
        calls.append(os.path.basename(argv[0]))
        if "python" in os.path.basename(argv[0]):
            return 3, b"", b"connection refused"
        return 0, b"__C4_200", b""

    transport = continent4.Continent4Transport(
        _config(tmp_path, tls=["python", "curl"]),
        runner=runner,
    )
    transport.bind_builtin()
    transport._password = PASSWORD
    with pytest.raises(continent4.Continent4Error, match="connection refused") as exc:
        transport._get("/api-v1-objects/config")
    assert "нет ГОСТ TLS" not in str(exc.value)
    assert calls == [calls[0]]
    assert "python" in calls[0]
    assert "curl" not in calls


def test_gost_failure_still_tries_the_next_method(tmp_path, monkeypatch):
    engine = tmp_path / "gost.so"
    engine.write_bytes(b"x")
    monkeypatch.setattr(continent4, "find_gost_engine", lambda explicit=None: str(engine))
    calls = []

    def runner(argv, env, data, timeout):
        calls.append(os.path.basename(argv[0]))
        if "python" in os.path.basename(argv[0]):
            return 2, b"", "рукопожатие TLS: no shared cipher".encode("utf-8")
        return 0, b'{"ok":true}__C4_200', b""

    transport = continent4.Continent4Transport(
        _config(tmp_path, tls=["python", "curl"]),
        runner=runner,
    )
    transport.bind_builtin()
    transport._password = PASSWORD
    body = transport._get("/api-v1-objects/config")
    assert body.startswith(b'{"ok":true}')
    assert calls[0].startswith("python") or "python" in calls[0]
    assert calls[1] == "curl"


def test_curl_with_pin_explains_the_pin_not_a_missing_engine(tmp_path):
    transport = continent4.Continent4Transport(_config(tmp_path, tls=["curl"], pin_sha256="ab" * 32))
    transport.bind_builtin()
    transport._password = PASSWORD
    with pytest.raises(continent4.Continent4Error, match="не сверяет отпечаток") as exc:
        transport._get("/api-v1-objects/config")
    text = str(exc.value)
    assert "не отсутствие движка" in text
    assert "libengine-gost-openssl" not in text


def test_foreign_openssl_conf_does_not_hide_the_gost_engine(tmp_path, monkeypatch):
    plain = tmp_path / "no-gost.cnf"
    plain.write_text("openssl_conf = system_default\n[system_default]\nssl_conf = ssl_sect\n", encoding="utf-8")
    engine = tmp_path / "gost.so"
    engine.write_bytes(b"x")
    monkeypatch.setenv("OPENSSL_CONF", str(plain))
    monkeypatch.setattr(continent4, "find_gost_engine", lambda explicit=None: str(engine))
    transport = continent4.Continent4Transport(_config(tmp_path))
    path = transport._prepare_conf()
    assert path != str(plain)
    assert "gost.so" in Path(path).read_text(encoding="utf-8")
    assert engine.name in Path(path).read_text(encoding="utf-8") or str(engine) in Path(path).read_text(encoding="utf-8")

    monkeypatch.setattr(continent4, "find_gost_engine", lambda explicit=None: None)
    with pytest.raises(continent4.TlsUnavailable, match="не подключает движок ГОСТ") as exc:
        transport._prepare_conf()
    assert str(plain) in str(exc.value)
    assert "libengine-gost-openssl" in str(exc.value)


def test_cli_tls_flag_selects_methods(tmp_path, capsys):
    secret = _secret(tmp_path)
    code = continent4.main([
        "--host", "127.0.0.1", "--user", "hardening-ro", "--password-file", str(secret),
        "--tls", "wget",
    ])
    assert code == 2
    assert "--tls" in capsys.readouterr().err

    code = continent4.main([
        "--host", "127.0.0.1", "--user", "hardening-ro", "--password-file", str(secret),
        "--tls", "curl", "--pin-sha256", "ab" * 32,
    ])
    assert code == 2
    captured = capsys.readouterr()
    assert "не сверяет отпечаток" in captured.err
    assert captured.out.strip() == ""
    assert "kontinent4." not in captured.out and "kontinent4." not in captured.err
