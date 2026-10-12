"""Связь агента с сервером: только HTTPS, проверка сертификата, закрепление ключа, очередь, подписанный отчёт.
Сервер — настоящий HTTPS в потоке теста (самоподписанный сертификат из tests/tls)."""
import hashlib
import hmac
import json
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

import collector
from collector import RejectedError, ServerConnection, TransientError

TLS = os.path.join(os.path.dirname(__file__), "tls")
CERT, KEY, OTHER = (os.path.join(TLS, n) for n in ("server.crt", "server.key", "other.crt"))
PIN = "DNFWvTmaoDt0ILWvrpCJhDEKPfeysbJ2cqEo1uuiXp4="       # openssl: SHA-256 SPKI server.crt
OTHER_PIN = "xuv5QZocJHeTQ8bvQUd9z81O1UyEtknQnVo+2lIQtYE="


class Server:
    """HTTPS-сервер: GET — {"status": "ok"}; POST /api/ingest — код из self.status, тела запросов — в self.received,
    ключи — в self.keys; POST /api/agent/enroll — код из self.enroll_status, имена хостов — в self.enrolled,
    ключ хоста — host-key-<n>; ingest с ключом из self.dead_keys — 401."""

    def __init__(self):
        outer = self
        self.status, self.received, self.keys = 200, [], []
        self.enroll_status, self.enrolled, self.dead_keys = 201, [], set()

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _reply(self, code, body):
                data = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                self._reply(200, {"status": "ok", "key": self.headers.get("X-Agent-Api-Key")})

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                key = self.headers.get("X-Agent-Api-Key")
                if self.path == "/api/agent/enroll":
                    outer.enrolled.append((body["hostname"], key))
                    host_key = f"host-key-{len(outer.enrolled)}"
                    self._reply(outer.enroll_status, {"host_id": "h", "hostname": body["hostname"], "key": host_key}
                                if outer.enroll_status == 201 else {"detail": "имя занято"})
                    return
                if key in outer.dead_keys:
                    self._reply(401, {"detail": "Недействительный ключ агента"})
                    return
                outer.received.append(body)
                outer.keys.append(key)
                self._reply(outer.status, {"ok": outer.status == 200})

        self.httpd = HTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(CERT, KEY)
        self.httpd.socket = context.wrap_socket(self.httpd.socket, server_side=True)
        self.url = f"https://localhost:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def server():
    srv = Server()
    yield srv
    srv.close()


# ---------- только HTTPS ----------

@pytest.mark.parametrize("url", ["http://audit.example.ru", "http://10.8.0.1", "ftp://localhost"])
def test_plain_http_to_a_remote_server_is_refused(url):
    with pytest.raises(SystemExit, match="нужен https"):
        ServerConnection(url, "k")


@pytest.mark.parametrize("url", ["https://audit.example.ru", "http://localhost:8000", "http://127.0.0.1:8000", "http://[::1]:8000"])
def test_https_and_loopback_http_are_allowed(url):
    ServerConnection(url, "k")


def test_http_inside_vpn_needs_explicit_flag():
    ServerConnection("http://10.8.0.1", "k", allow_http=True)


# ---------- сертификат и закрепление ключа ----------

def test_pin_of_certificate_matches_openssl():
    pem = open(CERT, encoding="ascii").read()
    assert collector.spki_pin(ssl.PEM_cert_to_DER_cert(pem)) == PIN


def test_trusted_ca_and_matching_pin_connect(server):
    conn = ServerConnection(server.url, "secret", ca_file=CERT, pins=[f"sha256//{PIN}"])
    assert conn.request("GET", "/health") == {"status": "ok", "key": "secret"}
    assert conn.seen_pins == [PIN]


def test_backup_pin_is_enough(server):
    ServerConnection(server.url, "k", ca_file=CERT, pins=[OTHER_PIN, PIN]).request("GET", "/health")


def test_wrong_pin_is_a_security_error_not_a_retry(server):
    """Подмена сервера (MITM с доверенным в сети корневым сертификатом): сертификат проходит проверку,
    но ключ другой — остановка, а не «сервер недоступен, отложим в очередь»."""
    with pytest.raises(SystemExit, match="Ошибка безопасности.*закреплённым"):
        ServerConnection(server.url, "k", ca_file=CERT, pins=[OTHER_PIN]).request("GET", "/health")


def test_untrusted_certificate_is_a_security_error(server):
    with pytest.raises(SystemExit, match="сертификат сервера не прошёл проверку"):
        ServerConnection(server.url, "k", ca_file=OTHER).request("GET", "/health")


def test_show_server_pin_prints_pin_for_configuration(server, capsys):
    assert collector.main(["--api-url", server.url, "--environment", "x", "--ca-file", CERT, "--show-server-pin"]) == 0
    assert capsys.readouterr().out.strip() == f"sha256//{PIN}"


# ---------- ответы сервера ----------

@pytest.mark.parametrize("code,kind", [(500, TransientError), (502, TransientError), (429, TransientError),
                                       (401, RejectedError), (409, RejectedError), (422, RejectedError)])
def test_server_errors_are_classified(server, code, kind):
    server.status = code
    with pytest.raises(kind):
        collector.send_ingest(ServerConnection(server.url, "k", ca_file=CERT), {"x": 1})


def test_unreachable_server_is_transient():
    with pytest.raises(TransientError, match="нет связи"):
        ServerConnection("https://127.0.0.1:9", "k", timeout=2).request("GET", "/health")


# ---------- очередь ----------

def _payload(n):
    return {"run_id": f"00000000-0000-0000-0000-00000000000{n}", "collected_at": f"2026-10-1{n}T10:00:00+00:00", "n": n}


def test_spool_keeps_runs_and_sends_them_in_order(server, tmp_path):
    spool = str(tmp_path / "spool")
    for n in (2, 1):
        path = collector.spool_save(spool, _payload(n))
        if os.name != "nt":
            assert os.stat(path).st_mode & 0o777 == 0o600
    sent = collector.spool_flush(ServerConnection(server.url, "k", ca_file=CERT), spool, print)
    assert sent == 2 and [r["n"] for r in server.received] == [1, 2]
    assert collector.spool_files(spool) == []


def test_spool_stays_when_server_is_down_again(tmp_path):
    spool = str(tmp_path / "spool")
    collector.spool_save(spool, _payload(1))
    with pytest.raises(TransientError):
        collector.spool_flush(ServerConnection("https://127.0.0.1:9", "k", timeout=2), spool, print)
    assert len(collector.spool_files(spool)) == 1


def test_spool_duplicate_is_dropped_and_rejected_is_set_aside(server, tmp_path):
    spool = str(tmp_path / "spool")
    collector.spool_save(spool, _payload(1))
    server.status = 409  # уже принят
    assert collector.spool_flush(ServerConnection(server.url, "k", ca_file=CERT), spool, print) == 0
    assert collector.spool_files(spool) == []
    collector.spool_save(spool, _payload(2))
    server.status = 422
    collector.spool_flush(ServerConnection(server.url, "k", ca_file=CERT), spool, print)
    assert collector.spool_files(spool) == [] and [f for f in os.listdir(spool) if f.endswith(".rejected")]


def test_spool_is_kept_when_key_is_revoked(server, tmp_path):
    spool = str(tmp_path / "spool")
    collector.spool_save(spool, _payload(1))
    server.status = 401
    with pytest.raises(RejectedError):
        collector.spool_flush(ServerConnection(server.url, "k", ca_file=CERT), spool, print)
    assert len(collector.spool_files(spool)) == 1


def test_spool_is_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr(collector, "SPOOL_MAX_FILES", 3)
    spool = str(tmp_path / "spool")
    for n in range(1, 6):
        collector.spool_save(spool, _payload(n))
    assert [os.path.basename(p)[:8] for p in collector.spool_files(spool)] == ["20261013", "20261014", "20261015"]
    old = collector.spool_files(spool)[0]
    os.utime(old, (0, 0))
    collector.spool_trim(spool)
    assert old not in collector.spool_files(spool)


def test_main_spools_on_outage_and_flushes_next_time(server, tmp_path, monkeypatch, capsys):
    """Полный цикл агента: сервер упал — код 75 и прогон в очереди; сервер поднялся — сначала досылка, потом новый."""
    monkeypatch.setattr(collector, "build_payload", lambda args: {"environment": args.environment, "asset": {}})
    spool = str(tmp_path / "spool")
    args = ["--environment", "prod", "--api-key", "k", "--ca-file", CERT, "--spool-dir", spool, "--state-dir", str(tmp_path)]
    assert collector.main(["--api-url", "https://127.0.0.1:9", *args]) == 75
    assert len(collector.spool_files(spool)) == 1
    assert collector.main(["--api-url", server.url, *args]) == 0
    assert len(server.received) == 2 and collector.spool_files(spool) == []
    first, second = server.received
    assert first["run_id"] != second["run_id"] and first["collected_at"] <= second["collected_at"]


# ---------- подписанный отчёт для переноса файлом ----------

def test_signed_report_is_verifiable_with_the_stored_key_hash_only(tmp_path, monkeypatch):
    monkeypatch.setattr(collector, "build_payload", lambda args: {"environment": args.environment, "asset": {"hostname": "h"}})
    out = tmp_path / "report.json"
    assert collector.main(["--api-url", "https://audit.example.ru", "--environment", "prod", "--api-key", "yak_secret", "--out", str(out),
                           "--state-dir", str(tmp_path / "state")]) == 0
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["format"] == "hardening-agent-report" and report["payload"]["run_id"]
    stored_hash = hashlib.sha256(b"yak_secret").hexdigest()  # так ключ хранит сервер
    expected = hmac.new(stored_hash.encode(), collector.canonical(report["payload"]), hashlib.sha256).hexdigest()
    assert hmac.compare_digest(report["signature"], expected)
    report["payload"]["asset"]["hostname"] = "подменён"
    assert not hmac.compare_digest(report["signature"],
                                   hmac.new(stored_hash.encode(), collector.canonical(report["payload"]), hashlib.sha256).hexdigest())


# ---------- регистрация хоста ----------

def _run(server, tmp_path, *extra, key="site-key"):
    args = ["--api-url", server.url, "--environment", "prod", "--ca-file", CERT,
            "--spool-dir", str(tmp_path / "spool"), "--state-dir", str(tmp_path / "state"), *extra]
    return collector.main(args + (["--api-key", key] if key else []))


@pytest.fixture
def host_payload(monkeypatch):
    monkeypatch.setattr(collector, "build_payload", lambda args: {"environment": args.environment, "asset": {"hostname": "PC-001", "os": "Ubuntu"}})


def test_first_run_enrolls_with_site_key_then_uses_host_key(server, tmp_path, host_payload):
    assert _run(server, tmp_path) == 0
    assert server.enrolled == [("PC-001", "site-key")] and server.keys == ["host-key-1"]
    host_file = tmp_path / "state" / "host.json"
    assert json.loads(host_file.read_text(encoding="utf-8"))["key"] == "host-key-1"
    if os.name != "nt":
        assert host_file.stat().st_mode & 0o777 == 0o600 and (tmp_path / "state").stat().st_mode & 0o777 == 0o700
    # следующие прогоны — ключом хоста, без регистрации; ключ площадки больше не нужен
    assert _run(server, tmp_path, key=None) == 0
    assert len(server.enrolled) == 1 and server.keys == ["host-key-1", "host-key-1"]


def test_enroll_only_registers_and_exits(server, tmp_path):
    assert _run(server, tmp_path, "--enroll", "--hostname", "WS-42") == 0
    assert server.enrolled == [("WS-42", "site-key")] and server.received == []
    assert _run(server, tmp_path, "--enroll", "--hostname", "WS-42") == 0  # повторно — уже зарегистрирован
    assert len(server.enrolled) == 1


def test_enrollment_conflict_is_reported_and_nothing_is_sent(server, tmp_path, host_payload, capsys):
    server.enroll_status = 409
    assert _run(server, tmp_path) == 1
    assert "имя занято" in capsys.readouterr().err
    assert server.received == [] and not (tmp_path / "state" / "host.json").exists()


def test_server_without_enrollment_gets_site_key_as_before(server, tmp_path, host_payload):
    server.enroll_status = 404
    assert _run(server, tmp_path) == 0
    assert server.keys == ["site-key"] and not (tmp_path / "state" / "host.json").exists()


def test_deleted_registration_is_renewed_with_site_key(server, tmp_path, host_payload):
    assert _run(server, tmp_path) == 0
    server.dead_keys.add("host-key-1")  # администратор удалил регистрацию на сервере
    assert _run(server, tmp_path) == 0
    assert [k for k, _ in server.enrolled] == ["PC-001", "PC-001"] and server.keys == ["host-key-1", "host-key-2"]


def test_without_site_key_a_dead_host_key_is_explained(server, tmp_path, host_payload, capsys):
    assert _run(server, tmp_path) == 0
    server.dead_keys.add("host-key-1")
    assert _run(server, tmp_path, key=None) == 1
    assert "ключ площадки" in capsys.readouterr().err


def test_no_key_and_no_registration_is_an_error(server, tmp_path, host_payload, capsys):
    assert _run(server, tmp_path, key=None) == 1
    assert "host.json" in capsys.readouterr().err



def test_pack_mode_fetches_manifests_with_host_key_alone(tmp_path, monkeypatch):
    """Режим паков после регистрации: манифесты забираются ключом хоста, ключ площадки не нужен."""
    collector.save_host_registration(str(tmp_path / "state"), {"key": "host-key-1"})
    used = []

    def fake_fetch(conn, transport):
        used.append(conn.api_key)
        raise SystemExit("стоп")
    monkeypatch.setattr(collector, "fetch_manifests", fake_fetch)
    monkeypatch.delenv("HARDENING_AGENT_API_KEY", raising=False)
    with pytest.raises(SystemExit):
        collector.main(["--api-url", "https://audit.example.ru", "--environment", "prod", "--use-packs", "--pack-key", "k",
                        "--state-dir", str(tmp_path / "state")])
    assert used == ["host-key-1"]
