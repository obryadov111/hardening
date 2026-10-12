"""Тестовый сервер для CI: отдаёт манифесты из файла, регистрирует хост, принимает отчёт.

    python agent_fake_server.py <порт> <manifests.json> <журнал.json> [hardening-agent.exe]

Журнал — JSON-строки запросов: путь, ключ агента (X-Agent-Api-Key), тело. По нему CI проверяет, что
настоящий hardening-agent.exe зарегистрировал хост ключом площадки и отправил отчёт ключом хоста.
"""
import hashlib
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT, MANIFESTS, LOG = int(sys.argv[1]), sys.argv[2], sys.argv[3]
EXE = sys.argv[4] if len(sys.argv) > 4 else None  # опубликованный агент — для сценария GPO
SITE_KEY, HOST_KEY = "ci-site-key", "ci-host-key"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _reply(self, code, body):
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _log(self, body):
        with open(LOG, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"path": self.path, "key": self.headers.get("X-Agent-Api-Key"), "body": body}, ensure_ascii=False) + "\n")

    def do_GET(self):
        self._log(None)
        if self.path == "/downloads/version.json" and EXE:
            with open(EXE, "rb") as fh:
                digest = hashlib.sha256(fh.read()).hexdigest()
            return self._reply(200, {"server_url": None, "server_pin": None, "files": [
                {"platform": "windows", "name": "hardening-agent.exe", "version": "ci", "sha256": digest, "size": os.path.getsize(EXE)}]})
        if self.path == "/downloads/hardening-agent.exe" and EXE:
            with open(EXE, "rb") as fh:
                data = fh.read()
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if self.path.startswith("/api/agent/manifests"):
            if self.headers.get("X-Agent-Api-Key") not in (SITE_KEY, HOST_KEY):
                return self._reply(401, {"detail": "Недействительный ключ агента"})
            with open(MANIFESTS, encoding="utf-8") as fh:
                return self._reply(200, json.load(fh))
        self._reply(200, {"status": "ok"})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self._log(body)
        key = self.headers.get("X-Agent-Api-Key")
        if self.path == "/api/agent/enroll":
            if key != SITE_KEY:
                return self._reply(401, {"detail": "Недействительный ключ агента"})
            return self._reply(201, {"host_id": "ci", "hostname": body["hostname"], "key": HOST_KEY})
        if self.path == "/api/ingest":
            if key != HOST_KEY:
                return self._reply(403, {"detail": "Это ключ площадки"})
            return self._reply(200, {"snapshot_id": "ci", "checks": {"total": 0, "passed": 0, "failed": 0, "errors": 0}})
        self._reply(404, {"detail": "Not Found"})


HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
