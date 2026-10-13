"""Засев стенда сквозных тестов интерфейса (e2e/): очищает тестовую БД и наполняет её тем же путём, что и прод.

Хосты регистрируются по ключу площадки (/api/agent/enroll), отчёты строятся настоящими пробами агента
(agent/probes.py) на образцах pack_tests/ и уходят на /api/ingest ключом хоста — как от живого агента.
Пользователи всех ролей и БДУ — напрямую в БД (суперадмина через API не создать, БДУ грузится командой).

Запуск — из global-setup.js:  cd src/backend && DATABASE_URL=… python ../../e2e/seed.py <out.json>
Только для одноразовой БД: всё в ней стирается.
"""
import json
import os
import sys
import tempfile
import uuid
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src" / "backend"))

DB_URL = os.environ.get("DATABASE_URL", "")
if not DB_URL or ":5432/" in DB_URL or "diploma_db" in DB_URL:
    raise SystemExit(f"seed.py стирает БД — нужен одноразовый PostgreSQL, а не {DB_URL or '(DATABASE_URL не задан)'}")
os.environ.setdefault("JWT_SECRET_KEY", "e2e-secret-key")
os.environ.setdefault("TOTP_SECRET_ENCRYPTION_KEY", "e2e-totp-encryption-key")
os.environ.setdefault("PACK_SIGNING_KEY", "e2e-pack-signing-key")
os.environ["REQUIRE_2FA"] = "false"

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import text  # noqa: E402

from app.core.security import hash_password  # noqa: E402
from app.db.session import SessionLocal  # noqa: E402
from app.main import app  # noqa: E402
from app.services.bdu.importer import import_bdu  # noqa: E402
from app.services.packs.authoring import FixtureHost, _merge, load_agent_probes  # noqa: E402
from app.services.packs.manifest import build_manifest  # noqa: E402
from app.services.packs.registry import load_registry  # noqa: E402

BACKEND = Path(__file__).resolve().parents[1] / "src" / "backend"
PASSWORD = "E2e-password-123"
USERS = {
    "super": "super@e2e.example.com",
    "admin": "admin@e2e.example.com",
    "auditor": "auditor@e2e.example.com",
    "viewer": "viewer@e2e.example.com",
    "beta": "beta-admin@e2e.example.com",
}
ORG_MAIN, ORG_OTHER = "ООО «Альфа»", "ООО «Бета»"

# Сценарий «до → после» для web-01 и по одному снимку остальных хостов: (хост, часов назад, [(образцы, случай)]).
# Порядок — хронологический, как пришли бы отчёты: отчёт организации пересчитывается при каждом приёме.
# db-01: ubuntu-server «нет файлов» — все проверки ОС «не проверено» (покрытие < 100 %).
SCANS = [
    ("web-01", 144, [("ubuntu-server", 1), ("docker", 1)]),
    ("web-01", 72, [("ubuntu-server", 3), ("docker", 2)]),
    ("web-01", 24, [("ubuntu-server", 0), ("docker", 0)]),
    ("db-01", 20, [("ubuntu-server", 5), ("postgresql", 1)]),
    ("win-srv-01", 2, [("windows-server", 1)]),
]
HOST_META = {
    "web-01": {"ip_address": "10.10.0.11", "os": "Ubuntu 24.04", "asset_type": "linux-server", "criticality": "critical",
               "tags": ["linux-server", "debian-family", "ubuntu", "docker"]},
    "db-01": {"ip_address": "10.10.0.12", "os": "Ubuntu 24.04", "asset_type": "linux-server", "criticality": "high",
              "tags": ["linux-server", "debian-family", "ubuntu", "postgresql"]},
    "win-srv-01": {"ip_address": "10.10.0.21", "os": "Windows Server 2022", "asset_type": "windows-server",
                   "criticality": "medium", "tags": ["windows", "windows-server"]},
}
SOFTWARE = [
    {"name": "openssh-server", "version": "1:9.6p1-3ubuntu13.19"},
    {"name": "openssh-client", "version": "1:9.6p1-3ubuntu13.19"},
    {"name": "bash", "version": "5.2.21-2ubuntu4"},
    {"name": "docker-ce", "version": "5:27.3.1-1~ubuntu.24.04~noble"},
]
BDU_XML = """<?xml version="1.0" encoding="UTF-8"?>
<vulnerabilities>
 <vul><identifier>BDU:2024-04914</identifier>
  <name>Уязвимость OpenSSH, позволяющая нарушителю выполнить произвольный код</name>
  <vulnerable_software><soft><name>OpenSSH</name><vendor>The OpenBSD Project</vendor><version>от 8.6 до 9.8</version></soft></vulnerable_software>
  <cvss3><vector score="8,1">AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H</vector></cvss3>
  <publication_date>01.07.2024</publication_date><exploit_status>Существует</exploit_status>
  <fix_status>Уязвимость устранена</fix_status><solution>Обновить OpenSSH</solution>
  <identifiers><identifier type="CVE" link="x">CVE-2024-6387</identifier></identifiers>
 </vul>
 <vul><identifier>BDU:2019-00001</identifier>
  <name>Уязвимость OpenSSH, позволяющая нарушителю вызвать отказ в обслуживании</name>
  <vulnerable_software><soft><name>OpenSSH</name><vendor>The OpenBSD Project</vendor><version>до 7.4</version></soft></vulnerable_software>
  <cvss3><vector score="5.3">AV:N</vector></cvss3>
 </vul>
</vulnerabilities>
"""


def truncate(db):
    tables = db.execute(text(
        "SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename NOT IN ('alembic_version', 'hardening_rules')"
    )).scalars().all()
    db.execute(text(f"TRUNCATE TABLE {', '.join(tables)} CASCADE"))
    db.commit()


def add_user(db, email, superadmin=False):
    user_id = str(uuid.uuid4())
    db.execute(text(
        "INSERT INTO users (id, email, password_hash, display_name, full_name, is_active, is_superadmin, account_status)"
        " VALUES (:id, :email, :hash, :name, :name, true, :su, 'active')"
    ), {"id": user_id, "email": email, "hash": hash_password(PASSWORD), "name": email.split("@")[0], "su": superadmin})
    return user_id


def probe_results(agent, registry, fixture, case_index):
    spec = yaml.safe_load((BACKEND / "pack_tests" / f"{fixture}.yaml").read_text(encoding="utf-8"))
    pack = registry.get(spec["pack"], spec.get("version"))
    host = FixtureHost(agent, pack.transport, **_merge(spec.get("base") or {}, spec["cases"][case_index]))
    raw = agent.run_manifest(host, build_manifest(pack))
    return {"id": pack.pack, "version": pack.version, "probe_results": raw}


def main(out_path: str):
    db = SessionLocal()
    truncate(db)
    ids = {role: add_user(db, email, superadmin=(role == "super")) for role, email in USERS.items()}
    db.commit()

    client = TestClient(app)
    def login(role):
        resp = client.post("/api/auth/login", json={"email": USERS[role], "password": PASSWORD})
        resp.raise_for_status()
        return {"Authorization": f"Bearer {resp.json()['access_token']}"}

    su = login("super")
    orgs = {}
    for name in (ORG_MAIN, ORG_OTHER):
        resp = client.post("/api/admin/organizations", json={"name": name}, headers=su)
        resp.raise_for_status()
        orgs[name] = resp.json()["id"]
    main_org = orgs[ORG_MAIN]
    for role in ("admin", "auditor", "viewer"):
        client.post(f"/api/organizations/{main_org}/users", json={"email": USERS[role], "role": role}, headers=su).raise_for_status()
    client.post(f"/api/organizations/{orgs[ORG_OTHER]}/users", json={"email": USERS["beta"], "role": "admin"}, headers=su).raise_for_status()

    admin = login("admin")
    site = client.post(f"/api/organizations/{main_org}/agent-keys", json={"name": "Головной офис"}, headers=admin)
    site.raise_for_status()
    site_key = site.json()["key"]

    agent, registry = load_agent_probes(), load_registry(BACKEND / "app" / "packs")
    host_keys = {}
    now = datetime.now(UTC)
    for hostname, hours_ago, runs in SCANS:
        meta = HOST_META[hostname]
        if hostname not in host_keys:
            resp = client.post("/api/agent/enroll", json={"hostname": hostname, "os": meta["os"]}, headers={"X-Agent-Api-Key": site_key})
            resp.raise_for_status()
            host_keys[hostname] = resp.json()["key"]
        payload = {
            "environment": "prod",
            "asset": {"hostname": hostname, **{k: meta[k] for k in ("ip_address", "os", "asset_type", "criticality")}},
            "software": SOFTWARE if meta["asset_type"] == "linux-server" else [],
            "platform_tags": meta["tags"],
            "packs": [probe_results(agent, registry, fixture, case) for fixture, case in runs],
            "scan_label": f"e2e {hostname} −{hours_ago} ч",
            "run_id": str(uuid.uuid4()),
            "collected_at": (now - timedelta(hours=hours_ago)).isoformat(),
        }
        resp = client.post("/api/ingest", json=payload, headers={"X-Agent-Api-Key": host_keys[hostname]})
        if resp.status_code != 200:
            raise SystemExit(f"ingest {hostname}: {resp.status_code} {resp.text}")

    with tempfile.TemporaryDirectory() as tmp:
        archive = Path(tmp) / "vulxml.zip"
        with zipfile.ZipFile(archive, "w") as z:
            z.writestr("export/vulxml.xml", BDU_XML)
        import_bdu(db, archive)
    db.commit()
    db.close()

    Path(out_path).write_text(json.dumps({
        "password": PASSWORD, "users": USERS, "user_ids": ids,
        "orgs": {"main": {"id": main_org, "name": ORG_MAIN}, "other": {"id": orgs[ORG_OTHER], "name": ORG_OTHER}},
        "site_key": site_key, "hosts": sorted(host_keys),
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"seed: {len(SCANS)} снимков, хосты {', '.join(sorted(host_keys))}")


if __name__ == "__main__":
    main(sys.argv[1])
