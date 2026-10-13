"""Нагрузочный тест интерфейса: как быстро открываются страницы организации на тысяче хостов.

Приём отчётов от 1000 хостов проверен отдельно (заметка «Агент на 1000+ хостов»); здесь — обратная
сторона: API, которые вызывают страницы («Обзор», «Активы», «ПО», «Харденинг», «Уязвимости ПО»,
«Методика ФСТЭК», «Сканирования», «Отчёты», «Агенты»), на данных такого объёма.

  1. populate — засев в ОДНОРАЗОВУЮ БД: N хостов регистрируются ключом площадки, каждый присылает
     несколько отчётов (по одному в день). ПО — как на хосте, где запущен засев (dpkg/rpm, ~1500
     пакетов) с вариацией версий; проверки — настоящими пробами агента на образцах pack_tests/.
     Копию БДУ и данные Ubuntu загрузить заранее (python -m app.commands.bdu import / oval).
  2. measure — запросы к запущенному бэкенду (как в проде: uvicorn, WEB_CONCURRENCY=2), время
     (медиана из нескольких) и размер ответа по каждому API.

  cd src/backend && DATABASE_URL=… python ../../tools/loadtest/ui_load.py populate --hosts 1000 --days 3
  python ../../tools/loadtest/ui_load.py measure --url http://127.0.0.1:8013 --state /tmp/load.json
"""
import argparse
import json
import os
import random
import statistics
import subprocess
import sys
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[2] / "src" / "backend"
sys.path.insert(0, str(BACKEND))
PASSWORD = "Load-test-password-1"


def installed_packages() -> list[tuple[str, str]]:
    for cmd in (["dpkg-query", "-W", "-f=${Package}\t${Version}\n"], ["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"]):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
        except (OSError, subprocess.CalledProcessError):
            continue
        return [tuple(line.split("\t", 1)) for line in out.splitlines() if "\t" in line]
    raise SystemExit("нет ни dpkg, ни rpm — нечем взять реалистичный список ПО")


def populate(args) -> None:
    url = os.environ.get("DATABASE_URL", "")
    if not url or ":5432/" in url or "diploma_db" in url:
        raise SystemExit(f"populate стирает БД — нужен одноразовый PostgreSQL, а не {url or '(DATABASE_URL не задан)'}")
    os.environ.setdefault("JWT_SECRET_KEY", "load-secret")
    os.environ.setdefault("TOTP_SECRET_ENCRYPTION_KEY", "load-totp")
    os.environ.setdefault("PACK_SIGNING_KEY", "load-pack")
    os.environ["REQUIRE_2FA"] = "false"

    import yaml
    from fastapi.testclient import TestClient
    from sqlalchemy import text

    from app.core.security import hash_password
    from app.db.session import SessionLocal
    from app.main import app
    from app.services.packs.authoring import FIXTURES_DIR, PACKS_DIR, FixtureHost, _merge, load_agent_probes
    from app.services.packs.manifest import build_manifest
    from app.services.packs.registry import load_registry

    db = SessionLocal()
    keep = ("alembic_version", "hardening_rules", "bdu_vulnerabilities", "bdu_software", "bdu_imports",
            "distro_cve_status", "distro_oval_imports")
    tables = db.execute(text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")).scalars().all()
    db.execute(text(f"TRUNCATE TABLE {', '.join(t for t in tables if t not in keep)} CASCADE"))
    db.execute(text(
        "INSERT INTO users (id, email, password_hash, is_active, is_superadmin, account_status)"
        " VALUES (:id, 'load@example.com', :hash, true, true, 'active')"
    ), {"id": str(uuid.uuid4()), "hash": hash_password(PASSWORD)})
    db.commit()

    client = TestClient(app)
    token = client.post("/api/auth/login", json={"email": "load@example.com", "password": PASSWORD}).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    org = client.post("/api/admin/organizations", json={"name": "Нагрузка 1000"}, headers=headers).json()["id"]
    site_key = client.post(f"/api/organizations/{org}/agent-keys", json={"name": "ЦОД"}, headers=headers).json()["key"]

    agent, registry = load_agent_probes(), load_registry(PACKS_DIR)

    def variants(fixture: str) -> list[dict]:
        spec = yaml.safe_load((FIXTURES_DIR / f"{fixture}.yaml").read_text(encoding="utf-8"))
        pack = registry.get(spec["pack"], spec.get("version"))
        out = []
        for case in spec["cases"]:
            host = FixtureHost(agent, pack.transport, **_merge(spec.get("base") or {}, case))
            if "detect" in case and not agent.matches_detect(host, build_manifest(pack)["detect"]):
                continue
            out.append({"id": pack.pack, "version": pack.version, "probe_results": agent.run_manifest(host, build_manifest(pack))})
        return out

    ubuntu, docker = variants("ubuntu-server"), variants("docker")
    packages = installed_packages()
    rng = random.Random(42)
    now = datetime.now(UTC)
    started = time.monotonic()
    for i in range(1, args.hosts + 1):
        hostname = f"host-{i:04d}"
        key = client.post("/api/agent/enroll", json={"hostname": hostname, "os": "Ubuntu 24.04.1 LTS"},
                          headers={"X-Agent-Api-Key": site_key}).json()["key"]
        # у части хостов — старые версии части пакетов: находки БДУ различаются
        software = [{"name": n, "version": v if rng.random() > 0.05 else v.replace(".", ".0", 1)} for n, v in packages]
        for day in range(args.days, 0, -1):
            packs = [rng.choice(ubuntu)] + ([rng.choice(docker)] if i % 3 == 0 else [])
            resp = client.post("/api/ingest", headers={"X-Agent-Api-Key": key}, json={
                "environment": "prod" if i % 10 else "test",
                "asset": {"hostname": hostname, "ip_address": f"10.{i // 250}.{i % 250}.10", "os": "Ubuntu 24.04.1 LTS",
                          "asset_type": "linux-server", "criticality": rng.choice(["low", "medium", "high", "critical"])},
                "software": software, "platform_tags": ["linux-server", "debian-family", "ubuntu"],
                "packs": packs, "run_id": str(uuid.uuid4()),
                "collected_at": (now - timedelta(days=day - 1, minutes=rng.randint(0, 600))).isoformat(),
            })
            if resp.status_code != 200:
                raise SystemExit(f"{hostname}: {resp.status_code} {resp.text[:300]}")
        if i % 50 == 0:
            rate = i / (time.monotonic() - started)
            print(f"{i}/{args.hosts} хостов, {rate:.1f} хост/с", flush=True)
    Path(args.state).write_text(json.dumps({"org": org, "email": "load@example.com", "password": PASSWORD}), encoding="utf-8")
    print(f"готово: {args.hosts} хостов × {args.days} отчёта за {time.monotonic() - started:.0f} с; {args.state}")


def measure(args) -> None:
    import httpx

    state = json.loads(Path(args.state).read_text(encoding="utf-8"))
    org = state["org"]
    with httpx.Client(base_url=args.url, timeout=300) as client:
        token = client.post("/api/auth/login", json={"email": state["email"], "password": state["password"]}).json()["access_token"]
        client.headers["Authorization"] = f"Bearer {token}"
        snapshot = client.get(f"/api/organizations/{org}/snapshots", params={"limit": 1}).json()["items"][0]
        asset = client.get(f"/api/organizations/{org}/assets").json()[0]["id"]
        cases = [
            ("Обзор: сводка", f"/api/organizations/{org}/dashboard"),
            ("Обзор: динамика по дням", f"/api/organizations/{org}/reports?daily=true&limit=30"),
            ("Активы", f"/api/organizations/{org}/assets"),
            ("Карточка актива", f"/api/assets/{asset}"),
            ("ПО: первая страница", f"/api/organizations/{org}/software"),
            ("ПО: поиск openssl", f"/api/organizations/{org}/software?q=openssl"),
            ("ПО: хост", f"/api/organizations/{org}/software?host=host-0500"),
            ("ПО: сортировка по версии", f"/api/organizations/{org}/software?sort=version&dir=desc"),
            ("Харденинг: первая страница", f"/api/organizations/{org}/hardening"),
            ("Харденинг: нарушения", f"/api/organizations/{org}/hardening?status=fail"),
            ("Харденинг: поиск", f"/api/organizations/{org}/hardening?q=ssh"),
            ("Отчёты: план (сводка)", f"/api/organizations/{org}/hardening?limit=1"),
            ("Отчёты: история по дням", f"/api/organizations/{org}/reports?daily=true&limit=90"),
            ("Сканирования: страница", f"/api/organizations/{org}/snapshots"),
            ("Сканирования: хост", f"/api/organizations/{org}/snapshots?host=host-0500"),
            ("Сравнение: список для выбора", f"/api/organizations/{org}/snapshots?limit=200"),
            ("Сравнение сканов", f"/api/snapshots/compare?before_snapshot_id={snapshot['previous_snapshot_id']}&after_snapshot_id={snapshot['id']}"),
            ("Уязвимости ПО", f"/api/organizations/{org}/vulnerabilities"),
            ("Методика ФСТЭК", f"/api/organizations/{org}/fstec-coverage"),
            ("Агенты: ключи и хосты", f"/api/organizations/{org}/agent-keys"),
            ("Агенты: охват", f"/api/organizations/{org}/coverage"),
            ("Экспорт PDF скана", f"/api/exports/snapshots/{snapshot['id']}/download?format=pdf"),
            ("Экспорт Excel скана", f"/api/exports/snapshots/{snapshot['id']}/download?format=excel"),
        ]
        print(f"{'страница / API':38} {'медиана, с':>10} {'макс, с':>8} {'ответ':>10}")
        slow = []
        for title, path in cases:
            times, size, status = [], 0, None
            for _ in range(args.repeat):
                started = time.perf_counter()
                resp = client.get(path)
                times.append(time.perf_counter() - started)
                size, status = len(resp.content), resp.status_code
            median = statistics.median(times)
            mark = "" if status == 200 else f"  HTTP {status}"
            print(f"{title:38} {median:10.2f} {max(times):8.2f} {size / 1024:8.0f} КБ{mark}")
            if median > args.budget or status != 200:
                slow.append(title)
        if slow:
            print(f"\nдольше {args.budget} с или с ошибкой: {', '.join(slow)}")
            raise SystemExit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("populate")
    p.add_argument("--hosts", type=int, default=1000)
    p.add_argument("--days", type=int, default=3, help="отчётов на хост (по одному в день)")
    p.add_argument("--state", default="/tmp/hardening-load.json")
    p.set_defaults(func=populate)
    m = sub.add_parser("measure")
    m.add_argument("--url", required=True)
    m.add_argument("--state", default="/tmp/hardening-load.json")
    m.add_argument("--repeat", type=int, default=3)
    m.add_argument("--budget", type=float, default=2.0, help="допустимая медиана, с")
    m.set_defaults(func=measure)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
