"""Прогоны: окно, один хост — один снимок, сравнение, права, раскладка уже существующих сканов."""
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest
from alembic.config import Config
from sqlalchemy import create_engine, text

from alembic import command
from app.core.config import settings
from app.services.scan_runs import auto_window, backfill_window, plan_backfill, score_of
from tests.test_ingest_packs import pack_payload, pack_registry  # noqa: F401

engine = create_engine(settings.DATABASE_URL, future=True)

UTC_TZ = ZoneInfo("UTC")
NOV2 = datetime(2026, 11, 2, 10, 0, tzinfo=UTC)
NOV3 = datetime(2026, 11, 3, 18, 0, tzinfo=UTC)
NOV6 = datetime(2026, 11, 6, 12, 0, tzinfo=UTC)


def past_anchor(hours_back=6):
    """Момент внутри уже открытого суточного окна и точно в прошлом.

    Сдвиг «на N часов назад» может перешагнуть 01:00 — границу окна — и разнести
    хосты по двум прогонам. Полдень суток окна этой границы не касается; если он
    ещё впереди, берём время незадолго до сейчас.
    """
    moment = datetime.now(UTC) - timedelta(hours=hours_back)
    start, end = auto_window(moment, "daily", UTC_TZ)
    noon = start + timedelta(hours=12)
    if start <= noon < end and noon <= datetime.now(UTC) - timedelta(minutes=5):
        return noon
    return min(datetime.now(UTC) - timedelta(minutes=20), end - timedelta(minutes=1))


def test_score_matches_fstec_fraction():
    assert score_of(33, 1) == 97.06
    assert score_of(0, 0) is None


def test_daily_window_keeps_the_hour_after_midnight_in_the_previous_run():
    start, end = auto_window(datetime(2026, 11, 8, 15, 0, tzinfo=UTC), "daily", UTC_TZ)
    assert (start, end) == (
        datetime(2026, 11, 8, 0, 0, tzinfo=UTC),
        datetime(2026, 11, 9, 1, 0, tzinfo=UTC),
    )
    # 00:30 следующих суток — хвост RandomDelay, ещё предыдущий прогон
    assert auto_window(datetime(2026, 11, 9, 0, 30, tzinfo=UTC), "daily", UTC_TZ)[0] == start
    # ровно 01:00 — уже новые сутки
    assert auto_window(datetime(2026, 11, 9, 1, 0, tzinfo=UTC), "daily", UTC_TZ)[0] == datetime(2026, 11, 9, tzinfo=UTC)


def test_weekly_window_starts_monday():
    # 4 ноября 2026 — среда, неделя с понедельника 2 ноября
    start, end = auto_window(datetime(2026, 11, 4, 12, 0, tzinfo=UTC), "weekly", UTC_TZ)
    assert start == datetime(2026, 11, 2, tzinfo=UTC)
    assert end == datetime(2026, 11, 9, 1, 0, tzinfo=UTC)
    assert auto_window(datetime(2026, 11, 9, 0, 30, tzinfo=UTC), "weekly", UTC_TZ)[0] == start


def test_backfill_puts_november_2_and_3_into_one_wave_and_keeps_the_latest_per_host():
    """176 отдельных сканов 2–3 ноября (плюс повтор одного хоста) — один прогон; 6 ноября — следующий."""
    rows = []
    first_host = uuid.uuid4()
    start = datetime(2026, 11, 2, 8, 0, tzinfo=UTC)
    for index in range(176):
        rows.append({
            "id": uuid.uuid4(),
            "organization_id": "org",
            "asset_id": first_host if index == 0 else uuid.uuid4(),
            "scan_number": index + 1,
            "ts": start + timedelta(minutes=10 * index),  # до 3 ноября ~13:10, внутри двух суток
        })
    later = {
        "id": uuid.uuid4(), "organization_id": "org", "asset_id": first_host,
        "scan_number": 177, "ts": datetime(2026, 11, 3, 9, 0, tzinfo=UTC),
    }
    rows.append(later)
    rows.append({
        "id": uuid.uuid4(), "organization_id": "org", "asset_id": uuid.uuid4(),
        "scan_number": 178, "ts": NOV6,
    })
    rows.sort(key=lambda row: (row["organization_id"], row["ts"], row["scan_number"]))
    plans = plan_backfill(rows, UTC_TZ, now=datetime(2026, 11, 8, tzinfo=UTC))
    assert [plan["run_number"] for plan in plans] == [1, 2]
    assert later["id"] in plans[0]["member_ids"]
    assert rows[0]["id"] not in plans[0]["member_ids"]  # ранний снимок того же хоста вытеснен
    assert len(plans[0]["member_ids"]) == 176
    assert plans[0]["label"] == "02.11.2026–03.11.2026"
    assert plans[0]["status"] == "closed"
    assert len(plans[1]["member_ids"]) == 1
    # окно волны: полночь 2-го, до 4-го 01:00
    assert backfill_window(NOV2, UTC_TZ) == (
        datetime(2026, 11, 2, tzinfo=UTC), datetime(2026, 11, 4, 1, 0, tzinfo=UTC),
    )
    assert NOV3 < plans[0]["window_ends_at"]
    assert NOV6 >= plans[0]["window_ends_at"]


@pytest.fixture
def org(client, make_org, make_agent_key, make_user, add_membership, auth_header, pack_registry):  # noqa: F811
    org_id = make_org("Run Org")
    key = make_agent_key(org_id)
    admin_id = make_user("run-admin@example.com")
    add_membership(admin_id, org_id, role="admin")
    add_membership(make_user("run-viewer@example.com"), org_id, role="viewer")
    make_user("run-outsider@example.com")
    return {
        "id": org_id,
        "key": key,
        "admin": auth_header("run-admin@example.com"),
        "viewer": auth_header("run-viewer@example.com"),
        "outsider": auth_header("run-outsider@example.com"),
    }


def ingest(client, org, hostname, *, collected_at=None, root="yes", tries="3", environment="prod"):
    results = {
        "ssh.permit_root_login": {"found": True, "value": root, "evidence": f"PermitRootLogin {root}"},
        "ssh.max_auth_tries": {"found": True, "value": tries, "evidence": f"MaxAuthTries {tries}"},
    }
    payload = pack_payload(
        environment=environment,
        asset={"hostname": hostname, "asset_type": "linux-server", "criticality": "high"},
        probe_results=results,
        run_id=str(uuid.uuid4()),
    )
    if collected_at is not None:
        payload["collected_at"] = collected_at.isoformat()
    resp = client.post("/api/ingest", json=payload, headers={"X-Agent-Api-Key": org["key"]})
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_two_hosts_share_one_run_and_a_repeat_keeps_only_the_latest(client, org, db):
    morning = past_anchor()
    first = ingest(client, org, "web-01", collected_at=morning, root="yes")
    second = ingest(client, org, "db-01", collected_at=morning + timedelta(hours=1), root="yes")
    assert first["scan_run_id"] == second["scan_run_id"]
    # повтор того же хоста в том же окне не создаёт вторую строку прогона
    again = ingest(client, org, "web-01", collected_at=morning + timedelta(hours=2), root="no")
    assert again["scan_run_id"] == first["scan_run_id"]
    in_run = db.execute(
        text("SELECT count(*) FROM scan_snapshots WHERE run_id = :run"),
        {"run": first["scan_run_id"]},
    ).scalar()
    assert in_run == 2
    kept = db.execute(
        text("""
            SELECT s.id FROM scan_snapshots s
            JOIN assets a ON a.id = s.asset_id
            WHERE s.run_id = :run AND a.hostname = 'web-01'
        """),
        {"run": first["scan_run_id"]},
    ).scalar()
    assert str(kept) == again["snapshot_id"]
    # ранний снимок не удалён — старая ручка по id жива
    old = client.get(f"/api/organizations/{org['id']}/snapshots?limit=50", headers=org["viewer"])
    assert old.status_code == 200
    assert old.json()["total"] == 3

    hosts = client.get(f"/api/scan-runs/{first['scan_run_id']}/hosts?limit=10", headers=org["viewer"])
    assert hosts.status_code == 200, hosts.text
    body = hosts.json()
    assert body["total"] == 2
    assert {item["hostname"] for item in body["items"]} == {"db-01", "web-01"}
    web = next(item for item in body["items"] if item["hostname"] == "web-01")
    assert web["compliance_score"] == 100.0  # оба pass

    findings = client.get(f"/api/scan-runs/{first['scan_run_id']}/findings", headers=org["viewer"]).json()
    # db-01: root yes → fail. web-01 последний — pass. Одно нарушение, один хост.
    assert findings["total"] == 1
    assert findings["items"][0]["check_key"] == "ssh.permit_root_login"
    assert findings["items"][0]["hosts"] == 1

    detail = client.get(f"/api/scan-runs/{first['scan_run_id']}", headers=org["viewer"]).json()
    # web: 2 pass; db: 1 pass + 1 fail → passed 3, failed 1, 3/4 = 75
    assert detail["hosts"] == 2
    assert detail["compliance_score"] == 75.0


def test_next_day_opens_another_run_and_compare_shows_fixed_and_added_host(client, org):
    today = past_anchor()
    yesterday = today - timedelta(days=2)
    ingest(client, org, "web-01", collected_at=yesterday, root="yes")
    first_id = client.get(f"/api/organizations/{org['id']}/scan-runs", headers=org["viewer"]).json()["items"][-1]["id"]
    ingest(client, org, "web-01", collected_at=today, root="no")
    ingest(client, org, "db-01", collected_at=today + timedelta(minutes=20), root="yes")
    listing = client.get(f"/api/organizations/{org['id']}/scan-runs", headers=org["viewer"]).json()
    assert listing["total"] == 2
    latest, previous = listing["items"][0], listing["items"][1]
    assert latest["hosts"] == 2
    assert previous["hosts"] == 1
    assert previous["id"] == first_id

    compared = client.get(
        f"/api/scan-runs/compare?before_run_id={previous['id']}&after_run_id={latest['id']}",
        headers=org["viewer"],
    )
    assert compared.status_code == 200, compared.text
    body = compared.json()
    assert body["summary"]["fixed"] == 1  # root yes → no на web-01
    assert [host["hostname"] for host in body["hostsAdded"]] == ["db-01"]
    assert body["hostsRemoved"] == []
    assert body["score"]["after"] is not None
    web = next(item for item in body["hosts"]["items"] if item["hostname"] == "web-01")
    assert web["presence"] == "both"
    assert web["summary"]["fixed"] == 1
    added = next(item for item in body["hosts"]["items"] if item["hostname"] == "db-01")
    assert added["presence"] == "added"
    assert added["diffs"] == []  # хост не общий — нарушения не смешиваются с динамикой


def test_older_report_does_not_replace_the_newer_snapshot(client, org, db):
    later = past_anchor()
    earlier = later - timedelta(hours=2)
    first = ingest(client, org, "web-01", collected_at=later, root="no")
    second = ingest(client, org, "web-01", collected_at=earlier, root="yes")
    assert second["scan_run_id"] is None
    kept = db.execute(
        text("SELECT id::text FROM scan_snapshots WHERE run_id = :run"),
        {"run": first["scan_run_id"]},
    ).scalar()
    assert kept == first["snapshot_id"]


def test_manual_run_collects_hosts_until_closed_and_viewer_cannot_open(client, org):
    denied = client.post(f"/api/organizations/{org['id']}/scan-runs", json={"label": "волна"}, headers=org["viewer"])
    assert denied.status_code == 403
    opened = client.post(
        f"/api/organizations/{org['id']}/scan-runs", json={"label": "Волна GPO"}, headers=org["admin"],
    )
    assert opened.status_code == 201, opened.text
    run_id = opened.json()["id"]
    # даже если время сбора попадает в другое автоокно, явный прогон (через параметр приёма интерфейса)
    # проверяем здесь прямым вызовом: агентский ingest без scan_run_id идёт в открытый ручной прогон,
    # потому что он открыт на всю организацию и окно его содержит «сейчас».
    body = ingest(client, org, "pc-01")
    assert body["scan_run_id"] == run_id
    again = client.post(
        f"/api/organizations/{org['id']}/scan-runs", json={"label": "второй"}, headers=org["admin"],
    )
    assert again.status_code == 409

    closed = client.post(f"/api/scan-runs/{run_id}/close", headers=org["admin"])
    assert closed.status_code == 200, closed.text
    assert closed.json()["status"] == "closed"
    assert client.post(f"/api/scan-runs/{run_id}/close", headers=org["admin"]).status_code == 409
    assert client.post(f"/api/scan-runs/{run_id}/close", headers=org["viewer"]).status_code == 403

    nxt = ingest(client, org, "pc-02")
    assert nxt["scan_run_id"] != run_id


def test_environment_scoped_run_does_not_take_other_environments(client, org, db):
    env = db.execute(
        text("SELECT id::text FROM environments WHERE organization_id = :org AND name = 'prod'"),
        {"org": org["id"]},
    ).scalar()
    # окружение появится после первого приёма
    ingest(client, org, "seed-host")
    # закрыть автопрогон, иначе ручной на всю организацию... нам нужен прогон на окружение.
    # автопрогон org-wide открыт. Ручной на окружение — другая область, уникальный индекс это разрешает.
    env = db.execute(
        text("SELECT id::text FROM environments WHERE organization_id = :org AND name = 'prod'"),
        {"org": org["id"]},
    ).scalar()
    opened = client.post(
        f"/api/organizations/{org['id']}/scan-runs",
        json={"label": "только prod", "environment_id": env},
        headers=org["admin"],
    )
    assert opened.status_code == 201, opened.text
    prod = ingest(client, org, "prod-01", environment="prod")
    other = ingest(client, org, "lab-01", environment="lab")
    assert prod["scan_run_id"] == opened.json()["id"]
    assert other["scan_run_id"] != opened.json()["id"]


def test_schedule_weekly_groups_a_week(client, org):
    saved = client.put(
        f"/api/organizations/{org['id']}/scan-schedule",
        json={"schedule": "weekly"},
        headers=org["admin"],
    )
    assert saved.status_code == 200, saved.text
    assert client.put(
        f"/api/organizations/{org['id']}/scan-schedule", json={"schedule": "weekly"}, headers=org["viewer"],
    ).status_code == 403
    now = datetime.now(UTC) - timedelta(hours=3)
    this_start, _ = auto_window(now, "weekly", UTC_TZ)
    earlier = this_start - timedelta(days=2)
    week_start, _ = auto_window(earlier, "weekly", UTC_TZ)
    first = ingest(client, org, "web-01", collected_at=week_start + timedelta(days=1, hours=12))
    second = ingest(client, org, "db-01", collected_at=week_start + timedelta(days=3, hours=12))
    third = ingest(client, org, "web-01", collected_at=now, root="no")
    assert first["scan_run_id"] == second["scan_run_id"]
    assert third["scan_run_id"] != first["scan_run_id"]


def test_outsider_cannot_read_run_or_export(client, org):
    body = ingest(client, org, "web-01")
    run_id = body["scan_run_id"]
    assert client.get(f"/api/scan-runs/{run_id}", headers=org["outsider"]).status_code == 403
    assert client.get(f"/api/organizations/{org['id']}/scan-runs", headers=org["outsider"]).status_code == 403
    assert client.get(f"/api/exports/scan-runs/{run_id}/download?format=excel", headers=org["outsider"]).status_code == 403
    exported = client.get(f"/api/exports/scan-runs/{run_id}/download?format=excel", headers=org["viewer"])
    assert exported.status_code == 200, exported.text
    assert exported.content[:2] == b"PK"
    assert "attachment;" in exported.headers["content-disposition"]
    missing = client.get(f"/api/scan-runs/{uuid.uuid4()}", headers=org["viewer"])
    assert missing.status_code == 404


def test_host_search_and_pagination(client, org):
    moment = past_anchor()
    for index in range(5):
        ingest(client, org, f"pc-{index:02d}", collected_at=moment + timedelta(minutes=index), root="yes" if index < 2 else "no")
    run_id = client.get(f"/api/organizations/{org['id']}/scan-runs", headers=org["viewer"]).json()["items"][0]["id"]
    page = client.get(f"/api/scan-runs/{run_id}/hosts?limit=2&offset=2", headers=org["viewer"])
    assert page.status_code == 200, page.text
    body = page.json()
    assert body["total"] == 5
    assert len(body["items"]) == 2
    assert [item["hostname"] for item in body["items"]] == ["pc-02", "pc-03"]
    found = client.get(f"/api/scan-runs/{run_id}/hosts?q=pc-01", headers=org["viewer"]).json()
    assert [item["hostname"] for item in found["items"]] == ["pc-01"]
    failed = client.get(f"/api/scan-runs/{run_id}/hosts?status=failed", headers=org["viewer"]).json()
    assert {item["hostname"] for item in failed["items"]} == {"pc-00", "pc-01"}


def test_manual_scan_can_target_an_open_run(client, org):
    from app.api.deps import get_pack_registry
    from app.main import app
    from app.services.packs.models import Pack
    from app.services.packs.registry import PackRegistry
    from tests.test_ingest_packs import SSH_PACK
    from tests.test_manual_scans import MANUAL_PACK
    from tests.test_packs import BASE_PACK

    app.dependency_overrides[get_pack_registry] = lambda: PackRegistry([
        Pack.model_validate(MANUAL_PACK), Pack.model_validate(SSH_PACK), Pack.model_validate(BASE_PACK),
    ])
    closed = client.post(f"/api/organizations/{org['id']}/scan-runs", json={"label": "закрытый"}, headers=org["admin"])
    assert closed.status_code == 201, closed.text
    closed_id = closed.json()["id"]
    assert client.post(f"/api/scan-runs/{closed_id}/close", headers=org["admin"]).status_code == 200
    fresh = client.post(f"/api/organizations/{org['id']}/scan-runs", json={"label": "анкета"}, headers=org["admin"])
    assert fresh.status_code == 201, fresh.text
    answers = {"gw.default_password_changed": {"value": True}}
    resp = client.post(
        f"/api/organizations/{org['id']}/manual-scans",
        json={"pack": "gateway-test", "hostname": "manual-01", "answers": answers, "scan_run_id": fresh.json()["id"]},
        headers=org["admin"],
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["scan_run_id"] == fresh.json()["id"]
    refused = client.post(
        f"/api/organizations/{org['id']}/manual-scans",
        json={"pack": "gateway-test", "hostname": "manual-02", "answers": answers, "scan_run_id": closed_id},
        headers=org["admin"],
    )
    assert refused.status_code == 409


def _alembic():
    backend = Path(__file__).resolve().parents[1]
    return Config(str(backend / "alembic.ini"))


def test_migration_groups_existing_snapshots_and_downgrade_keeps_them(db):
    """Снимки без прогона (схема до миграции) после upgrade собираются в волны; downgrade строки не удаляет."""
    db.rollback()
    db.close()
    cfg = _alembic()
    org_id, env_id = str(uuid.uuid4()), str(uuid.uuid4())
    assets = {name: str(uuid.uuid4()) for name in ("a", "b", "c")}
    command.downgrade(cfg, "a1d9c4f27e63")
    try:
        with engine.begin() as conn:
            conn.execute(text("INSERT INTO client_organizations (id, name) VALUES (:id, 'Migration Org')"), {"id": org_id})
            conn.execute(
                text("INSERT INTO environments (id, organization_id, name) VALUES (:id, :org, 'prod')"),
                {"id": env_id, "org": org_id},
            )
            for name, asset_id in assets.items():
                conn.execute(
                    text("INSERT INTO assets (id, environment_id, hostname) VALUES (:id, :env, :name)"),
                    {"id": asset_id, "env": env_id, "name": name},
                )
            snapshots = [
                ("a", NOV2, 1),
                ("b", datetime(2026, 11, 2, 18, 0, tzinfo=UTC), 2),
                ("a", datetime(2026, 11, 3, 9, 0, tzinfo=UTC), 3),  # тот же хост позже — он и останется в прогоне
                ("c", NOV3, 4),
                ("a", NOV6, 5),
            ]
            ids = []
            for name, moment, number in snapshots:
                snapshot_id = str(uuid.uuid4())
                ids.append((snapshot_id, name, number))
                conn.execute(text("""
                    INSERT INTO scan_snapshots (
                        id, organization_id, scan_number, started_at, created_at, status, total_assets, total_software,
                        total_checks, passed, failed
                    ) VALUES (
                        :id, :org, :num, :ts, :ts, 'completed', 1, 0, 2, 1, 1
                    )
                """), {"id": snapshot_id, "org": org_id, "num": number, "ts": moment})
                conn.execute(text("""
                    INSERT INTO scan_check_results (snapshot_id, asset_id, status, check_id, title, severity)
                    VALUES (:sid, :aid, 'fail', 'ssh.permit_root_login', 'root', 'high')
                """), {"sid": snapshot_id, "aid": assets[name]})
        command.upgrade(cfg, "head")
        with engine.begin() as conn:
            runs = conn.execute(text("""
                SELECT run_number, status, label,
                       (SELECT count(*) FROM scan_snapshots s WHERE s.run_id = r.id) AS hosts
                FROM scan_runs r WHERE organization_id = :org ORDER BY run_number
            """), {"org": org_id}).mappings().all()
            assert len(runs) == 2
            assert runs[0]["hosts"] == 3  # a (поздний), b, c
            assert runs[0]["label"] == "02.11.2026–03.11.2026"
            assert runs[1]["hosts"] == 1
            early = conn.execute(text("""
                SELECT run_id FROM scan_snapshots WHERE organization_id = :org AND scan_number = 1
            """), {"org": org_id}).scalar()
            assert early is None  # вытеснен снимком №3, строка на месте
            assert conn.execute(text("SELECT count(*) FROM scan_snapshots WHERE organization_id = :org"), {"org": org_id}).scalar() == 5
            asset_of_latest = conn.execute(text("""
                SELECT asset_id FROM scan_snapshots WHERE organization_id = :org AND scan_number = 3
            """), {"org": org_id}).scalar()
            assert str(asset_of_latest) == assets["a"]
        command.downgrade(cfg, "a1d9c4f27e63")
        with engine.begin() as conn:
            assert conn.execute(text("SELECT count(*) FROM scan_snapshots WHERE organization_id = :org"), {"org": org_id}).scalar() == 5
            assert conn.execute(text("SELECT to_regclass('public.scan_runs')")).scalar() is None
        command.upgrade(cfg, "head")
    finally:
        command.upgrade(cfg, "head")
        with engine.begin() as conn:
            conn.execute(text("DELETE FROM scan_check_results WHERE snapshot_id IN (SELECT id FROM scan_snapshots WHERE organization_id = :org)"), {"org": org_id})
            conn.execute(text("DELETE FROM scan_snapshots WHERE organization_id = :org"), {"org": org_id})
            conn.execute(text("DELETE FROM scan_runs WHERE organization_id = :org"), {"org": org_id})
            conn.execute(text("DELETE FROM assets WHERE environment_id = :env"), {"env": env_id})
            conn.execute(text("DELETE FROM environments WHERE id = :id"), {"id": env_id})
            conn.execute(text("DELETE FROM client_organizations WHERE id = :id"), {"id": org_id})
