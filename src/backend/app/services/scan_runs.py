"""Прогон организации: одно окно, много хостов, у каждого хоста последний снимок.

Автопрогон совпадает с расписанием агента. Ежедневно (дефолт, как hardening-agent@.timer
и задача Windows без -Schedule Weekly): локальные сутки DISPLAY_TIMEZONE плюс час
RandomDelay. Снимок в первый час после полуночи остаётся в прогоне предыдущих суток —
это хвост RandomizedDelaySec / RandomDelay, который может перешагнуть полночь.
Еженедельно: с понедельника 00:00, длина 7 суток + тот же час.

Ручной прогон открывает администратор. Пока он открыт, снимки его области (вся
организация или одно окружение) идут в него, а не в автоокно. Отдельной «группы хостов»
в модели нет: граница — окружение. Автопрогон всегда на всю организацию, чтобы волна
GPO не разъехалась по окружениям.

Окно, которое уже кончилось, закрывается при следующем приёме или при чтении списка.
Своего планировщика у сервера нет (глава 20). Опоздавший отчёт, чей collected_at ещё
внутри окна, дописывается в тот прогон, даже если окно уже закрыто: прогон заново не
открывается. Более ранний снимок того же хоста из прогона выходит (run_id становится
пустым), строка снимка остаётся.

Тяжёлые агрегаты при приёме не считаются. Оценка прогона — та же дробь, что
compute_compliance_score, но по суммам passed/failed уже записанных снимков.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.routes.snapshots import classify
from app.core.config import settings
from app.models.scan_run import ScanRun
from app.models.scan_snapshot import ScanSnapshot

RANDOM_DELAY = timedelta(hours=1)
BACKFILL_DAYS = 2  # уже накопленные снимки: двое суток + час, чтобы 2–3 ноября стали одним прогоном
SCHEDULES = ("daily", "weekly")
HOST_STATUSES = ("", "failed", "clean", "unchecked")

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class ScanRunError(Exception):
    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(detail)


def display_zone() -> ZoneInfo:
    return ZoneInfo(settings.DISPLAY_TIMEZONE)


def _aware(moment: datetime) -> datetime:
    if moment.tzinfo is None:
        return moment.replace(tzinfo=UTC)
    return moment


def score_of(passed: int, failed: int) -> float | None:
    """Процент методики: соблюдено / (соблюдено + нарушено без принятого риска)."""
    scoreable = passed + failed
    return round(passed / scoreable * 100, 2) if scoreable else None


def auto_window(moment: datetime, schedule: str, tz: ZoneInfo | None = None) -> tuple[datetime, datetime]:
    """Полуинтервал [начало, конец) автопрогона, в который попадает moment."""
    tz = tz or display_zone()
    local = _aware(moment).astimezone(tz)
    shifted = local - RANDOM_DELAY  # [00:00, 01:00) относится к предыдущему окну
    if schedule == "weekly":
        start = (shifted - timedelta(days=shifted.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
        end = start + timedelta(days=7) + RANDOM_DELAY
    else:
        start = shifted.replace(hour=0, minute=0, second=0, microsecond=0)
        end = start + timedelta(days=1) + RANDOM_DELAY
    return start.astimezone(UTC), end.astimezone(UTC)


def backfill_window(first: datetime, tz: ZoneInfo | None = None) -> tuple[datetime, datetime]:
    """Окно уже накопленной волны: полночь суток первого снимка, двое суток и час RandomDelay.

    Первый снимок 2 ноября в любой час даёт окно до 4 ноября 01:00 по тому же поясу,
    то есть и 2, и 3 ноября. Следующая волна начинается со снимка за границей окна.
    """
    tz = tz or display_zone()
    local = _aware(first).astimezone(tz)
    start = local.replace(hour=0, minute=0, second=0, microsecond=0)
    end = start + timedelta(days=BACKFILL_DAYS) + RANDOM_DELAY
    return start.astimezone(UTC), end.astimezone(UTC)


def auto_label(start: datetime, schedule: str, tz: ZoneInfo) -> str:
    local = start.astimezone(tz)
    if schedule == "weekly":
        return f"Неделя {local.strftime('%G')}-W{local.strftime('%V')}"
    return f"Сутки {local.strftime('%Y-%m-%d')}"


def backfill_label(start: datetime, tz: ZoneInfo) -> str:
    d0 = start.astimezone(tz).date()
    d1 = d0 + timedelta(days=BACKFILL_DAYS - 1)
    return f"{d0.strftime('%d.%m.%Y')}–{d1.strftime('%d.%m.%Y')}"


def plan_backfill(rows: list, tz: ZoneInfo, now: datetime | None = None) -> list[dict]:
    """Разложить уже существующие снимки по волнам. rows отсортированы по организации, времени, номеру.

    В прогон входит последний снимок каждого актива. Более ранний снимок того же актива
    в ту же волну не входит — строка в таблице остаётся, run_id у неё пустой.
    """
    now = _aware(now or datetime.now(UTC))
    plans: list[dict] = []
    current_org = None
    number = 0
    wave: dict | None = None

    def seal() -> None:
        if wave is None or "members" not in wave:
            return
        wave["member_ids"].extend(item[2] for item in wave.pop("members").values())

    for row in rows:
        org = row["organization_id"]
        if org != current_org:
            seal()
            current_org = org
            number = 0
            wave = None
        ts = row["ts"] or now
        ts = _aware(ts)
        scan_number = row["scan_number"] or 0
        if wave is None or ts >= wave["window_ends_at"]:
            seal()
            number += 1
            start, end = backfill_window(ts, tz)
            wave = {
                "organization_id": org,
                "run_number": number,
                "opened_at": start,
                "window_ends_at": end,
                "status": "closed" if end <= now else "open",
                "closed_at": end if end <= now else None,
                "label": backfill_label(start, tz),
                "members": {},
                "member_ids": [],
            }
            plans.append(wave)
        asset = row["asset_id"]
        if asset is None:
            wave["member_ids"].append(row["id"])
            continue
        previous = wave["members"].get(asset)
        if previous is None or (ts, scan_number) >= (previous[0], previous[1]):
            wave["members"][asset] = (ts, scan_number, row["id"])
    seal()
    return plans


def org_schedule(db: Session, organization_id: str) -> str:
    schedule = db.execute(
        text("SELECT schedule FROM organization_scan_settings WHERE organization_id = :org"),
        {"org": organization_id},
    ).scalar()
    return schedule if schedule in SCHEDULES else "daily"


def set_org_schedule(db: Session, organization_id: str, schedule: str) -> str:
    if schedule not in SCHEDULES:
        raise ScanRunError(422, "Расписание: daily или weekly")
    db.execute(
        text("""
            INSERT INTO organization_scan_settings (organization_id, schedule)
            VALUES (:org, :schedule)
            ON CONFLICT (organization_id) DO UPDATE SET schedule = EXCLUDED.schedule
        """),
        {"org": organization_id, "schedule": schedule},
    )
    db.commit()
    return schedule


def close_expired(db: Session, organization_id: str, now: datetime | None = None) -> None:
    """Закрыть автоокна, у которых вышло время. Вызывается при приёме и при чтении, не по cron."""
    now = _aware(now or datetime.now(UTC))
    db.execute(
        text("""
            UPDATE scan_runs
            SET status = 'closed', closed_at = window_ends_at
            WHERE organization_id = :org AND status = 'open'
              AND window_ends_at IS NOT NULL AND window_ends_at <= :now
        """),
        {"org": organization_id, "now": now},
    )


def _lock_runs(db: Session, organization_id: str) -> None:
    db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:key))"), {"key": f"scan_run:{organization_id}"})


def _next_number(db: Session, organization_id: str) -> int:
    return db.execute(
        text("SELECT COALESCE(MAX(run_number), 0) + 1 FROM scan_runs WHERE organization_id = :org"),
        {"org": organization_id},
    ).scalar() or 1


def _open_for_scope(db: Session, organization_id: str, environment_id: str | None) -> ScanRun | None:
    query = db.query(ScanRun).filter(ScanRun.organization_id == organization_id, ScanRun.status == "open")
    if environment_id is None:
        query = query.filter(ScanRun.environment_id.is_(None))
    else:
        query = query.filter(ScanRun.environment_id == environment_id)
    return query.order_by(ScanRun.run_number.desc()).first()


def open_manual_run(
    db: Session,
    organization_id: str,
    *,
    user_id: str | None,
    label: str | None = None,
    environment_id: str | None = None,
    closes_at: datetime | None = None,
) -> ScanRun:
    """Открыть ручной прогон. Пока он открыт, новый автопрогон той же области не создаётся."""
    now = datetime.now(UTC)
    if closes_at is not None:
        closes_at = _aware(closes_at)
        if closes_at <= now:
            raise ScanRunError(422, "Момент закрытия должен быть в будущем")
    if environment_id is not None:
        env_org = db.execute(
            text("SELECT organization_id FROM environments WHERE id = :id"),
            {"id": environment_id},
        ).scalar()
        if env_org is None or str(env_org) != str(organization_id):
            raise ScanRunError(422, "Окружение не найдено в этой организации")
    _lock_runs(db, organization_id)
    close_expired(db, organization_id, now)
    existing = _open_for_scope(db, organization_id, environment_id)
    if existing is not None:
        raise ScanRunError(409, f"Уже открыт прогон №{existing.run_number}. Закройте его, чтобы открыть новый")
    run = ScanRun(
        organization_id=organization_id,
        environment_id=environment_id,
        run_number=_next_number(db, organization_id),
        status="open",
        source="manual",
        schedule="manual",
        label=(label or "").strip() or None,
        opened_at=now,
        window_ends_at=closes_at,
        opened_by=user_id,
        created_at=now,
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def close_run(db: Session, run: ScanRun, *, user_id: str | None) -> ScanRun:
    if run.status != "open":
        raise ScanRunError(409, "Прогон уже закрыт")
    now = datetime.now(UTC)
    run.status = "closed"
    run.closed_at = now
    run.closed_by = user_id
    db.commit()
    db.refresh(run)
    return run


def _find_open_target(
    db: Session, organization_id: str, environment_id: str | None, collected_at: datetime,
) -> ScanRun | None:
    """Открытый прогон, в чьё окно попадает время сбора. Сначала ручной и более узкий (окружение)."""
    rows = db.execute(
        text("""
            SELECT id FROM scan_runs
            WHERE organization_id = :org AND status = 'open'
              AND (environment_id IS NULL OR environment_id = :env)
              AND opened_at <= :ts
              AND (window_ends_at IS NULL OR :ts < window_ends_at)
            ORDER BY (source = 'manual') DESC, (environment_id IS NOT NULL) DESC, run_number DESC
            LIMIT 1
        """),
        {"org": organization_id, "env": environment_id, "ts": collected_at},
    ).first()
    return db.get(ScanRun, rows[0]) if rows else None


def _find_window_run(db: Session, organization_id: str, start: datetime, end: datetime) -> ScanRun | None:
    return (
        db.query(ScanRun)
        .filter(
            ScanRun.organization_id == organization_id,
            ScanRun.environment_id.is_(None),
            ScanRun.source == "auto",
            ScanRun.opened_at == start,
            ScanRun.window_ends_at == end,
        )
        .order_by(ScanRun.run_number.desc())
        .first()
    )


def _create_auto_run(
    db: Session, organization_id: str, schedule: str, start: datetime, end: datetime, now: datetime,
) -> ScanRun:
    closed = end <= now
    run = ScanRun(
        organization_id=organization_id,
        environment_id=None,
        run_number=_next_number(db, organization_id),
        status="closed" if closed else "open",
        source="auto",
        schedule=schedule if schedule in SCHEDULES else "daily",
        label=auto_label(start, schedule, display_zone()),
        opened_at=start,
        window_ends_at=end,
        closed_at=end if closed else None,
        created_at=now,
    )
    db.add(run)
    try:
        with db.begin_nested():
            db.flush()
    except IntegrityError:
        # Параллельный приём этой же организации уже открыл окно (уникальный индекс открытого прогона).
        found = _find_window_run(db, organization_id, start, end) or _open_for_scope(db, organization_id, None)
        if found is None:
            raise
        return found
    return run


def _place_snapshot(db: Session, snapshot: ScanSnapshot, run: ScanRun, asset_id: str | None, collected_at: datetime) -> None:
    """Один хост — один снимок прогона: остаётся тот, что собран позже."""
    snapshot.asset_id = uuid.UUID(str(asset_id)) if asset_id else snapshot.asset_id
    if asset_id is None:
        snapshot.run_id = run.id
        return
    current = db.execute(
        text("""
            SELECT id, COALESCE(started_at, created_at) AS ts
            FROM scan_snapshots
            WHERE run_id = :run AND asset_id = :asset AND id <> :sid
        """),
        {"run": run.id, "asset": asset_id, "sid": snapshot.id},
    ).mappings().first()
    if current is not None:
        current_ts = _aware(current["ts"]) if current["ts"] else datetime.min.replace(tzinfo=UTC)
        if collected_at < current_ts:
            snapshot.run_id = None
            return
        previous = db.get(ScanSnapshot, current["id"])
        if previous is not None:
            previous.run_id = None
            db.flush()
    snapshot.run_id = run.id
    try:
        with db.begin_nested():
            db.flush()
    except IntegrityError:
        # Второй отчёт того же хоста успел занять место в прогоне.
        winner = db.execute(
            text("""
                SELECT id, COALESCE(started_at, created_at) AS ts
                FROM scan_snapshots
                WHERE run_id = :run AND asset_id = :asset AND id <> :sid
            """),
            {"run": run.id, "asset": asset_id, "sid": snapshot.id},
        ).mappings().first()
        snapshot.run_id = None
        if winner is None:
            snapshot.run_id = run.id
            db.flush()
            return
        winner_ts = _aware(winner["ts"]) if winner["ts"] else datetime.min.replace(tzinfo=UTC)
        if collected_at >= winner_ts:
            previous = db.get(ScanSnapshot, winner["id"])
            if previous is not None:
                previous.run_id = None
            db.flush()
            snapshot.run_id = run.id
            db.flush()


def attach_snapshot(
    db: Session,
    *,
    organization_id: str,
    environment_id: str | None,
    asset_id: str | None,
    collected_at: datetime,
    snapshot: ScanSnapshot,
    scan_run_id: str | None = None,
) -> ScanRun:
    """Положить снимок в прогон. Вызывается из той же транзакции, что и приём, до commit."""
    collected_at = _aware(collected_at)
    now = datetime.now(UTC)
    _lock_runs(db, organization_id)
    close_expired(db, organization_id, now)

    if scan_run_id:
        run = db.get(ScanRun, scan_run_id)
        if run is None or str(run.organization_id) != str(organization_id):
            raise ScanRunError(404, "Прогон не найден")
        if run.status != "open":
            raise ScanRunError(409, "Прогон закрыт: выберите открытый или оставьте автоокно")
        if run.environment_id is not None and str(run.environment_id) != str(environment_id):
            raise ScanRunError(409, "Прогон ограничен другим окружением")
        if run.window_ends_at is not None and collected_at >= run.window_ends_at:
            raise ScanRunError(409, "Окно прогона уже закончилось")
        # Явный выбор прогона (выгрузка, опрос, файл) кладёт снимок в него, даже если collected_at
        # раньше момента открытия: администратор так и попросил.
        _place_snapshot(db, snapshot, run, asset_id, collected_at)
        return run

    run = _find_open_target(db, organization_id, environment_id, collected_at)
    if run is None:
        schedule = org_schedule(db, organization_id)
        start, end = auto_window(collected_at, schedule)
        run = _find_window_run(db, organization_id, start, end)
        if run is None:
            run = _create_auto_run(db, organization_id, schedule, start, end, now)
    _place_snapshot(db, snapshot, run, asset_id, collected_at)
    return run


def load_run(db: Session, run_id: str) -> ScanRun | None:
    return db.get(ScanRun, run_id)


def run_totals(db: Session, run_id: str) -> dict:
    row = db.execute(
        text("""
            SELECT count(*) AS hosts,
                   COALESCE(sum(passed), 0) AS passed,
                   COALESCE(sum(failed), 0) AS failed,
                   COALESCE(sum(accepted_risks), 0) AS accepted,
                   COALESCE(sum(total_checks), 0) AS total
            FROM scan_snapshots
            WHERE run_id = :run
        """),
        {"run": run_id},
    ).mappings().one()
    passed, failed = int(row["passed"]), int(row["failed"])
    total = int(row["total"])
    accepted = int(row["accepted"])
    return {
        "hosts": int(row["hosts"]),
        "passed": passed,
        "failed": failed,
        "accepted_risks": accepted,
        "total_checks": total,
        "not_checked": total - passed - failed - accepted,
        "compliance_score": score_of(passed, failed),
    }


def _run_dict(run: ScanRun, totals: dict, previous_id=None, environment_name: str | None = None) -> dict:
    return {
        "id": run.id,
        "organization_id": run.organization_id,
        "environment_id": run.environment_id,
        "environment_name": environment_name,
        "run_number": run.run_number,
        "status": run.status,
        "source": run.source,
        "schedule": run.schedule,
        "label": run.label,
        "notes": run.notes,
        "opened_at": run.opened_at,
        "window_ends_at": run.window_ends_at,
        "closed_at": run.closed_at,
        "created_at": run.created_at,
        "previous_run_id": previous_id,
        **totals,
    }


def list_runs(
    db: Session, organization_id: str, *, status: str | None, limit: int, offset: int,
) -> dict:
    close_expired(db, organization_id)
    db.commit()
    where = "r.organization_id = :org"
    params: dict = {"org": organization_id, "limit": limit, "offset": offset}
    if status in ("open", "closed"):
        where += " AND r.status = :status"
        params["status"] = status
    total = db.execute(
        text(f"SELECT count(*) FROM scan_runs r WHERE {where}"),
        {key: value for key, value in params.items() if key in ("org", "status")},
    ).scalar()
    rows = db.execute(
        text(f"""
            SELECT r.id, prev.id AS previous_run_id, e.name AS environment_name,
                   COALESCE(agg.hosts, 0) AS hosts,
                   COALESCE(agg.passed, 0) AS passed,
                   COALESCE(agg.failed, 0) AS failed,
                   COALESCE(agg.accepted, 0) AS accepted,
                   COALESCE(agg.total, 0) AS total
            FROM scan_runs r
            LEFT JOIN environments e ON e.id = r.environment_id
            LEFT JOIN (
                SELECT run_id, count(*) AS hosts,
                       sum(passed) AS passed, sum(failed) AS failed,
                       sum(accepted_risks) AS accepted, sum(total_checks) AS total
                FROM scan_snapshots
                WHERE organization_id = :org AND run_id IS NOT NULL
                GROUP BY run_id
            ) agg ON agg.run_id = r.id
            LEFT JOIN LATERAL (
                SELECT p.id FROM scan_runs p
                WHERE p.organization_id = r.organization_id AND p.run_number < r.run_number
                ORDER BY p.run_number DESC
                LIMIT 1
            ) prev ON true
            WHERE {where}
            ORDER BY r.run_number DESC
            LIMIT :limit OFFSET :offset
        """),
        params,
    ).mappings().all()
    ids = [row["id"] for row in rows]
    by_id = {run.id: run for run in db.query(ScanRun).filter(ScanRun.id.in_(ids)).all()} if ids else {}
    items = []
    for row in rows:
        run = by_id[row["id"]]
        passed, failed = int(row["passed"]), int(row["failed"])
        total_checks, accepted = int(row["total"]), int(row["accepted"])
        items.append(_run_dict(
            run,
            {
                "hosts": int(row["hosts"]),
                "passed": passed,
                "failed": failed,
                "accepted_risks": accepted,
                "total_checks": total_checks,
                "not_checked": total_checks - passed - failed - accepted,
                "compliance_score": score_of(passed, failed),
            },
            previous_id=row["previous_run_id"],
            environment_name=row["environment_name"],
        ))
    return {
        "items": items,
        "total": total,
        "limit": limit,
        "offset": offset,
        "schedule": org_schedule(db, organization_id),
    }


def run_detail(db: Session, run: ScanRun) -> dict:
    close_expired(db, str(run.organization_id))
    db.commit()
    db.refresh(run)
    env_name = None
    if run.environment_id is not None:
        env_name = db.execute(
            text("SELECT name FROM environments WHERE id = :id"), {"id": run.environment_id},
        ).scalar()
    previous = db.execute(
        text("""
            SELECT id FROM scan_runs
            WHERE organization_id = :org AND run_number < :num
            ORDER BY run_number DESC LIMIT 1
        """),
        {"org": run.organization_id, "num": run.run_number},
    ).scalar()
    environments = db.execute(
        text("""
            SELECT DISTINCT e.id, e.name
            FROM scan_snapshots s
            JOIN assets a ON a.id = s.asset_id
            JOIN environments e ON e.id = a.environment_id
            WHERE s.run_id = :run
            ORDER BY e.name
        """),
        {"run": run.id},
    ).mappings().all()
    return {
        **_run_dict(run, run_totals(db, str(run.id)), previous_id=previous, environment_name=env_name),
        "environments": [dict(row) for row in environments],
    }


def _like(query: str) -> str:
    escaped = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def list_hosts(
    db: Session, run_id: str, *, q: str, status: str, environment_id: str | None, limit: int, offset: int,
) -> dict:
    where = ["s.run_id = :run"]
    params: dict = {"run": run_id, "limit": limit, "offset": offset}
    if q:
        where.append("(a.hostname ILIKE :q ESCAPE '\\' OR COALESCE(a.ip_address, '') ILIKE :q ESCAPE '\\')")
        params["q"] = _like(q)
    if environment_id:
        where.append("a.environment_id = :env")
        params["env"] = environment_id
    if status == "failed":
        where.append("COALESCE(s.failed, 0) > 0")
    elif status == "clean":
        where.append("COALESCE(s.failed, 0) = 0")
    elif status == "unchecked":
        where.append("(COALESCE(s.total_checks, 0) - COALESCE(s.passed, 0) - COALESCE(s.failed, 0) - COALESCE(s.accepted_risks, 0)) > 0")
    clause = " AND ".join(where)
    base = f"""
        FROM scan_snapshots s
        LEFT JOIN assets a ON a.id = s.asset_id
        LEFT JOIN environments e ON e.id = a.environment_id
        WHERE {clause}
    """
    count_params = {key: value for key, value in params.items() if key not in ("limit", "offset")}
    total = db.execute(text(f"SELECT count(*) {base}"), count_params).scalar()
    rows = db.execute(
        text(f"""
            SELECT s.id AS snapshot_id, s.asset_id, a.hostname, a.ip_address, a.os, a.asset_type, a.criticality,
                   e.id AS environment_id, e.name AS environment_name,
                   s.status, s.compliance_score, s.passed, s.failed, s.accepted_risks, s.total_checks,
                   s.total_software, s.snapshot_label, s.collection, s.scan_number,
                   COALESCE(s.started_at, s.created_at) AS collected_at
            {base}
            ORDER BY a.hostname NULLS LAST, s.scan_number
            LIMIT :limit OFFSET :offset
        """),
        params,
    ).mappings().all()
    items = []
    for row in rows:
        item = dict(row)
        item["compliance_score"] = float(item["compliance_score"]) if item["compliance_score"] is not None else None
        total_checks = item["total_checks"] or 0
        item["not_checked"] = total_checks - (item["passed"] or 0) - (item["failed"] or 0) - (item["accepted_risks"] or 0)
        items.append(item)
    return {"items": items, "total": total, "limit": limit, "offset": offset}


def list_findings(db: Session, run_id: str, *, limit: int, offset: int) -> dict:
    grouped = """
        SELECT COALESCE(hr.rule_code, scr.check_id) AS check_key,
               COALESCE(hr.title, scr.title) AS title,
               COALESCE(hr.severity, scr.severity) AS severity,
               count(DISTINCT scr.asset_id) AS hosts
        FROM scan_check_results scr
        JOIN scan_snapshots s ON s.id = scr.snapshot_id
        LEFT JOIN hardening_rules hr ON hr.id = scr.rule_id
        WHERE s.run_id = :run AND scr.status = 'fail' AND scr.risk_exception_id IS NULL
        GROUP BY 1, 2, 3
    """
    params = {"run": run_id, "limit": limit, "offset": offset}
    total = db.execute(text(f"SELECT count(*) FROM ({grouped}) findings"), {"run": run_id}).scalar()
    rows = db.execute(
        text(f"""
            SELECT * FROM ({grouped}) findings
            ORDER BY CASE lower(severity)
                       WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3
                       ELSE 4 END,
                     hosts DESC, check_key
            LIMIT :limit OFFSET :offset
        """),
        params,
    ).mappings().all()
    return {"items": [dict(row) for row in rows], "total": total, "limit": limit, "offset": offset}


_COMPARE_CHECKS = """
    SELECT s.asset_id::text AS asset_id, a.hostname, scr.status,
           COALESCE(hr.rule_code, scr.check_id) AS check_key,
           COALESCE(hr.title, scr.title) AS title,
           COALESCE(hr.severity, scr.severity) AS severity,
           COALESCE(scr.expected_value, hr.expected_value) AS expected_value,
           scr.status = 'fail' AND scr.risk_exception_id IS NOT NULL AS accepted,
           re.reason AS exception_reason
    FROM scan_snapshots s
    JOIN scan_check_results scr ON scr.snapshot_id = s.id
    LEFT JOIN assets a ON a.id = s.asset_id
    LEFT JOIN hardening_rules hr ON hr.id = scr.rule_id
    LEFT JOIN risk_exceptions re ON re.id = scr.risk_exception_id
    WHERE s.run_id = :run AND scr.asset_id IS NOT NULL
"""

_COMPARE_HOSTS = """
    SELECT s.asset_id::text AS asset_id, a.hostname, s.compliance_score, s.passed, s.failed, s.accepted_risks
    FROM scan_snapshots s
    LEFT JOIN assets a ON a.id = s.asset_id
    WHERE s.run_id = :run AND s.asset_id IS NOT NULL
"""


def _checks(db: Session, run_id: str) -> dict:
    rows = db.execute(text(_COMPARE_CHECKS), {"run": run_id}).mappings().all()
    return {(row["asset_id"], row["check_key"]): dict(row) for row in rows if row["check_key"]}


def _hosts(db: Session, run_id: str) -> dict:
    rows = db.execute(text(_COMPARE_HOSTS), {"run": run_id}).mappings().all()
    return {row["asset_id"]: dict(row) for row in rows}


def compare_runs(db: Session, before: ScanRun, after: ScanRun, *, limit: int, offset: int) -> dict:
    """Динамика двух прогонов. Нарушения сравниваются только у общих хостов.

    Хост, который есть лишь в одном прогоне, — добавлен или пропал. Его проверки не
    считаются «новыми» или «исчезнувшими»: иначе появление машины раздуло бы список
    нарушений всеми её пунктами. Под раскрытием такого хоста — его оценка и число нарушений.
    """
    if before.organization_id != after.organization_id:
        raise ScanRunError(400, "Прогоны относятся к разным организациям")
    if before.id == after.id:
        raise ScanRunError(400, "Выбран один и тот же прогон")

    before_checks, after_checks = _checks(db, str(before.id)), _checks(db, str(after.id))
    before_hosts, after_hosts = _hosts(db, str(before.id)), _hosts(db, str(after.id))
    common = set(before_hosts) & set(after_hosts)
    added_ids = set(after_hosts) - set(before_hosts)
    removed_ids = set(before_hosts) - set(after_hosts)

    per_host: dict[str, list] = {asset: [] for asset in common}
    summary = {"fixed": 0, "regressed": 0, "stillFailed": 0, "newIssues": 0, "removed": 0, "changed": 0, "accepted": 0}
    for key in sorted(set(before_checks) | set(after_checks)):
        if key[0] not in common:
            continue
        was, now = before_checks.get(key), after_checks.get(key)
        change = classify(
            was and was["status"], now and now["status"],
            bool(was and was["accepted"]), bool(now and now["accepted"]),
        )
        if change is None:
            continue
        meta = now or was
        per_host[key[0]].append({
            "key": f"{key[0]}:{key[1]}",
            "rule": {"title": meta["title"], "rule_code": key[1], "severity": meta["severity"]},
            "beforeStatus": was and was["status"],
            "afterStatus": now and now["status"],
            "afterAccepted": bool(now and now["accepted"]),
            "exceptionReason": (now or {}).get("exception_reason") if now else None,
            "expectedValue": meta["expected_value"],
            "changeType": change,
        })
        if change == "new" and now and now["status"] == "fail" and not now["accepted"]:
            summary["newIssues"] += 1
        elif change == "fixed":
            summary["fixed"] += 1
        elif change == "regressed":
            summary["regressed"] += 1
        elif change == "still_failed":
            summary["stillFailed"] += 1
        elif change == "removed":
            summary["removed"] += 1
        elif change == "changed":
            summary["changed"] += 1
        elif change == "accepted":
            summary["accepted"] += 1

    from app.api.routes.snapshots import CHANGE_ORDER

    def host_row(asset_id: str, presence: str) -> dict:
        was, now = before_hosts.get(asset_id), after_hosts.get(asset_id)
        meta = now or was
        diffs = per_host.get(asset_id, [])
        diffs.sort(key=lambda item: (CHANGE_ORDER[item["changeType"]], item["rule"]["rule_code"] or ""))
        counts = {"fixed": 0, "regressed": 0, "stillFailed": 0, "newIssues": 0, "removed": 0, "changed": 0, "accepted": 0}
        for item in diffs:
            if item["changeType"] == "new":
                if item["afterStatus"] == "fail" and not item["afterAccepted"]:
                    counts["newIssues"] += 1
            elif item["changeType"] == "still_failed":
                counts["stillFailed"] += 1
            elif item["changeType"] in counts:
                counts[item["changeType"]] += 1
        before_score = float(was["compliance_score"]) if was and was["compliance_score"] is not None else None
        after_score = float(now["compliance_score"]) if now and now["compliance_score"] is not None else None
        return {
            "assetId": asset_id,
            "hostname": meta["hostname"] if meta else None,
            "presence": presence,
            "beforeScore": before_score,
            "afterScore": after_score,
            "beforeFailed": int(was["failed"] or 0) if was else None,
            "afterFailed": int(now["failed"] or 0) if now else None,
            "summary": counts,
            "diffs": diffs,
        }

    hosts = [host_row(asset, "both") for asset in common]
    hosts += [host_row(asset, "added") for asset in added_ids]
    hosts += [host_row(asset, "removed") for asset in removed_ids]
    hosts.sort(key=lambda item: (
        {"both": 0, "added": 1, "removed": 2}[item["presence"]],
        item["hostname"] or "",
    ))
    before_totals, after_totals = run_totals(db, str(before.id)), run_totals(db, str(after.id))
    before_score, after_score = before_totals["compliance_score"], after_totals["compliance_score"]
    delta = None
    if before_score is not None and after_score is not None:
        delta = round(after_score - before_score, 2)

    def host_brief(asset_id: str, pool: dict) -> dict:
        row = pool[asset_id]
        return {"assetId": asset_id, "hostname": row["hostname"], "failed": int(row["failed"] or 0),
                "complianceScore": float(row["compliance_score"]) if row["compliance_score"] is not None else None}

    return {
        "before": _run_dict(before, before_totals),
        "after": _run_dict(after, after_totals),
        "score": {"before": before_score, "after": after_score, "delta": delta},
        "summary": summary,
        "hostsAdded": sorted((host_brief(asset, after_hosts) for asset in added_ids), key=lambda item: item["hostname"] or ""),
        "hostsRemoved": sorted((host_brief(asset, before_hosts) for asset in removed_ids), key=lambda item: item["hostname"] or ""),
        "hosts": {
            "items": hosts[offset:offset + limit],
            "total": len(hosts),
            "limit": limit,
            "offset": offset,
        },
    }
