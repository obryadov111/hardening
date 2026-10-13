from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.deps import (
    get_accessible_org_ids,
    get_current_user,
    get_db,
    get_user_role_in_org,
    require_org_access,
)
from app.core.config import settings
from app.models.asset import Asset
from app.models.environment import Environment
from app.models.organization import ClientOrganization
from app.models.scan_snapshot import ScanSnapshot
from app.models.software import Software
from app.models.user import User
from app.schemas.data import (
    AssetOut,
    DashboardSummaryOut,
    OrganizationAssetOut,
    OrganizationOut,
    ScanSnapshotOut,
    SoftwareOut,
)

router = APIRouter(dependencies=[Depends(get_current_user)])


def _require_asset_access(db: Session, current_user: User, asset_id: str) -> str | None:
    """404 если актива нет, 403 если нет доступа к его организации. Возвращает environment_id."""
    environment_id = db.execute(
        text("SELECT environment_id FROM assets WHERE id = :asset_id"),
        {"asset_id": asset_id},
    ).scalar()
    if environment_id is None and not db.execute(text("SELECT 1 FROM assets WHERE id = :asset_id"), {"asset_id": asset_id}).scalar():
        raise HTTPException(status_code=404, detail="Актив не найден")

    if current_user.is_superadmin:
        return environment_id

    org_id = environment_id and db.execute(
        text("SELECT organization_id FROM environments WHERE id = :eid"),
        {"eid": environment_id},
    ).scalar()
    if not org_id or not get_user_role_in_org(db, current_user, str(org_id)):
        raise HTTPException(status_code=403, detail="Нет доступа к этому активу")

    return environment_id


@router.get("/organizations", response_model=list[OrganizationOut])
def get_organizations(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    org_ids = get_accessible_org_ids(db, current_user)
    query = db.query(ClientOrganization)
    if org_ids is not None:
        query = query.filter(ClientOrganization.id.in_(org_ids))
    return query.order_by(ClientOrganization.name.asc()).all()


@router.get("/organizations/{organization_id}/my-role")
def get_my_role(organization_id: str, current_user: User = Depends(require_org_access), db: Session = Depends(get_db)):
    role = get_user_role_in_org(db, current_user, organization_id)
    is_admin = role == "admin"

    return {
        "organization_id": organization_id,
        "role": role,
        "permissions": {
            "view_dashboard": True,
            "view_assets": True,
            "view_reports": True,
            "manage_users": is_admin,
            "manage_policies": is_admin,
        },
    }


@router.get("/assets", response_model=list[AssetOut])
def get_assets(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    org_ids = get_accessible_org_ids(db, current_user)
    query = db.query(Asset).join(Environment, Environment.id == Asset.environment_id)
    if org_ids is not None:
        query = query.filter(Environment.organization_id.in_(org_ids))
    return query.order_by(Asset.hostname.asc()).limit(50).all()


@router.get("/organizations/{organization_id}/assets", response_model=list[OrganizationAssetOut])
def get_assets_by_organization(organization_id: str, _: User = Depends(require_org_access), db: Session = Depends(get_db)):
    rows = db.execute(
        text("""
            SELECT
                a.id,
                a.environment_id,
                e.name AS environment_name,
                a.hostname,
                a.ip_address,
                a.os,
                a.asset_type,
                a.criticality,
                a.created_at,
                COALESCE((
                    SELECT COUNT(*) FROM software s WHERE s.asset_id = a.id
                ), 0) AS software_count,
                COALESCE((
                    SELECT COUNT(*) FROM hardening_checks hc
                    WHERE hc.asset_id = a.id AND hc.status = 'fail' AND hc.risk_exception_id IS NULL
                ), 0) AS failed_checks_count
            FROM assets a
            JOIN environments e ON e.id = a.environment_id
            WHERE e.organization_id = :org_id
            ORDER BY a.hostname ASC
        """),
        {"org_id": organization_id},
    ).mappings().all()

    return [dict(row) for row in rows]


@router.get("/assets/{asset_id}")
def get_asset_details(asset_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    row = db.execute(
        text("""
            SELECT
                a.id,
                a.environment_id,
                e.name AS environment_name,
                a.hostname,
                a.ip_address,
                a.os,
                a.asset_type,
                a.criticality,
                a.created_at,
                COALESCE((
                    SELECT COUNT(*) FROM software s WHERE s.asset_id = a.id
                ), 0) AS software_count,
                COALESCE((
                    SELECT COUNT(*) FROM hardening_checks hc WHERE hc.asset_id = a.id
                ), 0) AS checks_count,
                COALESCE((
                    SELECT COUNT(*) FROM hardening_checks hc
                    WHERE hc.asset_id = a.id AND hc.status = 'fail' AND hc.risk_exception_id IS NULL
                ), 0) AS failed_checks_count
            FROM assets a
            LEFT JOIN environments e ON e.id = a.environment_id
            WHERE a.id = :asset_id
            LIMIT 1
        """),
        {"asset_id": asset_id},
    ).mappings().first()

    if not row:
        raise HTTPException(status_code=404, detail="Актив не найден")

    _require_asset_access(db, current_user, asset_id)

    software_rows = db.execute(
        text("""
            SELECT id, asset_id, name, version, vendor, category, type, created_at
            FROM software WHERE asset_id = :asset_id ORDER BY name ASC
        """),
        {"asset_id": asset_id},
    ).mappings().all()

    checks_rows = db.execute(
        text("""
            SELECT id, asset_id, rule_id, actual_value, expected_value, status, checked_at, risk_exception_id
            FROM hardening_checks WHERE asset_id = :asset_id ORDER BY checked_at DESC NULLS LAST
        """),
        {"asset_id": asset_id},
    ).mappings().all()

    return {
        **dict(row),
        "software": [dict(item) for item in software_rows],
        "checks": [dict(item) for item in checks_rows],
    }


@router.get("/software", response_model=list[SoftwareOut])
def get_software(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    org_ids = get_accessible_org_ids(db, current_user)
    query = (
        db.query(Software)
        .join(Asset, Asset.id == Software.asset_id)
        .join(Environment, Environment.id == Asset.environment_id)
    )
    if org_ids is not None:
        query = query.filter(Environment.organization_id.in_(org_ids))
    return query.order_by(Software.name.asc()).limit(50).all()


@router.get("/scan-snapshots", response_model=list[ScanSnapshotOut])
def get_scan_snapshots(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    org_ids = get_accessible_org_ids(db, current_user)
    query = db.query(ScanSnapshot)
    if org_ids is not None:
        query = query.filter(ScanSnapshot.organization_id.in_(org_ids))
    return query.order_by(ScanSnapshot.created_at.desc()).limit(50).all()


@router.get("/organizations/{organization_id}/environments")
def get_environments_by_organization(organization_id: str, _: User = Depends(require_org_access), db: Session = Depends(get_db)):
    rows = db.execute(
        text("""
            SELECT e.id, e.organization_id, e.name,
                   COALESCE((SELECT COUNT(*) FROM assets a WHERE a.environment_id = e.id), 0) AS assets_count
            FROM environments e
            WHERE e.organization_id = :org_id
            ORDER BY e.name ASC
        """),
        {"org_id": organization_id},
    ).mappings().all()
    return [dict(row) for row in rows]


_SOFTWARE_SELECT = """
    SELECT
        s.id, s.name, s.version, s.vendor, s.category, s.type, s.created_at,
        a.id AS asset_id, a.hostname AS asset_hostname, a.os AS asset_os
    FROM software s
    JOIN assets a ON a.id = s.asset_id
    JOIN environments e ON e.id = a.environment_id
"""


def _software_row_to_dict(row: dict) -> dict:
    return {
        "id": row["id"],
        "name": row["name"],
        "version": row["version"],
        "vendor": row["vendor"],
        "category": row["category"],
        "type": row["type"],
        "created_at": row["created_at"],
        "asset": {"id": row["asset_id"], "hostname": row["asset_hostname"], "os": row["asset_os"]},
    }


_SOFTWARE_SORT = {
    "name": "s.name", "version": "s.version", "vendor": "s.vendor", "host": "a.hostname", "created_at": "s.created_at",
}


@router.get("/organizations/{organization_id}/software")
def get_software_by_organization(
    organization_id: str,
    q: str = Query("", max_length=200, description="Подстрока в названии, версии, производителе или имени хоста"),
    host: str = Query("", max_length=255, description="Только ПО этого хоста"),
    sort: Literal["name", "version", "vendor", "host", "created_at"] = "name",
    direction: Literal["asc", "desc"] = Query("asc", alias="dir"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    _: User = Depends(require_org_access),
    db: Session = Depends(get_db),
):
    """Страница инвентаризации ПО: на хосте ~1500 пакетов, на тысячу хостов — полтора миллиона строк,
    поэтому поиск, фильтр по хосту и сортировка — на сервере, а в ответе страница и итоги."""
    where = ["e.organization_id = :org_id"]
    params: dict = {"org_id": organization_id}
    if q.strip():
        where.append("(s.name ILIKE :q OR s.version ILIKE :q OR s.vendor ILIKE :q OR a.hostname ILIKE :q)")
        params["q"] = "%" + q.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    if host:
        where.append("a.hostname = :host")
        params["host"] = host
    condition = " AND ".join(where)
    order = f"{_SOFTWARE_SORT[sort]} {direction.upper()} NULLS LAST, s.name ASC, a.hostname ASC, s.id ASC"
    rows = db.execute(
        text(_SOFTWARE_SELECT + f" WHERE {condition} ORDER BY {order} LIMIT :limit OFFSET :offset"),
        {**params, "limit": limit, "offset": offset},
    ).mappings().all()
    total = db.execute(
        text(f"SELECT count(*) FROM software s JOIN assets a ON a.id = s.asset_id JOIN environments e ON e.id = a.environment_id WHERE {condition}"),
        params,
    ).scalar()
    summary = db.execute(text("""
        SELECT count(*) AS programs, count(DISTINCT s.category) AS categories,
               COALESCE(array_agg(DISTINCT a.hostname ORDER BY a.hostname) FILTER (WHERE a.hostname IS NOT NULL), '{}') AS hosts
        FROM software s JOIN assets a ON a.id = s.asset_id JOIN environments e ON e.id = a.environment_id
        WHERE e.organization_id = :org_id
    """), {"org_id": organization_id}).mappings().one()
    return {
        "items": [_software_row_to_dict(row) for row in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
        "summary": {"programs": summary["programs"], "categories": summary["categories"], "hosts": list(summary["hosts"])},
    }


@router.get("/assets/{asset_id}/software")
def get_software_by_asset(asset_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    _require_asset_access(db, current_user, asset_id)
    rows = db.execute(
        text(_SOFTWARE_SELECT + " WHERE a.id = :asset_id ORDER BY s.name ASC"),
        {"asset_id": asset_id},
    ).mappings().all()
    return [_software_row_to_dict(row) for row in rows]


_HARDENING_SELECT = """
    SELECT
        hc.id, hc.actual_value, hc.expected_value, hc.status, hc.checked_at, hc.evidence,
        hc.pack_id, hc.pack_version,
        a.id AS asset_id, a.hostname AS asset_hostname,
        r.id AS rule_id, r.expected_value AS rule_expected_value,
        -- Результаты контент-пака не имеют строки в hardening_rules: метаданные хранятся в самой записи.
        COALESCE(r.title, hc.title) AS rule_title,
        COALESCE(r.rule_code, hc.check_id) AS rule_code,
        COALESCE(r.severity, hc.severity) AS severity,
        COALESCE(r.remediation, hc.remediation) AS remediation,
        re.id AS exception_id, re.reason AS exception_reason, re.expires_at AS exception_expires_at,
        re.asset_id IS NULL AS exception_org_wide
    FROM hardening_checks hc
    JOIN assets a ON a.id = hc.asset_id
    JOIN environments e ON e.id = a.environment_id
    LEFT JOIN hardening_rules r ON r.id = hc.rule_id
    LEFT JOIN risk_exceptions re ON re.id = hc.risk_exception_id
"""


def _hardening_row_to_dict(row: dict) -> dict:
    return {
        "id": row["id"],
        "actual_value": row["actual_value"],
        "expected_value": row["expected_value"] or row["rule_expected_value"],
        "status": row["status"],
        "checked_at": row["checked_at"],
        "evidence": row["evidence"],
        "pack": {"id": row["pack_id"], "version": row["pack_version"]} if row["pack_id"] else None,
        "asset": {"id": row["asset_id"], "hostname": row["asset_hostname"]},
        "rule": {
            "id": row["rule_id"],
            "title": row["rule_title"],
            "rule_code": row["rule_code"],
            "severity": row["severity"],
            "remediation": row["remediation"],
        },
        # Принятый риск: нарушение осознанно не устраняется и не входит в оценку.
        "risk_exception": {
            "id": row["exception_id"],
            "reason": row["exception_reason"],
            "expires_at": row["exception_expires_at"],
            "org_wide": row["exception_org_wide"],
        } if row["exception_id"] else None,
    }


_SEVERITY = "lower(COALESCE(r.severity, hc.severity))"
_SEVERITY_RANK = f"CASE {_SEVERITY} WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END"
_ACCEPTED = "(hc.status = 'fail' AND hc.risk_exception_id IS NOT NULL)"
_OPEN_FAIL = "(hc.status = 'fail' AND hc.risk_exception_id IS NULL)"
# Срок устранения: открытые нарушения — от критических к низким, затем принятые риски, остальное — в конце.
_DEADLINE = f"CASE WHEN {_OPEN_FAIL} THEN 4 - {_SEVERITY_RANK} WHEN {_ACCEPTED} THEN 8 ELSE 9 END"
_HARDENING_SORT = {
    "asset": "a.hostname",
    "rule": "COALESCE(r.title, hc.title)",
    "severity": _SEVERITY_RANK,
    "status": f"CASE WHEN {_ACCEPTED} THEN 'fail-accepted' ELSE hc.status END",
    "deadline": _DEADLINE,
    "checked_at": "hc.checked_at",
}
_HARDENING_STATUS = {
    "pass": "hc.status = 'pass'",
    "fail": _OPEN_FAIL,
    "accepted": _ACCEPTED,
    "error": "hc.status NOT IN ('pass', 'fail')",
}
_FROM_CHECKS = """
    FROM hardening_checks hc
    JOIN assets a ON a.id = hc.asset_id
    JOIN environments e ON e.id = a.environment_id
    LEFT JOIN hardening_rules r ON r.id = hc.rule_id
"""


@router.get("/organizations/{organization_id}/hardening")
def get_hardening_by_organization(
    organization_id: str,
    q: str = Query("", max_length=200, description="Подстрока в названии или коде проверки, имени хоста"),
    host: str = Query("", max_length=255),
    status: Literal["", "pass", "fail", "accepted", "error"] = Query("", description="fail — открытые нарушения, accepted — с принятым риском"),
    severity: Literal["", "critical", "high", "medium", "low"] = "",
    sort: Literal["asset", "rule", "severity", "status", "deadline", "checked_at"] = "deadline",
    direction: Literal["asc", "desc"] = Query("asc", alias="dir"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    _: User = Depends(require_org_access),
    db: Session = Depends(get_db),
):
    """Текущие результаты проверок организации: 36 проверок на хост, на тысячу хостов — десятки тысяч строк,
    поэтому фильтры, сортировка и страницы — на сервере. summary — по всей организации (плитки и план
    устранения на «Харденинге» и в «Отчётах»), без учёта фильтров."""
    where = ["e.organization_id = :org_id"]
    params: dict = {"org_id": organization_id}
    if q.strip():
        where.append("(COALESCE(r.title, hc.title) ILIKE :q OR COALESCE(r.rule_code, hc.check_id) ILIKE :q OR a.hostname ILIKE :q)")
        params["q"] = "%" + q.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    if host:
        where.append("a.hostname = :host")
        params["host"] = host
    if status:
        where.append(_HARDENING_STATUS[status])
    if severity:
        where.append(f"{_SEVERITY} = :severity")
        params["severity"] = severity
    condition = " AND ".join(where)
    order = f"{_HARDENING_SORT[sort]} {direction.upper()} NULLS LAST, a.hostname ASC, COALESCE(r.rule_code, hc.check_id) ASC, hc.id ASC"
    rows = db.execute(
        text(_HARDENING_SELECT + f" WHERE {condition} ORDER BY {order} LIMIT :limit OFFSET :offset"),
        {**params, "limit": limit, "offset": offset},
    ).mappings().all()
    total = db.execute(text(f"SELECT count(*) {_FROM_CHECKS} WHERE {condition}"), params).scalar()

    org = {"org_id": organization_id}
    counts = db.execute(text(f"""
        SELECT count(*) AS total,
               count(*) FILTER (WHERE hc.status = 'pass') AS passed,
               count(*) FILTER (WHERE {_OPEN_FAIL}) AS failed,
               count(*) FILTER (WHERE {_ACCEPTED}) AS accepted,
               count(*) FILTER (WHERE hc.status NOT IN ('pass', 'fail')) AS errors,
               count(*) FILTER (WHERE {_OPEN_FAIL} AND {_SEVERITY} IN ('critical', 'high')) AS mandatory,
               COALESCE(array_agg(DISTINCT a.hostname ORDER BY a.hostname), '{{}}') AS hosts
        {_FROM_CHECKS} WHERE e.organization_id = :org_id
    """), org).mappings().one()
    by_severity = db.execute(text(f"""
        SELECT {_SEVERITY} AS severity, count(*) AS count, count(DISTINCT hc.asset_id) AS assets
        {_FROM_CHECKS} WHERE e.organization_id = :org_id AND {_OPEN_FAIL} AND {_SEVERITY} IN ('critical', 'high', 'medium', 'low')
        GROUP BY 1 ORDER BY max({_SEVERITY_RANK}) DESC
    """), org).mappings().all()
    return {
        "items": [_hardening_row_to_dict(row) for row in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
        "summary": {
            **{k: counts[k] for k in ("total", "passed", "failed", "accepted", "errors", "mandatory")},
            "hosts": list(counts["hosts"]),
            # открытые нарушения по уровням — план устранения (сроки и обязательность — во фронтенде, utils/remediation.js)
            "open_by_severity": [dict(row) for row in by_severity],
        },
    }


@router.get("/assets/{asset_id}/hardening")
def get_hardening_by_asset(asset_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    _require_asset_access(db, current_user, asset_id)
    rows = db.execute(
        text(_HARDENING_SELECT + " WHERE a.id = :asset_id ORDER BY hc.checked_at DESC NULLS LAST"),
        {"asset_id": asset_id},
    ).mappings().all()
    return [_hardening_row_to_dict(row) for row in rows]


@router.get("/organizations/{organization_id}/snapshots")
def get_snapshots_by_organization(
    organization_id: str,
    host: str = Query("", max_length=255, description="Только сканы этого хоста"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    _: User = Depends(require_org_access),
    db: Session = Depends(get_db),
):
    """Сканы организации, новые сначала. Снимок создаётся на каждый прогон агента — тысяча хостов дают
    тысячу снимков в день, поэтому страницы; у каждого — имена хостов и предыдущий снимок с общим активом
    (соседний по номеру обычно про другой сервер). Предыдущий ищется только для снимков страницы."""
    where = "s.organization_id = :org_id"
    params: dict = {"org_id": organization_id}
    if host:
        where += """ AND EXISTS (
            SELECT 1 FROM scan_check_results scr JOIN assets a ON a.id = scr.asset_id
            WHERE scr.snapshot_id = s.id AND a.hostname = :host)"""
        params["host"] = host
    ids = db.execute(
        text(f"SELECT s.id FROM scan_snapshots s WHERE {where} ORDER BY s.scan_number DESC LIMIT :limit OFFSET :offset"),
        {**params, "limit": limit, "offset": offset},
    ).scalars().all()
    by_id = {snapshot.id: snapshot for snapshot in db.query(ScanSnapshot).filter(ScanSnapshot.id.in_(ids)).all()} if ids else {}
    snapshots = [by_id[i] for i in ids]
    total = db.execute(text(f"SELECT count(*) FROM scan_snapshots s WHERE {where}"), params).scalar()
    hosts: dict = {}
    previous: dict = {}
    if ids:
        hosts = dict(db.execute(text("""
            SELECT scr.snapshot_id, array_agg(DISTINCT a.hostname ORDER BY a.hostname)
            FROM scan_check_results scr JOIN assets a ON a.id = scr.asset_id
            WHERE scr.snapshot_id = ANY(:ids)
            GROUP BY scr.snapshot_id
        """), {"ids": ids}).all())
        previous = dict(db.execute(text("""
            WITH cur AS (
                SELECT DISTINCT scr.snapshot_id, scr.asset_id, s.scan_number
                FROM scan_check_results scr JOIN scan_snapshots s ON s.id = scr.snapshot_id
                WHERE scr.snapshot_id = ANY(:ids)
            )
            SELECT DISTINCT ON (cur.snapshot_id) cur.snapshot_id, prev.id
            FROM cur
            CROSS JOIN LATERAL (
                SELECT s2.id, s2.scan_number
                FROM scan_check_results scr2 JOIN scan_snapshots s2 ON s2.id = scr2.snapshot_id
                WHERE scr2.asset_id = cur.asset_id AND s2.organization_id = :org_id AND s2.scan_number < cur.scan_number
                ORDER BY s2.scan_number DESC
                LIMIT 1
            ) prev
            ORDER BY cur.snapshot_id, prev.scan_number DESC
        """), {"ids": ids, "org_id": organization_id}).all())
    summary = db.execute(text("""
        SELECT count(*) AS total,
               count(*) FILTER (WHERE status = 'completed') AS completed,
               count(*) FILTER (WHERE status = 'failed') AS failed
        FROM scan_snapshots WHERE organization_id = :org_id
    """), {"org_id": organization_id}).mappings().one()
    latest = (
        db.query(ScanSnapshot).filter(ScanSnapshot.organization_id == organization_id)
        .order_by(ScanSnapshot.scan_number.desc()).first()
    )
    return {
        "items": [
            ScanSnapshotOut.model_validate(snapshot).model_copy(
                update={"previous_snapshot_id": previous.get(snapshot.id), "hosts": list(hosts.get(snapshot.id) or [])}
            )
            for snapshot in snapshots
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
        "summary": {**summary, "latest": ScanSnapshotOut.model_validate(latest) if latest else None},
    }


@router.get("/organizations/{organization_id}/reports")
def get_reports_by_organization(
    organization_id: str,
    daily: bool = Query(False, description="Один отчёт за день — последний: отчёт пересчитывается при каждом приёме"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    _: User = Depends(require_org_access),
    db: Session = Depends(get_db),
):
    """Отчёты организации, новые сначала. Отчёт пересчитывается при каждом приёме данных (тысяча хостов —
    тысяча отчётов в день), поэтому для динамики — daily: последний отчёт каждого дня (по DISPLAY_TIMEZONE)."""
    source = "hardening_reports WHERE organization_id = :org_id"
    if daily:
        source = """(
            SELECT DISTINCT ON ((generated_at AT TIME ZONE :tz)::date) *
            FROM hardening_reports WHERE organization_id = :org_id
            ORDER BY (generated_at AT TIME ZONE :tz)::date, generated_at DESC
        ) daily"""
    rows = db.execute(
        text(f"""
            SELECT id, organization_id, total_checks, passed, failed, compliance_score, generated_at
            FROM {source}
            ORDER BY generated_at DESC
            LIMIT :limit OFFSET :offset
        """),
        {"org_id": organization_id, "tz": settings.DISPLAY_TIMEZONE, "limit": limit, "offset": offset},
    ).mappings().all()
    return [dict(row) for row in rows]


@router.get("/organizations/{organization_id}/dashboard", response_model=DashboardSummaryOut)
def get_dashboard_summary(organization_id: str, _: User = Depends(require_org_access), db: Session = Depends(get_db)):
    environments_count = db.execute(
        text("SELECT COUNT(*) FROM environments WHERE organization_id = :org_id"),
        {"org_id": organization_id},
    ).scalar()

    assets_count = db.execute(
        text("""
            SELECT COUNT(*) FROM assets a
            JOIN environments e ON e.id = a.environment_id
            WHERE e.organization_id = :org_id
        """),
        {"org_id": organization_id},
    ).scalar()

    critical_assets = db.execute(
        text("""
            SELECT COUNT(*) FROM assets a
            JOIN environments e ON e.id = a.environment_id
            WHERE e.organization_id = :org_id AND a.criticality = 'critical'
        """),
        {"org_id": organization_id},
    ).scalar()

    software_count = db.execute(
        text("""
            SELECT COUNT(*) FROM software s
            JOIN assets a ON a.id = s.asset_id
            JOIN environments e ON e.id = a.environment_id
            WHERE e.organization_id = :org_id
        """),
        {"org_id": organization_id},
    ).scalar()

    # error (проверка не выполнилась) — отдельная категория: раньше фронт считал
    # passed = total - failed, и невыполненные проверки выглядели как пройденные.
    checks = db.execute(
        text("""
            SELECT
                COUNT(*) AS total,
                COUNT(*) FILTER (WHERE hc.status = 'pass') AS passed,
                COUNT(*) FILTER (WHERE hc.status = 'fail' AND hc.risk_exception_id IS NULL) AS failed,
                COUNT(*) FILTER (WHERE hc.status = 'fail' AND hc.risk_exception_id IS NOT NULL) AS accepted
            FROM hardening_checks hc
            JOIN assets a ON a.id = hc.asset_id
            JOIN environments e ON e.id = a.environment_id
            WHERE e.organization_id = :org_id
        """),
        {"org_id": organization_id},
    ).mappings().first()
    checks_count = checks["total"] or 0
    passed_checks = checks["passed"] or 0
    failed_checks = checks["failed"] or 0
    accepted_checks = checks["accepted"] or 0
    evaluated = passed_checks + failed_checks + accepted_checks

    reports_count = db.execute(
        text("SELECT COUNT(*) FROM hardening_reports WHERE organization_id = :org_id"),
        {"org_id": organization_id},
    ).scalar()

    latest_report = db.execute(
        text("""
            SELECT compliance_score, generated_at, total_checks, failed
            FROM hardening_reports
            WHERE organization_id = :org_id
            ORDER BY generated_at DESC
            LIMIT 1
        """),
        {"org_id": organization_id},
    ).mappings().first()

    return {
        "assetsCount": assets_count or 0,
        "softwareCount": software_count or 0,
        "checksCount": checks_count,
        "passedChecks": passed_checks,
        "failedChecks": failed_checks,
        "acceptedChecks": accepted_checks,
        "notEvaluatedChecks": checks_count - evaluated,
        "coverage": round(evaluated / checks_count * 100, 2) if checks_count else None,
        "reportsCount": reports_count or 0,
        "latestReport": dict(latest_report) if latest_report else None,
        "environmentsCount": environments_count or 0,
        "criticalAssets": critical_assets or 0,
    }
