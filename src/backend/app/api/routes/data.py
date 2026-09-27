from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.deps import (
    get_accessible_org_ids,
    get_current_user,
    get_db,
    get_user_role_in_org,
    require_org_access,
)
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
                    WHERE hc.asset_id = a.id AND hc.status = 'fail'
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
                    WHERE hc.asset_id = a.id AND hc.status = 'fail'
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
            SELECT id, asset_id, rule_id, actual_value, expected_value, status, checked_at
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


@router.get("/organizations/{organization_id}/software")
def get_software_by_organization(organization_id: str, _: User = Depends(require_org_access), db: Session = Depends(get_db)):
    rows = db.execute(
        text(_SOFTWARE_SELECT + " WHERE e.organization_id = :org_id ORDER BY s.name ASC"),
        {"org_id": organization_id},
    ).mappings().all()
    return [_software_row_to_dict(row) for row in rows]


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
        COALESCE(r.remediation, hc.remediation) AS remediation
    FROM hardening_checks hc
    JOIN assets a ON a.id = hc.asset_id
    JOIN environments e ON e.id = a.environment_id
    LEFT JOIN hardening_rules r ON r.id = hc.rule_id
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
    }


@router.get("/organizations/{organization_id}/hardening")
def get_hardening_by_organization(organization_id: str, _: User = Depends(require_org_access), db: Session = Depends(get_db)):
    rows = db.execute(
        text(_HARDENING_SELECT + " WHERE e.organization_id = :org_id ORDER BY hc.checked_at DESC NULLS LAST"),
        {"org_id": organization_id},
    ).mappings().all()
    return [_hardening_row_to_dict(row) for row in rows]


@router.get("/assets/{asset_id}/hardening")
def get_hardening_by_asset(asset_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    _require_asset_access(db, current_user, asset_id)
    rows = db.execute(
        text(_HARDENING_SELECT + " WHERE a.id = :asset_id ORDER BY hc.checked_at DESC NULLS LAST"),
        {"asset_id": asset_id},
    ).mappings().all()
    return [_hardening_row_to_dict(row) for row in rows]


@router.get("/organizations/{organization_id}/snapshots", response_model=list[ScanSnapshotOut])
def get_snapshots_by_organization(organization_id: str, _: User = Depends(require_org_access), db: Session = Depends(get_db)):
    query = db.query(ScanSnapshot).filter(ScanSnapshot.organization_id == organization_id)
    return query.order_by(ScanSnapshot.scan_number.desc()).all()


@router.get("/organizations/{organization_id}/reports")
def get_reports_by_organization(organization_id: str, _: User = Depends(require_org_access), db: Session = Depends(get_db)):
    rows = db.execute(
        text("""
            SELECT id, organization_id, total_checks, passed, failed, compliance_score, generated_at
            FROM hardening_reports
            WHERE organization_id = :org_id
            ORDER BY generated_at DESC
        """),
        {"org_id": organization_id},
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
                COUNT(*) FILTER (WHERE hc.status = 'fail') AS failed
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
    evaluated = passed_checks + failed_checks

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
        "notEvaluatedChecks": checks_count - evaluated,
        "coverage": round(evaluated / checks_count * 100, 2) if checks_count else None,
        "reportsCount": reports_count or 0,
        "latestReport": dict(latest_report) if latest_report else None,
        "environmentsCount": environments_count or 0,
        "criticalAssets": critical_assets or 0,
    }
