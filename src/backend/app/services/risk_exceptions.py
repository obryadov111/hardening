"""Принятый риск: исключения из оценки соответствия.

Исключение действует на проверку (check_key — код правила или id проверки пака) на одном активе
или, если asset_id пуст, на всех активах организации. Действующее исключение — не отозвано и не
истекло. Если подходят оба вида, берётся исключение конкретного актива.

Исключение не меняет статус проверки: fail остаётся fail (это факт с хоста), а результат получает
ссылку risk_exception_id и не входит в compliance score. Ссылка проставляется при каждом прогоне
агента и сразу после создания или отзыва исключения в текущем состоянии (hardening_checks).
История снимков не переписывается: снимок показывает, какие риски были приняты на момент прогона.
Истёкшее исключение перестаёт действовать со следующего прогона агента.
"""
from datetime import datetime

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.models.hardening import HardeningReport
from app.services.hardening_engine import CheckResult

_ACTIVE = "re.organization_id = :org_id AND re.revoked_at IS NULL AND (re.expires_at IS NULL OR re.expires_at > :now)"


def active_exceptions(db: Session, organization_id: str, asset_id: str, now: datetime) -> dict[str, str]:
    """{check_key: id исключения}, действующие для актива на момент now."""
    rows = db.execute(
        text(f"""
            SELECT re.id, re.check_key FROM risk_exceptions re
            WHERE {_ACTIVE} AND (re.asset_id IS NULL OR re.asset_id = :asset_id)
            -- исключение конкретного актива перекрывает общее для организации
            ORDER BY re.asset_id NULLS FIRST, re.created_at
        """),
        {"org_id": organization_id, "asset_id": str(asset_id), "now": now},
    ).all()
    return {check_key: str(exception_id) for exception_id, check_key in rows}


def apply_exceptions(results: list[CheckResult], exceptions: dict[str, str]) -> None:
    for result in results:
        key = result.check_id or result.rule_code
        result.risk_exception_id = exceptions.get(key) if result.status == "fail" and key else None


def sync_current_state(db: Session, organization_id: str, now: datetime) -> None:
    """Пересчитывает ссылки на исключения в текущем состоянии всех активов организации."""
    db.execute(
        text(f"""
            UPDATE hardening_checks hc SET risk_exception_id = CASE WHEN hc.status = 'fail' THEN (
                SELECT re.id FROM risk_exceptions re
                WHERE {_ACTIVE}
                  AND (re.asset_id IS NULL OR re.asset_id = hc.asset_id)
                  AND re.check_key = COALESCE((SELECT r.rule_code FROM hardening_rules r WHERE r.id = hc.rule_id), hc.check_id)
                ORDER BY re.asset_id NULLS LAST, re.created_at
                LIMIT 1
            ) END
            FROM assets a JOIN environments e ON e.id = a.environment_id
            WHERE a.id = hc.asset_id AND e.organization_id = :org_id
        """),
        {"org_id": organization_id, "now": now},
    )


def record_org_report(db: Session, organization_id: str, now: datetime) -> HardeningReport:
    """Оргуровневый отчёт — агрегат по ТЕКУЩЕМУ состоянию всех активов организации
    (hardening_checks хранит только последний прогон на актив)."""
    totals = db.execute(
        text("""
            SELECT
                COUNT(*) AS total,
                COUNT(*) FILTER (WHERE hc.status = 'pass') AS passed,
                COUNT(*) FILTER (WHERE hc.status = 'fail' AND hc.risk_exception_id IS NULL) AS failed
            FROM hardening_checks hc
            JOIN assets a ON a.id = hc.asset_id
            JOIN environments e ON e.id = a.environment_id
            WHERE e.organization_id = :org_id
        """),
        {"org_id": organization_id},
    ).mappings().first()

    passed, failed = totals["passed"] or 0, totals["failed"] or 0
    report = HardeningReport(
        organization_id=organization_id,
        total_checks=totals["total"] or 0,
        passed=passed,
        failed=failed,
        compliance_score=round(passed / (passed + failed) * 100, 2) if passed + failed else None,
        generated_at=now,
    )
    db.add(report)
    db.flush()
    return report
