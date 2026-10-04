from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.deps import get_agent_organization_id, get_db, get_pack_registry
from app.models.asset import Asset
from app.models.environment import Environment
from app.models.hardening import (
    AgentCollection,
    HardeningCheck,
    HardeningRule,
    IngestionBatch,
    ScanCheckResult,
)
from app.models.scan_snapshot import ScanSnapshot
from app.models.software import Software
from app.schemas.ingest import (
    IngestChecksSummary,
    IngestCoverage,
    IngestPackRun,
    IngestPackSummary,
    IngestRequest,
    IngestResponse,
)
from app.services.hardening_engine import (
    compute_compliance_score,
    compute_coverage,
    count_accepted,
    evaluate_asset,
)
from app.services.packs.evaluate import evaluate_pack
from app.services.packs.registry import PackRegistry
from app.services.risk_exceptions import active_exceptions, apply_exceptions, record_org_report

router = APIRouter(tags=["ingest"])


def _get_or_create_environment(db: Session, organization_id: str, name: str) -> Environment:
    env = (
        db.query(Environment)
        .filter(Environment.organization_id == organization_id, Environment.name == name)
        .first()
    )
    if env:
        return env
    env = Environment(organization_id=organization_id, name=name)
    db.add(env)
    db.flush()
    return env


def _get_or_create_asset(db: Session, environment_id: str, payload, platform_tags: list[str]) -> Asset:
    asset = (
        db.query(Asset)
        .filter(Asset.environment_id == environment_id, Asset.hostname == payload.hostname)
        .first()
    )
    if asset:
        asset.ip_address = payload.ip_address
        asset.os = payload.os
        asset.asset_type = payload.asset_type
        asset.criticality = payload.criticality
        if platform_tags:
            asset.platform_tags = platform_tags
    else:
        asset = Asset(
            environment_id=environment_id,
            hostname=payload.hostname,
            ip_address=payload.ip_address,
            os=payload.os,
            asset_type=payload.asset_type,
            criticality=payload.criticality,
            platform_tags=platform_tags or None,
        )
        db.add(asset)
    db.flush()
    return asset


def _pack_runs(payload: IngestRequest) -> list[IngestPackRun]:
    """Все паки прогона: одиночный `pack` + `probe_results` (прежний формат) и/или список `packs`."""
    runs = list(payload.packs)
    if payload.pack:
        runs.insert(0, IngestPackRun(id=payload.pack.id, version=payload.pack.version, probe_results=payload.probe_results))
    ids = [run.id for run in runs]
    duplicates = sorted({i for i in ids if ids.count(i) > 1})
    if duplicates:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Пак указан больше одного раза: {', '.join(duplicates)}",
        )
    return runs


@router.post("/ingest", response_model=IngestResponse)
def ingest(
    payload: IngestRequest,
    organization_id: str = Depends(get_agent_organization_id),
    db: Session = Depends(get_db),
    registry: PackRegistry = Depends(get_pack_registry),
):
    """Приём данных от агента-сборщика: активы, ПО, сырые факты конфигурации.
    Прогоняет факты через движок сравнения (evaluate_asset) против hardening_rules,
    фиксирует текущее состояние (hardening_checks), историю (scan_snapshots +
    scan_check_results) и пересчитывает compliance_score организации (hardening_reports).
    """
    now = datetime.now(UTC)

    # Все паки разрешаются до записи в БД: неизвестный пак — 422 без побочных записей.
    resolved = []
    for run in _pack_runs(payload):
        pack = registry.get(run.id, run.version)
        if pack is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Неизвестный пак {run.id} версии {run.version}",
            )
        resolved.append((pack, run))

    batch = IngestionBatch(organization_id=organization_id, received_at=now, source="agent", status="processing")
    db.add(batch)
    db.flush()

    environment = _get_or_create_environment(db, organization_id, payload.environment)
    asset = _get_or_create_asset(db, str(environment.id), payload.asset, payload.platform_tags)

    db.query(Software).filter(Software.asset_id == asset.id).delete()
    for item in payload.software:
        db.add(
            Software(
                asset_id=asset.id,
                name=item.name,
                version=item.version,
                vendor=item.vendor,
                category=item.category,
                type=item.type,
            )
        )

    collected_data = payload.facts
    if resolved:
        # Сырые результаты проб — чтобы результат можно было перепрогнать по новой версии правил.
        collected_data = {
            "facts": payload.facts,
            "packs": [
                {
                    "id": run.id,
                    "version": run.version,
                    "probe_results": {k: v.model_dump() for k, v in run.probe_results.items()},
                }
                for _, run in resolved
            ],
        }
    db.add(AgentCollection(asset_id=asset.id, batch_id=batch.id, collected_data=collected_data, collected_at=now))

    results = []
    # Агент на паках присылает probe_results, а не facts: старые правила против пустых facts
    # дали бы ложные error по каждому правилу, поэтому без facts они не запускаются.
    if payload.facts or not resolved:
        rules = db.query(HardeningRule).all()
        results.extend(evaluate_asset(payload.facts, rules, asset.asset_type, payload.platform_tags))
    pack_summaries = []
    for pack, run in resolved:
        pack_results = evaluate_pack(pack, run.probe_results)
        results.extend(pack_results)
        pack_summaries.append(
            IngestPackSummary(
                id=pack.pack, version=pack.version, maturity=pack.maturity,
                total=len(pack_results),
                passed=sum(1 for r in pack_results if r.status == "pass"),
                failed=sum(1 for r in pack_results if r.status == "fail"),
                errors=sum(1 for r in pack_results if r.status == "error"),
            )
        )
    apply_exceptions(results, active_exceptions(db, organization_id, asset.id, now))
    score, total, passed, failed = compute_compliance_score(results)
    accepted = count_accepted(results)
    errors = total - passed - failed - accepted

    db.query(HardeningCheck).filter(HardeningCheck.asset_id == asset.id).delete()
    for r in results:
        db.add(
            HardeningCheck(
                asset_id=asset.id,
                rule_id=r.rule_id,
                actual_value=r.actual_value,
                expected_value=r.expected_value,
                status=r.status,
                checked_at=now,
                check_id=r.check_id,
                pack_id=r.pack_id,
                pack_version=r.pack_version,
                title=r.title,
                severity=r.severity,
                remediation=r.remediation,
                evidence=r.evidence,
                risk_exception_id=r.risk_exception_id,
            )
        )

    next_scan_number = (
        db.execute(
            text("SELECT COALESCE(MAX(scan_number), 0) + 1 FROM scan_snapshots WHERE organization_id = :org_id"),
            {"org_id": organization_id},
        ).scalar()
        or 1
    )

    snapshot = ScanSnapshot(
        organization_id=organization_id,
        scan_number=next_scan_number,
        started_at=now,
        completed_at=now,
        total_checks=total,
        passed=passed,
        failed=failed,
        accepted_risks=accepted,
        compliance_score=score,
        ingestion_batch_id=batch.id,
        snapshot_label=payload.scan_label,
        status="completed",
        total_assets=1,
        total_software=len(payload.software),
        created_at=now,
    )
    db.add(snapshot)
    db.flush()

    for r in results:
        db.add(
            ScanCheckResult(
                snapshot_id=snapshot.id,
                asset_id=asset.id,
                rule_id=r.rule_id,
                actual_value=r.actual_value,
                expected_value=r.expected_value,
                status=r.status,
                checked_at=now,
                check_id=r.check_id,
                pack_id=r.pack_id,
                pack_version=r.pack_version,
                evidence=r.evidence,
                title=r.title,
                severity=r.severity,
                remediation=r.remediation,
                risk_exception_id=r.risk_exception_id,
            )
        )

    # Оргуровневый отчёт — по текущему состоянию всех активов организации, не только этого прогона.
    report = record_org_report(db, organization_id, now)

    batch.status = "completed"
    batch.assets_count = 1
    batch.software_count = len(payload.software)
    batch.checks_count = total
    batch.report_id = report.id

    db.commit()

    return IngestResponse(
        batch_id=str(batch.id),
        asset_id=str(asset.id),
        snapshot_id=str(snapshot.id),
        checks=IngestChecksSummary(total=total, passed=passed, failed=failed, errors=errors),
        compliance_score=score,
        accepted_risks=accepted,
        coverage=IngestCoverage(**compute_coverage(results)),
        packs=pack_summaries,
        report_id=str(report.id),
    )
