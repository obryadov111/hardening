from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import insert, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.deps import AgentIdentity, get_agent_identity, get_db, get_pack_registry, normalize_hostname
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

# Насколько время сбора от агента может опережать часы сервера (расхождение часов) и насколько отставать
# (прогон пролежал в очереди агента; очередь агента хранит не дольше 30 дней).
MAX_CLOCK_SKEW = timedelta(minutes=10)
MAX_QUEUE_AGE = timedelta(days=31)


def _collected_at(collected_at: datetime | None, received: datetime) -> datetime:
    """Время снимка — когда агент собрал данные, а не когда прогон дошёл до сервера (из очереди — позже)."""
    if collected_at is None:
        return received
    if collected_at.tzinfo is None:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="collected_at — с часовым поясом")
    if collected_at > received + MAX_CLOCK_SKEW:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="collected_at в будущем: проверьте часы на хосте агента")
    if collected_at < received - MAX_QUEUE_AGE:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="collected_at старше 31 дня: прогон устарел")
    return min(collected_at, received)


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


def check_agent_may_report(identity: AgentIdentity, hostname: str) -> None:
    """Ключ хоста — отчёт только со своим именем; ключ площадки — только у ключей до регистрации хостов
    (direct_use). 403, а не 401: ключ верный, но на этот отчёт прав нет (агент хранит прогон в очереди)."""
    if identity.host is not None:
        if normalize_hostname(hostname) != identity.host.hostname_norm:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Хост {identity.host.hostname} зарегистрирован под своим именем и не может прислать отчёт хоста {hostname}",
            )
        return
    if not identity.direct_use:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Это ключ площадки: отчёт принимается от зарегистрированного хоста — агент регистрируется "
                   "сам при запуске (нужна версия агента с регистрацией хостов)",
        )


@router.post("/ingest", response_model=IngestResponse)
def ingest(
    payload: IngestRequest,
    identity: AgentIdentity = Depends(get_agent_identity),
    db: Session = Depends(get_db),
    registry: PackRegistry = Depends(get_pack_registry),
):
    """Приём данных от агента-сборщика: активы, ПО, сырые факты конфигурации.
    Прогоняет факты через движок сравнения (evaluate_asset) против hardening_rules,
    фиксирует текущее состояние (hardening_checks), историю (scan_snapshots +
    scan_check_results) и пересчитывает compliance_score организации (hardening_reports).
    """
    check_agent_may_report(identity, payload.asset.hostname)
    return ingest_payload(
        db, registry, identity.organization_id, payload,
        collection=payload.collection.model_dump() if payload.collection else None,
    )


def ingest_payload(
    db: Session,
    registry: PackRegistry,
    organization_id: str,
    payload: IngestRequest,
    collection: dict | None = None,
    source: str = "agent",
) -> IngestResponse:
    """Запись прогона: снимок, текущее состояние актива, отчёт организации. Общая для агента
    (POST /ingest), для выгрузки, загруженной через интерфейс (source="offline-upload"), и для опроса (source="manual").
    collection — источник данных снимка; задаётся вызывающим, а не берётся из payload: у загрузки
    через интерфейс в нём есть поля (кто загрузил), которые агент присылать не может."""
    received = datetime.now(UTC)
    now = _collected_at(payload.collected_at, received)
    if payload.run_id is not None and db.query(IngestionBatch.id).filter(
        IngestionBatch.organization_id == organization_id, IngestionBatch.run_id == payload.run_id,
    ).first():
        # Агент повторил отправку (ответ на первую потерялся, прогон остался в очереди): уже принято.
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Прогон {payload.run_id} уже принят")

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

    batch = IngestionBatch(
        organization_id=organization_id, received_at=received, source=source, status="processing",
        run_id=payload.run_id, collected_at=payload.collected_at and now,
    )
    db.add(batch)
    try:
        db.flush()
    except IntegrityError:  # тот же прогон пришёл одновременно двумя запросами — уникальный индекс
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Прогон {payload.run_id} уже принят") from None

    environment = _get_or_create_environment(db, organization_id, payload.environment)
    asset = _get_or_create_asset(db, str(environment.id), payload.asset, payload.platform_tags)

    db.query(Software).filter(Software.asset_id == asset.id).delete()
    # Находки БДУ актива посчитаны по прежнему списку ПО — пересчитаются при следующем открытии (bdu/matching.py)
    db.execute(text("DELETE FROM asset_vulnerability_state WHERE asset_id = :a"), {"a": asset.id})
    if payload.software:
        # Одним пакетным INSERT, а не объектами ORM: у сервера бывает полторы тысячи программ, и поштучный
        # учёт объектов был основной ценой отчёта (нагрузочный тест: 1000 хостов за одним NAT).
        db.execute(insert(Software), [
            {"asset_id": asset.id, "name": item.name, "version": item.version, "vendor": item.vendor,
             "category": item.category, "type": item.type}
            for item in payload.software
        ])

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

    # Номер скана — по порядку в организации. Параллельные отчёты разных хостов одной организации берут его
    # по очереди: блокировка до конца транзакции, иначе MAX + 1 выдавал одинаковые номера (нагрузочный тест —
    # 772 скана, 110 разных номеров). Блокировка — как можно позже: тяжёлая часть отчёта уже сделана.
    db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:key))"), {"key": f"scan_number:{organization_id}"})
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
        collection=collection,
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
