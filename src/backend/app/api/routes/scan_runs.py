"""Прогоны организации: список, страница хостов, нарушения, сравнение, открытие и закрытие.

Чтение — любой участник. Открыть, закрыть и сменить расписание — администратор организации.
Сравнение и выгрузка не меняют данные. Старые ручки снимков остаются в snapshots.py и data.py.
"""
from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db, get_user_role_in_org, require_org_access, require_org_admin
from app.models.user import User
from app.services.scan_runs import (
    HOST_STATUSES,
    ScanRunError,
    close_run,
    compare_runs,
    list_findings,
    list_hosts,
    list_runs,
    load_run,
    open_manual_run,
    org_schedule,
    run_detail,
    set_org_schedule,
)

router = APIRouter(dependencies=[Depends(get_current_user)])


class OpenRunIn(BaseModel):
    label: str | None = Field(default=None, max_length=200)
    environment_id: UUID | None = None
    closes_at: datetime | None = None


class ScheduleIn(BaseModel):
    schedule: str = Field(..., pattern="^(daily|weekly)$")


def _http(exc: ScanRunError) -> HTTPException:
    return HTTPException(status_code=exc.status_code, detail=exc.detail)


def _run_or_404(db: Session, run_id: UUID, user: User):
    run = load_run(db, str(run_id))
    if run is None:
        raise HTTPException(status_code=404, detail="Прогон не найден")
    if not get_user_role_in_org(db, user, str(run.organization_id)):
        raise HTTPException(status_code=403, detail="Нет доступа к этому прогону")
    return run


@router.get("/scan-runs/compare")
def get_scan_run_compare(
    before: UUID = Query(..., alias="before_run_id"),
    after: UUID = Query(..., alias="after_run_id"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    left, right = _run_or_404(db, before, current_user), _run_or_404(db, after, current_user)
    try:
        return compare_runs(db, left, right, limit=limit, offset=offset)
    except ScanRunError as exc:
        raise _http(exc) from exc


@router.get("/organizations/{organization_id}/scan-runs")
def get_scan_runs(
    organization_id: str,
    status: str | None = Query(None, pattern="^(open|closed)$"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    _: User = Depends(require_org_access),
    db: Session = Depends(get_db),
):
    """Прогоны организации, новые сначала. Сводка — суммы уже посчитанных снимков, без перебора проверок."""
    return list_runs(db, organization_id, status=status, limit=limit, offset=offset)


@router.get("/organizations/{organization_id}/scan-schedule")
def get_scan_schedule(
    organization_id: str,
    _: User = Depends(require_org_access),
    db: Session = Depends(get_db),
):
    return {"schedule": org_schedule(db, organization_id)}


@router.put("/organizations/{organization_id}/scan-schedule")
def put_scan_schedule(
    organization_id: str,
    body: ScheduleIn,
    _: User = Depends(require_org_admin),
    db: Session = Depends(get_db),
):
    """Расписание следующих автопрогонов. Уже открытое окно не переписывается."""
    try:
        schedule = set_org_schedule(db, organization_id, body.schedule)
    except ScanRunError as exc:
        raise _http(exc) from exc
    return {"schedule": schedule}


@router.post("/organizations/{organization_id}/scan-runs", status_code=201)
def post_scan_run(
    organization_id: str,
    body: OpenRunIn,
    current_user: User = Depends(require_org_admin),
    db: Session = Depends(get_db),
):
    try:
        run = open_manual_run(
            db, organization_id, user_id=str(current_user.id), label=body.label,
            environment_id=str(body.environment_id) if body.environment_id else None,
            closes_at=body.closes_at,
        )
    except ScanRunError as exc:
        raise _http(exc) from exc
    return run_detail(db, run)


@router.post("/scan-runs/{run_id}/close")
def post_close_run(
    run_id: UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    run = _run_or_404(db, run_id, current_user)
    if get_user_role_in_org(db, current_user, str(run.organization_id)) != "admin":
        raise HTTPException(status_code=403, detail="Нужна роль администратора организации")
    try:
        run = close_run(db, run, user_id=str(current_user.id))
    except ScanRunError as exc:
        raise _http(exc) from exc
    return run_detail(db, run)


@router.get("/scan-runs/{run_id}")
def get_scan_run(
    run_id: UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    run = _run_or_404(db, run_id, current_user)
    return run_detail(db, run)


@router.get("/scan-runs/{run_id}/hosts")
def get_scan_run_hosts(
    run_id: UUID,
    q: str = Query("", max_length=255),
    status: str = Query("", pattern="^(|failed|clean|unchecked)$"),
    environment_id: UUID | None = Query(None),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Страница хостов прогона. Фильтр и поиск — в SQL по индексу run_id, не по всей истории организации."""
    if status not in HOST_STATUSES:
        raise HTTPException(status_code=422, detail="Статус: failed, clean или unchecked")
    _run_or_404(db, run_id, current_user)
    return list_hosts(
        db, str(run_id), q=q.strip(), status=status,
        environment_id=str(environment_id) if environment_id else None,
        limit=limit, offset=offset,
    )


@router.get("/scan-runs/{run_id}/findings")
def get_scan_run_findings(
    run_id: UUID,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Нарушения прогона по правилам: сколько хостов задело каждое. Принятый риск сюда не входит."""
    _run_or_404(db, run_id, current_user)
    return list_findings(db, str(run_id), limit=limit, offset=offset)
