"""Выгрузка снимка сканирования (Excel / PDF). Файл формируется на лету — см. services/snapshot_export.py."""
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db, get_user_role_in_org
from app.models.user import User
from app.services.scan_run_export import filename_stem, load_run_export
from app.services.scan_run_export import to_pdf as run_to_pdf
from app.services.scan_run_export import to_xlsx as run_to_xlsx
from app.services.snapshot_export import ExportFontError, load_snapshot_report, to_pdf, to_xlsx

router = APIRouter(dependencies=[Depends(get_current_user)])

FORMATS = {
    "excel": ("xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", to_xlsx),
    "pdf": ("pdf", "application/pdf", to_pdf),
}


@router.get("/exports/snapshots/{snapshot_id}/download")
def download_snapshot_export(
    snapshot_id: UUID,
    format: Literal["excel", "pdf"] = Query(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """404 — снимка нет, 403 — нет доступа к его организации (как у остальных данных организации)."""
    row = db.execute(
        text("SELECT organization_id FROM scan_snapshots WHERE id = :sid"), {"sid": str(snapshot_id)}
    ).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Снимок не найден")
    if row.organization_id is None and not current_user.is_superadmin:
        raise HTTPException(status_code=403, detail="Нет доступа к этому снимку")
    if row.organization_id is not None and not get_user_role_in_org(db, current_user, str(row.organization_id)):
        raise HTTPException(status_code=403, detail="Нет доступа к этому снимку")

    report = load_snapshot_report(db, str(snapshot_id))
    extension, media_type, render = FORMATS[format]
    try:
        content = render(report)
    except ExportFontError as exc:
        raise HTTPException(status_code=503, detail=f"PDF недоступен: {exc}") from exc

    filename = f"{report.filename_stem}.{extension}"
    return Response(
        content=content,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            # отчёт аудита — не кэшировать ни в браузере, ни на промежуточных прокси
            "Cache-Control": "no-store",
        },
    )


@router.get("/exports/scan-runs/{run_id}/download")
def download_run_export(
    run_id: UUID,
    format: Literal["excel", "pdf"] = Query(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Сводка прогона: оценка, хосты, нарушения по правилам. Доступ — как у снимка, роль администратора не нужна."""
    row = db.execute(
        text("SELECT organization_id FROM scan_runs WHERE id = :rid"), {"rid": str(run_id)},
    ).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Прогон не найден")
    if not get_user_role_in_org(db, current_user, str(row.organization_id)):
        raise HTTPException(status_code=403, detail="Нет доступа к этому прогону")
    report = load_run_export(db, str(run_id))
    if report is None:
        raise HTTPException(status_code=404, detail="Прогон не найден")
    extension, media_type, render = {
        "excel": ("xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", run_to_xlsx),
        "pdf": ("pdf", "application/pdf", run_to_pdf),
    }[format]
    try:
        content = render(report)
    except ExportFontError as exc:
        raise HTTPException(status_code=503, detail=f"PDF недоступен: {exc}") from exc
    filename = f"{filename_stem(report['detail'])}.{extension}"
    return Response(
        content=content,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            # отчёт аудита — не кэшировать ни в браузере, ни на промежуточных прокси
            "Cache-Control": "no-store",
        },
    )
