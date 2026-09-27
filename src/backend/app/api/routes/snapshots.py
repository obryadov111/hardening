"""Сравнение двух снимков сканирования: что исправлено, что ухудшилось, что появилось.

Снимок создаётся на каждый прогон агента и обычно покрывает один актив, поэтому сравнивать можно
только снимки с общими активами. Ключ сравнения — (актив, проверка); проверка — код правила или
id проверки пака. id проверки сохраняется между версиями пака, поэтому результаты разных версий
сравнимы, а переименованная проверка честно видна как «удалено» + «новое».
"""
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db, get_user_role_in_org
from app.models.user import User

router = APIRouter(dependencies=[Depends(get_current_user)])

# Порядок в таблице: сначала то, что требует внимания.
CHANGE_ORDER = {"regressed": 0, "new": 1, "still_failed": 2, "changed": 3, "fixed": 4, "removed": 5}

_SNAPSHOT_HEAD = """
    SELECT id, organization_id, scan_number, snapshot_label, total_checks, passed, failed,
           compliance_score, status, total_assets, created_at
    FROM scan_snapshots WHERE id = :sid
"""

_SNAPSHOT_RESULTS = """
    SELECT scr.asset_id, a.hostname, scr.status,
           COALESCE(scr.expected_value, r.expected_value) AS expected_value,
           COALESCE(r.rule_code, scr.check_id) AS check_key,
           COALESCE(r.title, scr.title) AS title,
           COALESCE(r.severity, scr.severity) AS severity
    FROM scan_check_results scr
    LEFT JOIN assets a ON a.id = scr.asset_id
    LEFT JOIN hardening_rules r ON r.id = scr.rule_id
    WHERE scr.snapshot_id = :sid
"""


def classify(before: str | None, after: str | None) -> str | None:
    """Тип изменения; None — изменений нет (pass→pass, error→error), в таблицу не попадает."""
    if before is None:
        return "new"
    if after is None:
        return "removed"
    if before == "fail" and after == "pass":
        return "fixed"
    if before == "pass" and after == "fail":
        return "regressed"
    if before == "fail" and after == "fail":
        return "still_failed"
    if before != after:
        return "changed"  # с участием error: стало/перестало проверяться
    return None


def _load_snapshot(db: Session, snapshot_id: UUID, user: User) -> dict:
    head = db.execute(text(_SNAPSHOT_HEAD), {"sid": str(snapshot_id)}).mappings().first()
    if head is None:
        raise HTTPException(status_code=404, detail="Снимок не найден")
    org_id = head["organization_id"]
    if (org_id is None and not user.is_superadmin) or (org_id is not None and not get_user_role_in_org(db, user, str(org_id))):
        raise HTTPException(status_code=403, detail="Нет доступа к этому снимку")
    return dict(head)


def _results(db: Session, snapshot_id: UUID) -> dict:
    rows = db.execute(text(_SNAPSHOT_RESULTS), {"sid": str(snapshot_id)}).mappings().all()
    return {(str(r["asset_id"]), r["check_key"]): dict(r) for r in rows if r["check_key"]}


@router.get("/snapshots/compare")
def compare_snapshots(
    before_snapshot_id: UUID = Query(...),
    after_snapshot_id: UUID = Query(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    before = _load_snapshot(db, before_snapshot_id, current_user)
    after = _load_snapshot(db, after_snapshot_id, current_user)
    if before["organization_id"] != after["organization_id"]:
        raise HTTPException(status_code=400, detail="Снимки относятся к разным организациям")

    before_rows, after_rows = _results(db, before_snapshot_id), _results(db, after_snapshot_id)
    before_assets = {asset for asset, _ in before_rows}
    after_assets = {asset for asset, _ in after_rows}
    common = before_assets & after_assets

    diffs = []
    # Сравниваются только общие активы: актив, которого нет в одном из снимков, не «удалён» и не
    # «новый» — он просто не сканировался в этом прогоне.
    for key in sorted({k for k in (*before_rows, *after_rows) if k[0] in common}):
        was, now = before_rows.get(key), after_rows.get(key)
        change = classify(was and was["status"], now and now["status"])
        if change is None:
            continue
        meta = now or was
        diffs.append({
            "key": f"{key[0]}:{key[1]}",
            "asset": {"id": key[0], "hostname": meta["hostname"]},
            "rule": {"title": meta["title"], "rule_code": key[1], "severity": meta["severity"]},
            "beforeStatus": was and was["status"],
            "afterStatus": now and now["status"],
            "expectedValue": meta["expected_value"],
            "changeType": change,
        })
    diffs.sort(key=lambda d: (CHANGE_ORDER[d["changeType"]], d["asset"]["hostname"] or "", d["rule"]["rule_code"]))

    def count(change_type, status=None):
        return sum(1 for d in diffs if d["changeType"] == change_type and (status is None or d["afterStatus"] == status))

    return {
        "beforeSnapshot": before,
        "afterSnapshot": after,
        "commonAssets": len(common),
        "onlyBeforeAssets": len(before_assets - after_assets),
        "onlyAfterAssets": len(after_assets - before_assets),
        "summary": {
            "fixed": count("fixed"),
            "regressed": count("regressed"),
            "stillFailed": count("still_failed"),
            "newIssues": count("new", "fail"),
            "removed": count("removed"),
            "changed": count("changed"),
        },
        "diffs": diffs,
    }
