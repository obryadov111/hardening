"""Покрытие методики ФСТЭК от 25.11.2025 по пунктам — по текущему состоянию активов организации.

Для пункта с проверками берутся результаты проверок паков, у которых в refs есть id пункта (ссылки
берутся из той версии пака, которой проверка выполнена). Статус пункта:
- violated — хотя бы одно нарушение без принятого риска;
- accepted — нарушения есть, но по всем принят риск;
- passed — все выполненные проверки соблюдены;
- not_checked — проверки есть, но ни одна не выполнилась (нет прав, файла, службы);
- not_applied — проверки по пункту есть в паках, но к активам организации не применялись (нет такой
  платформы: например, пак postgresql без PostgreSQL);
- no_checks — проверок по пункту ещё нет;
- out — вне модели проекта (причина — в каталоге).
Для пунктов «уязвимости ПО» — открытые находки БДУ (без исправленного в дистрибутиве) по продуктам пункта.
"""
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.services.bdu.matching import open_findings_by_product
from app.services.fstec.catalog import CATALOG, SOURCE
from app.services.packs.registry import PackRegistry

CHECKS_SHOWN = 50
STATUS_ORDER = ["violated", "accepted", "not_checked", "passed", "not_applied", "no_checks", "out"]


def _item_ids(check) -> set[str]:
    return {ref.id for ref in check.refs if ref.id and ref.source == SOURCE}


def organization_coverage(db: Session, organization_id: str, registry: PackRegistry) -> dict:
    rows = db.execute(
        text("""
            SELECT hc.check_id, hc.pack_id, hc.pack_version, hc.status, hc.risk_exception_id, hc.title, a.hostname
            FROM hardening_checks hc
            JOIN assets a ON a.id = hc.asset_id
            JOIN environments e ON e.id = a.environment_id
            WHERE e.organization_id = :org_id AND hc.pack_id IS NOT NULL
        """),
        {"org_id": organization_id},
    ).mappings().all()

    results: dict[str, list[dict]] = {}
    for row in rows:
        pack = registry.get(row["pack_id"], row["pack_version"])
        check = next((c for c in pack.checks if c.id == row["check_id"]), None) if pack else None
        if check is None:
            continue
        status = "accepted" if row["status"] == "fail" and row["risk_exception_id"] else row["status"]
        for item in _item_ids(check):
            results.setdefault(item, []).append({
                "check_id": row["check_id"], "title": row["title"] or check.title, "pack": f"{row['pack_id']} {row['pack_version']}",
                "asset": row["hostname"], "status": status,
            })

    # Какие пункты вообще закрываются проверками паков (последние версии) — чтобы отличить
    # «к активам не применялось» от «проверок нет».
    available: dict[str, set[str]] = {}
    for pack in registry.latest():
        for check in pack.checks:
            for item in _item_ids(check):
                available.setdefault(item, set()).add(pack.pack)

    vulnerabilities = open_findings_by_product(db, organization_id)
    installed = vulnerabilities["installed_products"]

    sections, summary = [], {s: 0 for s in STATUS_ORDER}
    for section in CATALOG:
        items = []
        for item in section.items:
            entry = {"code": item.code, "title": item.title, "kind": item.kind, "note": item.note, "checks": [], "findings": None}
            if item.kind == "out":
                entry["status"] = "out"
            elif item.kind == "bdu" and item.products and not set(item.products) & installed:
                entry["status"] = "not_applied"
                entry["note"] = "на активах нет этого ПО (" + ", ".join(item.products) + ")"
            elif item.kind == "bdu":
                related = [(lvl, n) for product, lvl, n in vulnerabilities["open"] if not item.products or product in item.products]
                levels = {lvl: sum(n for found, n in related if found == lvl) for lvl in ("critical", "high", "medium", "low")}
                entry["findings"] = {"total": sum(n for _, n in related), **levels}
                if vulnerabilities["import"] is None:
                    entry["status"] = "not_checked"
                    entry["note"] = "копия БДУ не загружена"
                else:
                    entry["status"] = "violated" if related else "passed"
            else:
                checks = results.get(item.code, [])
                ordered = sorted(checks, key=lambda c: (c["status"] != "fail", c["status"] != "error", c["check_id"], c["asset"]))
                # На тысяче хостов по пункту — тысячи проверок (6,6 МБ ответа): счётчики по всем, примеры — первые,
                # сначала нарушения; полный список — на странице «Харденинг».
                entry["checks"] = ordered[:CHECKS_SHOWN]
                entry["check_counts"] = {s: sum(1 for c in checks if c["status"] == s) for s in ("fail", "accepted", "pass", "error")}
                entry["check_counts"]["total"] = len(checks)
                statuses = {c["status"] for c in checks}
                if "fail" in statuses:
                    entry["status"] = "violated"
                elif "accepted" in statuses:
                    entry["status"] = "accepted"
                elif "pass" in statuses:
                    entry["status"] = "passed"
                elif statuses:
                    entry["status"] = "not_checked"
                elif item.code in available:
                    entry["status"] = "not_applied"
                    entry["note"] = "проверки есть в паках " + ", ".join(sorted(available[item.code])) + "; к активам организации не применялись"
                else:
                    entry["status"] = "no_checks"
            summary[entry["status"]] += 1
            items.append(entry)
        sections.append({"code": section.code, "title": section.title, "items": items})
    return {"source": SOURCE, "summary": summary, "sections": sections}
