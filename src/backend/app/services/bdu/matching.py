"""Сопоставление установленного ПО активов организации с уязвимыми версиями из БДУ.

Результат — потенциальные уязвимости: версия пакета попадает в уязвимый диапазон БДУ. Дистрибутивы
переносят исправления в старые версии без смены номера, поэтому каждую находку нужно сверить с
бюллетенем дистрибутива (для Ubuntu — USN); это сказано и в интерфейсе.

Если для релиза Ubuntu актива загружены OVAL-данные Canonical (ubuntu_oval.py), каждая находка
получает статус дистрибутива: исправление вышло, но не установлено; исправления нет; исправлено
(в счёт по уровням не входит); нет данных — остаётся потенциальной.

Если на активе несколько пакетов одного продукта (несколько ядер, openssh-client и openssh-server),
сравнивается наибольшая версия — остальные, как правило, не используются (старые ядра).
"""
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.services.bdu.criticality import criticality
from app.services.bdu.products import not_compared_reason, product_for_package
from app.services.bdu.ubuntu_oval import distro_status, load_distro_index, ubuntu_release
from app.services.bdu.versions import VersionRange, compare, upstream_version
from app.services.remediation import REMEDIATION_BY_SEVERITY

LEVEL_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def latest_import(db: Session) -> dict | None:
    row = db.execute(
        text("SELECT imported_at, source, vulnerabilities, software_rows FROM bdu_imports ORDER BY imported_at DESC LIMIT 1")
    ).mappings().first()
    return dict(row) if row else None


def _installed_products(db: Session, asset_ids: list[str], skipped: dict[str, str]):
    """{asset_id: {product: (package, installed_version, upstream_version)}} — наибольшая версия продукта.
    Пакеты, которые сознательно не сопоставляются, попадают в skipped: {причина: пример пакета}."""
    result: dict[str, dict[str, tuple[str, str, str]]] = {}
    rows = db.execute(
        text("SELECT asset_id, name, version FROM software WHERE asset_id = ANY(CAST(:ids AS uuid[])) AND version IS NOT NULL"),
        {"ids": asset_ids},
    ).all()
    for asset_id, package, version in rows:
        if reason := not_compared_reason(package):
            skipped.setdefault(reason, package)
            continue
        product = product_for_package(package)
        if not product:
            continue
        upstream = upstream_version(version)
        if not upstream or not upstream[0].isdigit():
            continue
        products = result.setdefault(str(asset_id), {})
        current = products.get(product)
        diff = 1 if current is None else compare(upstream, current[2])
        if diff > 0:
            products[product] = (package, version, upstream)
        elif diff == 0 and package not in current[0].split(", "):
            # Несколько пакетов одного продукта той же версии (openssh-client и openssh-server) — все в находке.
            products[product] = (", ".join(sorted([*current[0].split(", "), package])), current[1], upstream)
    return result


def organization_vulnerabilities(db: Session, organization_id: str, asset_id: str | None = None) -> dict:
    assets = db.execute(
        text("""
            SELECT a.id, a.hostname, a.asset_type, a.platform_tags, a.os FROM assets a
            JOIN environments e ON e.id = a.environment_id WHERE e.organization_id = :org_id
        """),
        {"org_id": organization_id},
    ).mappings().all()
    assets_by_id = {str(a["id"]): a for a in assets}
    skipped: dict[str, str] = {}
    installed = _installed_products(db, list(assets_by_id), skipped)
    products = sorted({product for per_asset in installed.values() for product in per_asset})

    candidates = db.execute(
        text("""
            SELECT s.product, s.version_expr, s.lo, s.lo_incl, s.hi, s.hi_incl,
                   v.bdu_id, v.name, v.cvss3, v.cvss2, v.exploit_status, v.incident, v.fix_status, v.solution, v.cves
            FROM bdu_software s JOIN bdu_vulnerabilities v ON v.bdu_id = s.bdu_id
            WHERE s.product = ANY(:products)
        """),
        {"products": products},
    ).mappings().all() if products else []

    by_product: dict[str, list] = {}
    for row in candidates:
        by_product.setdefault(row["product"], []).append(row)

    matches: dict[tuple[str, str], tuple[dict, tuple[str, str, str]]] = {}
    for aid, per_asset in installed.items():
        for product, package_info in per_asset.items():
            for row in by_product.get(product, ()):
                if (aid, row["bdu_id"]) in matches:
                    continue
                if VersionRange(row["lo"], row["lo_incl"], row["hi"], row["hi_incl"]).contains(package_info[2]):
                    matches[(aid, row["bdu_id"])] = (row, package_info)

    affected: dict[str, int] = {}
    for _, bdu_id in matches:
        affected[bdu_id] = affected.get(bdu_id, 0) + 1

    oval_releases = {
        r for (r,) in db.execute(text("SELECT DISTINCT release FROM distro_oval_imports WHERE distro = 'ubuntu'")).all()
    }
    # Данные дистрибутива по CVE всех находок — одним запросом на релиз.
    needed: dict[str, set[str]] = {}
    for (aid, _), (row, _) in matches.items():
        release = ubuntu_release(assets_by_id[aid]["os"])
        if release in oval_releases and row["cves"]:
            needed.setdefault(release, set()).update(row["cves"].split(","))
    distro_index = {release: load_distro_index(db, release, cves) for release, cves in needed.items()}

    items = []
    for (aid, bdu_id), (row, (package, installed_version, upstream)) in matches.items():
        if asset_id and aid != asset_id:
            continue
        asset = assets_by_id[aid]
        crit = criticality(
            cvss3=float(row["cvss3"]) if row["cvss3"] is not None else None,
            cvss2=float(row["cvss2"]) if row["cvss2"] is not None else None,
            asset_type=asset["asset_type"], affected_assets=affected[bdu_id], total_assets=len(assets_by_id),
            internet_facing="internet-facing" in (asset["platform_tags"] or []),
            exploit_status=row["exploit_status"], incident=row["incident"], name=row["name"],
        )
        level = crit.level if crit else None
        release = ubuntu_release(asset["os"])
        distro = None
        if release in oval_releases:
            cves = row["cves"].split(",") if row["cves"] else []
            distro = {"distro": "ubuntu", "release": release,
                      **distro_status(distro_index.get(release, {}), cves, package.split(", "), installed_version)}
        items.append({
            "asset": {"id": aid, "hostname": asset["hostname"]},
            "package": package,
            "installed_version": installed_version,
            "compared_version": upstream,
            "product": row["product"],
            "vulnerable_versions": row["version_expr"],
            "bdu_id": bdu_id,
            "name": row["name"],
            "cves": row["cves"].split(",") if row["cves"] else [],
            "fix_status": row["fix_status"],
            "solution": row["solution"],
            "criticality": crit.__dict__ if crit else None,
            "level": level,
            "deadline": REMEDIATION_BY_SEVERITY[level].deadline if level else None,
            # Статус по данным дистрибутива; None — релиз не Ubuntu или данные для него не загружены.
            "distro": distro,
        })
    items.sort(key=lambda i: (LEVEL_ORDER.get(i["level"], 9), -(i["criticality"] or {}).get("v", 0), i["bdu_id"]))

    # Исправленное в дистрибутиве в счёт по уровням не входит: уязвимости на активе уже нет.
    open_items = [i for i in items if not (i["distro"] and i["distro"]["status"] == "fixed")]
    summary = {level: sum(1 for i in open_items if i["level"] == level) for level in LEVEL_ORDER}
    summary["unscored"] = sum(1 for i in open_items if i["level"] is None)
    distro_summary = {s: sum(1 for i in items if i["distro"] and i["distro"]["status"] == s)
                      for s in ("vulnerable", "unfixed", "fixed", "unknown")}
    distro_summary["not_checked"] = sum(1 for i in items if not i["distro"])
    return {
        "import": latest_import(db),
        "assets_checked": len(installed) if not asset_id else int(asset_id in installed),
        "products_checked": len(products),
        # Продукты, установленные на активах (для отчёта по методике: пункт о ПО, которого нет, — «не применялось»).
        "installed_products": products,
        "total": len(open_items),
        "summary": summary,
        "distro_summary": distro_summary,
        "oval": [dict(r) for r in db.execute(text(
            "SELECT DISTINCT ON (release) release, imported_at, cves FROM distro_oval_imports WHERE distro = 'ubuntu' "
            "ORDER BY release, imported_at DESC"
        )).mappings().all()],
        "not_compared": [{"example": package, "reason": reason} for reason, package in skipped.items()],
        "items": items,
    }
