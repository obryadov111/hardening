"""Сопоставление установленного ПО активов организации с уязвимыми версиями из БДУ.

Результат — потенциальные уязвимости: версия пакета попадает в уязвимый диапазон БДУ. Дистрибутивы
переносят исправления в старые версии без смены номера, поэтому каждую находку нужно сверить с
бюллетенем дистрибутива (для Ubuntu — USN); это сказано и в интерфейсе.

Если для релиза Ubuntu актива загружены OVAL-данные Canonical (ubuntu_oval.py), каждая находка
получает статус дистрибутива: исправление вышло, но не установлено; исправления нет; исправлено
(в счёт по уровням не входит); нет данных — остаётся потенциальной.

Если на активе несколько пакетов одного продукта (несколько ядер, openssh-client и openssh-server),
сравнивается наибольшая версия — остальные, как правило, не используются (старые ядра).

Находки хранятся (asset_vulnerabilities), а не считаются на каждый запрос: на тысяче хостов расчёт
занимал 310 с. Актив пересчитывается при чтении, если находок для него ещё нет (новый отчёт агента
сбрасывает их — ingest.py) или они посчитаны по прежней копии БДУ, прежним данным Ubuntu или другой ОС.
Сравнение версий и статус Ubuntu — по уникальным парам «продукт — версия»: у тысячи одинаково
настроенных хостов они повторяются. Уровень V (часть зависит от доли поражённых активов организации) —
в SQL при запросе; части, зависящие только от уязвимости, посчитаны при импорте БДУ (importer.py).
"""
import json
from functools import lru_cache

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.services.bdu.criticality import COMPONENT_K, COMPONENT_K_DEFAULT
from app.services.bdu.products import not_compared_reason, product_for_package
from app.services.bdu.ubuntu_oval import distro_status, load_distro_index, ubuntu_release
from app.services.bdu.versions import VersionRange, compare, upstream_version
from app.services.remediation import REMEDIATION_BY_SEVERITY

LEVEL_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
DISTRO_FILTERS = ("all", "open", "vulnerable", "unfixed", "fixed", "unknown", "not_checked")


def latest_import(db: Session) -> dict | None:
    row = db.execute(
        text("SELECT imported_at, source, vulnerabilities, software_rows FROM bdu_imports ORDER BY imported_at DESC LIMIT 1")
    ).mappings().first()
    return dict(row) if row else None


def _oval_releases(db: Session) -> dict[str, str]:
    """{релиз Ubuntu: время последней загрузки его данных} — часть отметки, по которой находки устаревают."""
    rows = db.execute(text(
        "SELECT release, max(imported_at) FROM distro_oval_imports WHERE distro = 'ubuntu' GROUP BY release"
    )).all()
    return {release: imported.isoformat() for release, imported in rows}


def _distro_key(os_name: str | None, oval: dict[str, str]) -> str:
    release = ubuntu_release(os_name)
    return f"{release}@{oval[release]}" if release in oval else f"{release or '-'}@-"


# ---------- расчёт находок активов ----------

def _installed_products(db: Session, asset_ids: list[str]):
    """{asset_id: {product: (package, installed_version, upstream_version)}} — наибольшая версия продукта;
    {asset_id: {причина: пример пакета}} — пакеты, которые сознательно не сопоставляются."""
    result: dict[str, dict[str, tuple[str, str, str]]] = {aid: {} for aid in asset_ids}
    skipped: dict[str, dict[str, str]] = {aid: {} for aid in asset_ids}
    rows = db.execute(
        text("SELECT asset_id, name, version FROM software WHERE asset_id = ANY(CAST(:ids AS uuid[])) AND version IS NOT NULL"),
        {"ids": asset_ids},
    ).all()
    for asset_id, package, version in rows:
        aid = str(asset_id)
        if reason := not_compared_reason(package):
            skipped[aid].setdefault(reason, package)
            continue
        product = product_for_package(package)
        if not product:
            continue
        upstream = _upstream(version)
        if not upstream or not upstream[0].isdigit():
            continue
        products = result[aid]
        current = products.get(product)
        diff = 1 if current is None else _compare(upstream, current[2])
        if diff > 0:
            products[product] = (package, version, upstream)
        elif diff == 0 and package not in current[0].split(", "):
            # Несколько пакетов одного продукта той же версии (openssh-client и openssh-server) — все в находке.
            products[product] = (", ".join(sorted([*current[0].split(", "), package])), current[1], upstream)
    return result, skipped


@lru_cache(maxsize=200_000)
def _upstream(version: str) -> str:
    return upstream_version(version)


@lru_cache(maxsize=200_000)
def _compare(a: str, b: str) -> int:
    return compare(a, b)


def refresh_findings(db: Session, organization_id: str) -> None:
    """Пересчитать находки активов организации, для которых они отсутствуют или устарели."""
    # Два процесса сервера не считают одну организацию одновременно; второй дождётся и увидит готовое.
    db.execute(text("SELECT pg_advisory_xact_lock(hashtext('vulnerabilities:' || :org))"), {"org": organization_id})
    bdu = latest_import(db)
    bdu_at = bdu["imported_at"] if bdu else None
    oval = _oval_releases(db)
    assets = db.execute(text("""
        SELECT a.id, a.os, s.bdu_imported_at, s.distro_key
        FROM assets a
        JOIN environments e ON e.id = a.environment_id
        LEFT JOIN asset_vulnerability_state s ON s.asset_id = a.id
        WHERE e.organization_id = :org
    """), {"org": organization_id}).mappings().all()
    stale = [
        a for a in assets
        if a["distro_key"] is None or a["bdu_imported_at"] != bdu_at or a["distro_key"] != _distro_key(a["os"], oval)
    ]
    if stale:
        _refresh_assets(db, organization_id, stale, bdu, oval)
    scored = db.execute(text("SELECT total_assets FROM vulnerability_org_state WHERE organization_id = :org"),
                        {"org": organization_id}).scalar()
    if stale or scored != len(assets):
        _score(db, organization_id, len(assets))
    db.commit()


def _refresh_assets(db: Session, organization_id: str, stale, bdu: dict | None, oval: dict[str, str]) -> None:
    bdu_at = bdu["imported_at"] if bdu else None

    ids = [str(a["id"]) for a in stale]
    installed, skipped = _installed_products(db, ids)
    products = sorted({product for per_asset in installed.values() for product in per_asset})
    candidates = db.execute(
        text("""
            SELECT s.product, s.version_expr, s.lo, s.lo_incl, s.hi, s.hi_incl, v.bdu_id, v.cves
            FROM bdu_software s JOIN bdu_vulnerabilities v ON v.bdu_id = s.bdu_id
            WHERE s.product = ANY(:products)
        """),
        {"products": products},
    ).mappings().all() if products and bdu else []
    by_product: dict[str, list] = {}
    for row in candidates:
        by_product.setdefault(row["product"], []).append(row)

    # Уязвимые диапазоны — один раз на пару «продукт — версия», а не на каждый актив.
    matched: dict[tuple[str, str], list] = {}

    def vulnerable_rows(product: str, upstream: str) -> list:
        key = (product, upstream)
        if key not in matched:
            seen, rows = set(), []
            for row in by_product.get(product, ()):
                if row["bdu_id"] in seen:
                    continue
                if VersionRange(row["lo"], row["lo_incl"], row["hi"], row["hi_incl"]).contains(upstream):
                    seen.add(row["bdu_id"])
                    rows.append(row)
            matched[key] = rows
        return matched[key]

    os_by_id = {str(a["id"]): a["os"] for a in stale}
    findings = []  # (asset_id, row, package_info)
    needed: dict[str, set[str]] = {}
    for aid, per_asset in installed.items():
        release = ubuntu_release(os_by_id[aid])
        seen_bdu: set[str] = set()
        # Уязвимость БДУ может перечислять несколько продуктов (OpenSSH и OpenSSL): на активе — одна находка,
        # по первому продукту в алфавитном порядке.
        for product in sorted(per_asset):
            info = per_asset[product]
            for row in vulnerable_rows(product, info[2]):
                if row["bdu_id"] in seen_bdu:
                    continue
                seen_bdu.add(row["bdu_id"])
                findings.append((aid, row, info))
                if release in oval and row["cves"]:
                    needed.setdefault(release, set()).update(row["cves"].split(","))
    distro_index = {release: load_distro_index(db, release, cves) for release, cves in needed.items()}

    statuses: dict[tuple, dict] = {}
    records = []
    for aid, row, (package, installed_version, upstream) in findings:
        release = ubuntu_release(os_by_id[aid])
        distro = None
        if release in oval:
            cves = tuple(row["cves"].split(",")) if row["cves"] else ()
            key = (release, cves, package, installed_version)
            if key not in statuses:
                statuses[key] = {"distro": "ubuntu", "release": release,
                                 **distro_status(distro_index.get(release, {}), list(cves), package.split(", "), installed_version)}
            distro = statuses[key]
        records.append({
            "a": aid, "o": organization_id, "b": row["bdu_id"], "p": row["product"], "pk": package, "iv": installed_version, "cv": upstream,
            "vv": row["version_expr"], "ds": distro["status"] if distro else None,
            "d": json.dumps(distro, ensure_ascii=False) if distro else None,
        })

    db.execute(text("DELETE FROM asset_vulnerabilities WHERE asset_id = ANY(CAST(:ids AS uuid[]))"), {"ids": ids})
    for start in range(0, len(records), 5000):
        db.execute(text("""
            INSERT INTO asset_vulnerabilities (asset_id, organization_id, bdu_id, product, package, installed_version,
                                               compared_version, vulnerable_versions, distro_status, distro)
            VALUES (:a, :o, :b, :p, :pk, :iv, :cv, :vv, :ds, CAST(:d AS jsonb))
        """), records[start:start + 5000])
    db.execute(text("""
        INSERT INTO asset_vulnerability_state (asset_id, bdu_imported_at, distro_key, products, skipped, computed_at)
        VALUES (:a, :bdu, :dk, :p, CAST(:s AS jsonb), now())
        ON CONFLICT (asset_id) DO UPDATE SET bdu_imported_at = EXCLUDED.bdu_imported_at, distro_key = EXCLUDED.distro_key,
            products = EXCLUDED.products, skipped = EXCLUDED.skipped, computed_at = EXCLUDED.computed_at
    """), [
        {"a": aid, "bdu": bdu_at, "dk": _distro_key(os_by_id[aid], oval), "p": sorted(installed[aid]),
         "s": json.dumps(skipped[aid], ensure_ascii=False)}
        for aid in ids
    ])


# ---------- уровень V ----------

def _sql_case(mapping: dict[str, float], default: float, column: str) -> str:
    whens = " ".join(f"WHEN '{key}' THEN {value!r}::numeric" for key, value in mapping.items())
    return f"CASE lower(coalesce({column}, '')) {whens} ELSE {default!r}::numeric END"


# Та же формула, что criticality() в Python (тест test_bdu: SQL и Python совпадают), в точной десятичной
# арифметике (numeric), как и там: V = Icvss × Iinfr × (Iat + Iimp), Iinfr = 0,5·K + 0,2·L + 0,3·P;
# L — доля активов организации с этой уязвимостью, P — доступ из интернета.
_SCORE = f"""
WITH affected AS (
    SELECT bdu_id, count(*)::numeric AS n FROM asset_vulnerabilities WHERE organization_id = :org GROUP BY bdu_id
),
s AS (
    SELECT av.asset_id, av.bdu_id, v.icvss, v.iat, v.iimp,
           0.5 * {_sql_case(COMPONENT_K, COMPONENT_K_DEFAULT, "a.asset_type")}
           + 0.2 * (CASE WHEN aff.n / :total > 0.7 THEN 1.0 WHEN aff.n / :total >= 0.5 THEN 0.8
                         WHEN aff.n / :total >= 0.1 THEN 0.6 ELSE 0.5 END)
           + 0.3 * (CASE WHEN coalesce(a.platform_tags, '[]'::jsonb) ? 'internet-facing' THEN 1.1 ELSE 0.6 END) AS iinfr
    FROM asset_vulnerabilities av
    JOIN assets a ON a.id = av.asset_id
    JOIN affected aff ON aff.bdu_id = av.bdu_id
    JOIN bdu_vulnerabilities v ON v.bdu_id = av.bdu_id
    WHERE av.organization_id = :org
),
c AS (
    SELECT s.*, CASE WHEN s.icvss IS NULL THEN NULL ELSE round(s.icvss * s.iinfr * (s.iat + s.iimp), 2) END AS v FROM s
),
scored AS (
    SELECT c.*, CASE WHEN c.v IS NULL THEN NULL WHEN c.v > 8 THEN 'critical' WHEN c.v >= 5 THEN 'high'
                     WHEN c.v >= 2 THEN 'medium' ELSE 'low' END AS level
    FROM c
)
UPDATE asset_vulnerabilities av
SET iinfr = round(scored.iinfr, 3), v = scored.v, level = scored.level,
    level_rank = CASE scored.level WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 9 END
FROM scored
WHERE av.asset_id = scored.asset_id AND av.bdu_id = scored.bdu_id
  AND (av.v IS DISTINCT FROM scored.v OR av.iinfr IS DISTINCT FROM round(scored.iinfr, 3) OR av.level IS DISTINCT FROM scored.level)
"""


def _score(db: Session, organization_id: str, total_assets: int) -> None:
    """V и уровень всех находок организации: доля поражённых активов (L) зависит от всех её активов. Пишутся
    только изменившиеся строки — обычно находки пересчитанных активов."""
    if total_assets:
        db.execute(text(_SCORE), {"org": organization_id, "total": total_assets})
    db.execute(text("""
        INSERT INTO vulnerability_org_state (organization_id, total_assets, scored_at) VALUES (:org, :n, now())
        ON CONFLICT (organization_id) DO UPDATE SET total_assets = EXCLUDED.total_assets, scored_at = EXCLUDED.scored_at
    """), {"org": organization_id, "n": total_assets})


# ---------- выдача ----------

_FINDINGS = """
FROM asset_vulnerabilities av
JOIN assets a ON a.id = av.asset_id
JOIN bdu_vulnerabilities v ON v.bdu_id = av.bdu_id
WHERE av.organization_id = :org
"""


def _filters(asset_id, level, distro, q) -> tuple[str, dict]:
    where, params = [], {}
    if asset_id:
        where.append("av.asset_id = CAST(:asset AS uuid)")
        params["asset"] = asset_id
    if level == "unscored":
        where.append("av.level IS NULL")
    elif level:
        where.append("av.level = :level")
        params["level"] = level
    if distro == "open":
        where.append("av.distro_status IS DISTINCT FROM 'fixed'")
    elif distro == "not_checked":
        where.append("av.distro_status IS NULL")
    elif distro and distro != "all":
        where.append("av.distro_status = :distro")
        params["distro"] = distro
    if q and q.strip():
        where.append("(av.bdu_id ILIKE :q OR v.name ILIKE :q OR av.package ILIKE :q OR av.product ILIKE :q "
                     "OR a.hostname ILIKE :q OR coalesce(v.cves, '') ILIKE :q)")
        params["q"] = "%" + q.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    return "".join(f" AND {w}" for w in where), params


def _item(row) -> dict:
    level = row["level"]
    crit = None
    if row["v"] is not None:
        crit = {"v": float(row["v"]), "level": level, "icvss": float(row["icvss"]), "cvss_version": row["cvss_version"],
                "iinfr": float(row["iinfr"]), "iat": float(row["iat"]), "iimp": float(row["iimp"]),
                "impact": row["impact"], "exploitation": row["exploitation"]}
    return {
        "asset": {"id": str(row["asset_id"]), "hostname": row["hostname"]},
        "package": row["package"],
        "installed_version": row["installed_version"],
        "compared_version": row["compared_version"],
        "product": row["product"],
        "vulnerable_versions": row["vulnerable_versions"],
        "bdu_id": row["bdu_id"],
        "name": row["name"],
        "cves": row["cves"].split(",") if row["cves"] else [],
        "fix_status": row["fix_status"],
        "solution": row["solution"],
        "criticality": crit,
        "level": level,
        "deadline": REMEDIATION_BY_SEVERITY[level].deadline if level else None,
        # Статус по данным дистрибутива; None — релиз не Ubuntu или данные для него не загружены.
        "distro": row["distro"],
    }


def organization_vulnerabilities(
    db: Session, organization_id: str, asset_id: str | None = None, *,
    level: str | None = None, distro: str = "all", q: str = "", limit: int = 100, offset: int = 0,
) -> dict:
    """Страница находок (сначала самые критичные) и сводка. summary и total — открытые находки (без
    исправленных в дистрибутиве: уязвимости на активе уже нет); found — сколько подходит под фильтры."""
    refresh_findings(db, organization_id)
    base = {"org": organization_id}
    where, params = _filters(asset_id, level, distro, q)
    rows = db.execute(text(f"""
        SELECT av.*, a.hostname, v.name, v.cves, v.fix_status, v.solution, v.icvss, v.cvss_version, v.iat, v.iimp,
               v.impact, v.exploitation
        {_FINDINGS} {where}
        ORDER BY av.level_rank, av.v DESC NULLS LAST, av.bdu_id, a.hostname
        LIMIT :limit OFFSET :offset
    """), {**base, **params, "limit": limit, "offset": offset}).mappings().all()
    found = db.execute(text(f"SELECT count(*) {_FINDINGS} {where}"), {**base, **params}).scalar()

    scope, scope_params = _filters(asset_id, None, "all", "")
    groups = db.execute(text(f"""
        SELECT av.distro_status, av.level, count(*) AS n {_FINDINGS} {scope} GROUP BY av.distro_status, av.level
    """), {**base, **scope_params}).all()
    summary = {key: 0 for key in ("critical", "high", "medium", "low", "unscored")}
    distro_summary = {key: 0 for key in ("vulnerable", "unfixed", "fixed", "unknown", "not_checked")}
    for status, lvl, n in groups:
        distro_summary[status or "not_checked"] += n
        if status != "fixed":
            summary[lvl or "unscored"] += n

    state_scope = "AND a.id = CAST(:asset AS uuid)" if asset_id else ""
    states = db.execute(text(f"""
        SELECT s.products, s.skipped FROM asset_vulnerability_state s
        JOIN assets a ON a.id = s.asset_id JOIN environments e ON e.id = a.environment_id
        WHERE e.organization_id = :org {state_scope}
    """), {**base, **scope_params}).all()
    products = sorted({p for row in states for p in row.products})
    skipped: dict[str, str] = {}
    for row in states:
        for reason, package in (row.skipped or {}).items():
            skipped.setdefault(reason, package)

    return {
        "import": latest_import(db),
        "assets_checked": sum(1 for row in states if row.products),
        "products_checked": len(products),
        # Продукты, установленные на активах (для отчёта по методике: пункт о ПО, которого нет, — «не применялось»).
        "installed_products": products,
        "total": sum(summary.values()),
        "found": found,
        "limit": limit,
        "offset": offset,
        "summary": summary,
        "distro_summary": distro_summary,
        "oval": [dict(r) for r in db.execute(text(
            "SELECT DISTINCT ON (release) release, imported_at, cves FROM distro_oval_imports WHERE distro = 'ubuntu' "
            "ORDER BY release, imported_at DESC"
        )).mappings().all()],
        "not_compared": [{"example": package, "reason": reason} for reason, package in skipped.items()],
        "items": [_item(row) for row in rows],
    }


def open_findings_by_product(db: Session, organization_id: str) -> dict:
    """Для отчёта по методике ФСТЭК: открытые находки по продуктам и уровням и установленные продукты."""
    refresh_findings(db, organization_id)
    rows = db.execute(text("""
        SELECT product, level, count(*) AS n FROM asset_vulnerabilities
        WHERE organization_id = :org AND distro_status IS DISTINCT FROM 'fixed' GROUP BY product, level
    """), {"org": organization_id}).all()
    products = db.execute(text("""
        SELECT DISTINCT unnest(s.products) FROM asset_vulnerability_state s
        JOIN assets a ON a.id = s.asset_id JOIN environments e ON e.id = a.environment_id
        WHERE e.organization_id = :org
    """), {"org": organization_id}).scalars().all()
    return {"import": latest_import(db), "open": [(r.product, r.level, r.n) for r in rows], "installed_products": set(products)}
