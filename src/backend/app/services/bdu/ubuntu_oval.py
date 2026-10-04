"""Статус CVE в Ubuntu по OVAL-данным Canonical — чтобы отличить «потенциально уязвим» от «уязвим».

Источник: https://security-metadata.canonical.com/oval/com.ubuntu.<релиз>.cve.oval.xml.bz2. В файле на
каждый CVE — определение со списком затронутых исходных пакетов; каждая проверка ссылается на объект
(список бинарных пакетов) и, если исправление вышло, на состояние «версия меньше X». Проверка без
состояния значит «затронута любая версия, исправления пока нет». Ядро Linux в этих данных Canonical
не публикуется.
"""
import bz2
import re
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from xml.etree.ElementTree import iterparse

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.services.bdu.versions import compare_deb

# Версия Ubuntu → кодовое имя релиза (как в именах файлов OVAL).
UBUNTU_RELEASES = {"20.04": "focal", "22.04": "jammy", "24.04": "noble", "24.10": "oracular", "25.04": "plucky", "25.10": "questing"}
OVAL_URL = "https://security-metadata.canonical.com/oval/com.ubuntu.{release}.cve.oval.xml.bz2"


def ubuntu_release(os_name: str | None) -> str | None:
    """«Ubuntu 24.04.4 LTS» → «noble»; не Ubuntu или неизвестный релиз → None."""
    match = re.search(r"ubuntu\s+(\d{2}\.\d{2})", os_name or "", re.I)
    return UBUNTU_RELEASES.get(match.group(1)) if match else None


@dataclass
class OvalStats:
    cves: int = 0
    rows: int = 0


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


@contextmanager
def _open(path: Path):
    opener = bz2.open if path.suffix == ".bz2" else open
    with opener(path, "rb") as stream:
        yield stream


def parse_oval(path: Path):
    """→ список (cve, priority, usns, source, [binaries], fixed_version | None)."""
    definitions = []  # (cve, priority, usns, [(test_ref, source)])
    tests: dict[str, tuple[str, str | None]] = {}
    objects: dict[str, str] = {}
    states: dict[str, str] = {}
    variables: dict[str, list[str]] = {}
    with _open(path) as stream:
        for _, el in iterparse(stream, events=("end",)):
            tag = _local(el.tag)
            if tag == "definition" and el.get("class") == "vulnerability":
                cve_el = next((e for e in el.iter() if _local(e.tag) == "cve"), None)
                refs = [
                    (c.get("test_ref"), c.get("comment", "").split(" source package", 1)[0])
                    for c in el.iter() if _local(c.tag) == "criterion" and " source package " in c.get("comment", "")
                ]
                if cve_el is not None and cve_el.text and refs:
                    usns = ",".join(f"USN-{u}" for u in (cve_el.get("usns") or "").split(",") if u)
                    definitions.append((cve_el.text.strip(), cve_el.get("priority"), usns or None, refs))
                el.clear()
            elif tag == "dpkginfo_test":
                obj = next((c.get("object_ref") for c in el if _local(c.tag) == "object"), None)
                state = next((c.get("state_ref") for c in el if _local(c.tag) == "state"), None)
                tests[el.get("id")] = (obj, state)
                el.clear()
            elif tag == "dpkginfo_object":
                name = next((c for c in el if _local(c.tag) == "name"), None)
                if name is not None and name.get("var_ref"):
                    objects[el.get("id")] = name.get("var_ref")
                el.clear()
            elif tag == "dpkginfo_state":
                evr = next((c for c in el if _local(c.tag) == "evr"), None)
                if evr is not None and evr.get("operation") == "less than" and evr.text:
                    states[el.get("id")] = evr.text.strip()
                el.clear()
            elif tag == "constant_variable":
                variables[el.get("id")] = [v.text.strip() for v in el if _local(v.tag) == "value" and v.text]
                el.clear()

    for cve, priority, usns, refs in definitions:
        for test_ref, source in refs:
            obj, state = tests.get(test_ref, (None, None))
            binaries = variables.get(objects.get(obj, ""), [])
            if binaries:
                yield cve, priority, usns, source, binaries, states.get(state) if state else None


def import_oval(db: Session, release: str, path: Path) -> OvalStats:
    stats = OvalStats()
    seen = set()
    rows = []
    for cve, priority, usns, source, binaries, fixed in parse_oval(path):
        seen.add(cve)
        for binary in binaries:
            rows.append({"r": release, "c": cve, "s": source, "b": binary, "f": fixed, "p": priority, "u": usns})
    db.execute(text("DELETE FROM distro_cve_status WHERE distro = 'ubuntu' AND release = :r"), {"r": release})
    for start in range(0, len(rows), 5000):
        db.execute(
            text("""
                INSERT INTO distro_cve_status (distro, release, cve, source_package, binary_package, fixed_version, priority, usns)
                VALUES ('ubuntu', :r, :c, :s, :b, :f, :p, :u)
            """),
            rows[start:start + 5000],
        )
    stats.cves, stats.rows = len(seen), len(rows)
    db.execute(
        text("INSERT INTO distro_oval_imports (distro, release, source, cves, rows) VALUES ('ubuntu', :r, :s, :c, :n)"),
        {"r": release, "s": path.name, "c": stats.cves, "n": stats.rows},
    )
    db.commit()
    return stats


# ---------- статус находки по данным дистрибутива ----------

# Порядок важности: первое найденное по CVE находки определяет её статус.
DISTRO_STATUS_ORDER = ["vulnerable", "unfixed", "fixed", "unknown"]


def load_distro_index(db: Session, release: str, cves: set[str]) -> dict[tuple[str, str], tuple[str | None, str | None]]:
    """Данные релиза по нужным CVE одним запросом: {(cve, бинарный пакет): (исправленная версия, USN)}."""
    if not cves:
        return {}
    rows = db.execute(
        text("""
            SELECT cve, binary_package, fixed_version, usns FROM distro_cve_status
            WHERE distro = 'ubuntu' AND release = :r AND cve = ANY(:cves)
        """),
        {"r": release, "cves": sorted(cves)},
    ).all()
    return {(cve, binary): (fixed, usns) for cve, binary, fixed, usns in rows}


def distro_status(index: dict, cves: list[str], packages: list[str], installed_version: str) -> dict:
    """Статус находки БДУ в релизе Ubuntu по её CVE и пакетам.

    - vulnerable — исправление вышло, но установлена более старая версия;
    - unfixed — релиз затронут, исправления пока нет;
    - fixed — установленная версия не ниже исправленной;
    - unknown — CVE нет или пакета нет в данных Ubuntu (дистрибутив не считает релиз затронутым или
      не отслеживает) — находка остаётся потенциальной.

    fix_requires_pro — исправление выпущено только в ESM (версия с «esm»): доступно по подписке Ubuntu Pro.
    """
    per_cve: dict[str, str] = {}
    fixed_versions, usns = [], set()
    for cve in cves:
        for package in packages:
            if (cve, package) not in index:
                continue
            fixed, usn = index[(cve, package)]
            if fixed is None:
                status = "unfixed"
            elif compare_deb(installed_version, fixed) < 0:
                status = "vulnerable"
                fixed_versions.append(fixed)
            else:
                status = "fixed"
                fixed_versions.append(fixed)
            if usn:
                usns.update(usn.split(","))
            current = per_cve.get(cve)
            if current is None or DISTRO_STATUS_ORDER.index(status) < DISTRO_STATUS_ORDER.index(current):
                per_cve[cve] = status
    statuses = set(per_cve.values())
    overall = next((s for s in DISTRO_STATUS_ORDER if s in statuses), "unknown")
    newest_fix = max(fixed_versions, key=_DebKey) if fixed_versions else None
    return {
        "status": overall,
        "fixed_version": newest_fix,
        "fix_requires_pro": bool(overall == "vulnerable" and newest_fix and "esm" in newest_fix),
        "usns": sorted(usns),
        "cves": per_cve,
    }


class _DebKey:
    def __init__(self, version: str):
        self.version = version

    def __lt__(self, other: "_DebKey") -> bool:
        return compare_deb(self.version, other.version) < 0
