"""Загрузка выгрузки БДУ ФСТЭК (vulxml.zip / vulxml.xml) в таблицы bdu_*.

Файл большой (~650 МБ XML, ~97 тыс. уязвимостей), поэтому разбирается потоком (iterparse) и пишется
через COPY. Загрузка заменяет данные целиком в одной транзакции: при ошибке остаётся прежняя копия.
"""
import io
import zipfile
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from xml.etree.ElementTree import iterparse

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.services.bdu.versions import parse_bdu_version


@dataclass
class ImportStats:
    vulnerabilities: int = 0
    software_rows: int = 0
    skipped_rows: int = 0


@contextmanager
def _open_xml(path: Path):
    if path.suffix.lower() == ".zip":
        with zipfile.ZipFile(path) as archive:
            member = next(name for name in archive.namelist() if name.lower().endswith(".xml"))
            with archive.open(member) as stream:
                yield stream
    else:
        with open(path, "rb") as stream:
            yield stream


def _score(element) -> tuple[float | None, str | None]:
    if element is None:
        return None, None
    vector = element.find("vector")
    if vector is None or not vector.get("score"):
        return None, None
    try:
        return float(vector.get("score").replace(",", ".")), (vector.text or "").strip() or None
    except ValueError:
        return None, None


def _date(value: str | None) -> date | None:
    try:
        return datetime.strptime((value or "").strip(), "%d.%m.%Y").date()
    except ValueError:
        return None


def _clean(value: str | None) -> str:
    # COPY в текстовом формате: табуляции и переводы строк внутри значений недопустимы.
    return " ".join((value or "").split()).replace("\\", "\\\\")


def _copy_value(value) -> str:
    if value is None:
        return "\\N"
    if isinstance(value, bool):
        return "t" if value else "f"
    return _clean(str(value))


def parse(stream):
    """Генератор (уязвимость, [строки ПО]) по XML выгрузки; счётчики пропусков — в stats."""
    stats = ImportStats()
    for _, element in iterparse(stream, events=("end",)):
        if element.tag != "vul":
            continue
        bdu_id = (element.findtext("identifier") or "").strip()
        if not bdu_id:
            element.clear()
            continue
        cvss3, vector3 = _score(element.find("cvss3"))
        cvss2, _ = _score(element.find("cvss"))
        cves = [i.text.strip() for i in element.iterfind("identifiers/identifier") if i.get("type") == "CVE" and i.text]
        vulnerability = (
            bdu_id, (element.findtext("name") or "").strip(), cvss3, vector3, cvss2,
            element.findtext("exploit_status"), element.findtext("vul_incident"), element.findtext("fix_status"),
            (element.findtext("solution") or "")[:2000], ",".join(cves) or None, _date(element.findtext("publication_date")),
        )
        software = []
        for soft in element.iterfind("vulnerable_software/soft"):
            product = " ".join((soft.findtext("name") or "").split()).lower()
            expression = " ".join((soft.findtext("version") or "").split())
            parsed = parse_bdu_version(expression) if product else None
            if parsed is None:
                stats.skipped_rows += 1
                continue
            software.append((bdu_id, product, soft.findtext("vendor"), expression, parsed.lo, parsed.lo_incl, parsed.hi, parsed.hi_incl))
        stats.vulnerabilities += 1
        stats.software_rows += len(software)
        element.clear()
        yield vulnerability, software, stats


def import_bdu(db: Session, path: Path) -> ImportStats:
    connection = db.connection().connection  # psycopg 3: нужен COPY
    stats = ImportStats()
    vuln_buffer, soft_buffer = io.StringIO(), io.StringIO()

    def flush(cursor):
        for table, columns, buffer in (
            ("bdu_vulnerabilities", "bdu_id, name, cvss3, cvss3_vector, cvss2, exploit_status, incident, fix_status, solution, cves, published", vuln_buffer),
            ("bdu_software", "bdu_id, product, vendor, version_expr, lo, lo_incl, hi, hi_incl", soft_buffer),
        ):
            data = buffer.getvalue()
            if data:
                with cursor.copy(f"COPY {table} ({columns}) FROM STDIN") as copy:
                    copy.write(data)
            buffer.seek(0)
            buffer.truncate()

    with connection.cursor() as cursor:
        cursor.execute("TRUNCATE bdu_software, bdu_vulnerabilities")
        with _open_xml(path) as stream:
            for vulnerability, software, stats in parse(stream):
                vuln_buffer.write("\t".join(_copy_value(v) for v in vulnerability) + "\n")
                for row in software:
                    soft_buffer.write("\t".join(_copy_value(v) for v in row) + "\n")
                if stats.vulnerabilities % 5000 == 0:
                    flush(cursor)
        flush(cursor)
    db.execute(
        text("INSERT INTO bdu_imports (source, vulnerabilities, software_rows, skipped_rows) VALUES (:s, :v, :r, :k)"),
        {"s": path.name, "v": stats.vulnerabilities, "r": stats.software_rows, "k": stats.skipped_rows},
    )
    db.commit()
    return stats
