"""Охват: какие хосты должны отчитываться (список из AD или CSV) и какие отчитываются на самом деле.

Для организации на тысячу хостов главный вопрос после раскатки агента — кто молчит: агент не установлен,
не зарегистрировался, ПК выключен давно. Список ожидаемых хостов загружается файлом — выгрузка из AD:

    Get-ADComputer -Filter * -Properties OperatingSystem,LastLogonDate |
      Select-Object Name,DNSHostName,OperatingSystem,LastLogonDate,Enabled |
      Export-Csv computers.csv -NoTypeInformation -Encoding UTF8

или любая таблица с колонкой имени (Name, Hostname, DNSHostName, ComputerName, «Имя»), либо просто
список имён по одному в строке. Имена сравниваются коротко и без регистра: pc-001.corp.local = PC-001
(агент на Windows присылает имя NetBIOS). Отключённые в AD компьютеры (Enabled = False) не загружаются.
"""
import csv
import re
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_org_access, require_org_admin
from app.models.hardening import ExpectedHost
from app.models.user import User

router = APIRouter(tags=["coverage"])

MAX_LIST_BYTES = 5_000_000
MAX_HOSTS = 50_000
NAME_COLUMNS = ("name", "hostname", "computername", "computer", "host", "dnshostname", "имя", "имя компьютера", "хост", "компьютер")
OS_COLUMNS = ("operatingsystem", "os", "ос", "операционная система")
LOGON_COLUMNS = ("lastlogondate", "lastlogontimestamp", "lastlogon", "последний вход")
ENABLED_COLUMNS = ("enabled", "включен", "включён")
IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def short_hostname(hostname: str) -> str:
    """Короткое имя в нижнем регистре: pc-001.corp.local → pc-001; IP-адрес — как есть."""
    name = hostname.strip().lower()
    return name if IPV4.match(name) else name.split(".")[0]


def _decode(content: bytes) -> str:
    if content.startswith((b"\xff\xfe", b"\xfe\xff")):
        return content.decode("utf-16")  # Export-Csv -Encoding Unicode
    try:
        return content.decode("utf-8-sig")
    except UnicodeDecodeError:
        return content.decode("cp1251")  # таблица из Excel на русской Windows


def parse_host_list(content: bytes) -> tuple[list[dict], int]:
    """Строки списка: [{hostname, os, last_logon}], число пропущенных отключённых. Колонки — по заголовку;
    без известного заголовка и с одной колонкой — список имён."""
    lines = [line for line in _decode(content).splitlines() if line.strip() and not line.startswith("#TYPE")]
    if not lines:
        return [], 0
    try:
        dialect = csv.Sniffer().sniff(lines[0], delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel
    rows = list(csv.reader(lines, dialect))
    header = [c.strip().strip('"').lower() for c in rows[0]]

    def column(names):
        return next((header.index(n) for n in names if n in header), None)

    name_col = column(NAME_COLUMNS)
    if name_col is None:
        if max(len(r) for r in rows) > 1:
            raise HTTPException(status_code=422, detail="Не найдена колонка с именем хоста: ожидается Name, Hostname, "
                                                        "DNSHostName, ComputerName или «Имя»")
        return [{"hostname": r[0].strip(), "os": None, "last_logon": None} for r in rows if r and r[0].strip()], 0
    os_col, logon_col, enabled_col = column(OS_COLUMNS), column(LOGON_COLUMNS), column(ENABLED_COLUMNS)

    def cell(row, index):
        return row[index].strip() or None if index is not None and index < len(row) else None

    hosts, disabled = [], 0
    for row in rows[1:]:
        name = cell(row, name_col)
        if not name:
            continue
        if (cell(row, enabled_col) or "").lower() in ("false", "ложь", "нет", "0"):
            disabled += 1
            continue
        hosts.append({"hostname": name, "os": cell(row, os_col), "last_logon": cell(row, logon_col)})
    return hosts, disabled


@router.post("/organizations/{organization_id}/expected-hosts")
async def upload_expected_hosts(
    organization_id: str,
    file: UploadFile = File(...),
    current_user: User = Depends(require_org_admin),
    db: Session = Depends(get_db),
):
    """Список ожидаемых хостов заменяется целиком."""
    content = await file.read(MAX_LIST_BYTES + 1)
    if len(content) > MAX_LIST_BYTES:
        raise HTTPException(status_code=413, detail=f"Список больше {MAX_LIST_BYTES // 1_000_000} МБ")
    rows, disabled = parse_host_list(content)
    unique = {}
    for row in rows:
        unique.setdefault(short_hostname(row["hostname"]), row)
    if not unique:
        raise HTTPException(status_code=422, detail="В файле нет ни одного имени хоста")
    if len(unique) > MAX_HOSTS:
        raise HTTPException(status_code=413, detail=f"Больше {MAX_HOSTS} хостов в списке")

    now = datetime.now(UTC)
    source = (file.filename or "")[:255] or None
    db.query(ExpectedHost).filter(ExpectedHost.organization_id == organization_id).delete()
    db.add_all(
        ExpectedHost(organization_id=organization_id, hostname=row["hostname"][:255], hostname_norm=norm,
                     os=(row["os"] or None) and row["os"][:200], last_logon=(row["last_logon"] or None) and row["last_logon"][:64],
                     source=source, imported_at=now, imported_by=current_user.email)
        for norm, row in unique.items()
    )
    db.commit()
    return {"imported": len(unique), "duplicates": len(rows) - len(unique), "skipped_disabled": disabled}


@router.delete("/organizations/{organization_id}/expected-hosts", status_code=204)
def delete_expected_hosts(organization_id: str, _: User = Depends(require_org_admin), db: Session = Depends(get_db)):
    db.query(ExpectedHost).filter(ExpectedHost.organization_id == organization_id).delete()
    db.commit()


@router.get("/organizations/{organization_id}/coverage")
def coverage(
    organization_id: str,
    days: int = Query(7, ge=1, le=90, description="Отчитался — за последние N дней"),
    _: User = Depends(require_org_access),
    db: Session = Depends(get_db),
):
    """Охват по списку ожидаемых хостов. Статус хоста из списка: reporting — отчёт за последние days дней;
    stale — отчёты были, но давно (или агент зарегистрирован и молчит); revoked — регистрация отозвана;
    not_installed — ни регистрации, ни отчётов. unexpected — отчитываются, но в списке их нет."""
    now = datetime.now(UTC)
    since = now - timedelta(days=days)

    # Последний отчёт по каждому хосту организации — по текущему состоянию проверок (и агенты старых версий)
    reported: dict[str, dict] = {}
    for row in db.execute(text("""
        SELECT a.hostname, a.os, MAX(hc.checked_at) AS last_report
        FROM assets a
        JOIN environments e ON e.id = a.environment_id
        LEFT JOIN hardening_checks hc ON hc.asset_id = a.id
        WHERE e.organization_id = :org
        GROUP BY a.id, a.hostname, a.os
    """), {"org": organization_id}).mappings():
        norm = short_hostname(row["hostname"])
        current = reported.get(norm)
        if current is None or (row["last_report"] and (current["last_report"] is None or row["last_report"] > current["last_report"])):
            reported[norm] = {"hostname": row["hostname"], "os": row["os"], "last_report": row["last_report"]}

    registered: dict[str, dict] = {}
    for row in db.execute(text("""
        SELECT hostname, status, last_seen_at FROM agent_hosts WHERE organization_id = :org AND status <> 'replaced'
    """), {"org": organization_id}).mappings():
        registered[short_hostname(row["hostname"])] = dict(row)

    expected = db.query(ExpectedHost).filter(ExpectedHost.organization_id == organization_id).order_by(ExpectedHost.hostname_norm).all()
    hosts, summary = [], {"reporting": 0, "stale": 0, "revoked": 0, "not_installed": 0}
    for item in expected:
        report, agent = reported.get(item.hostname_norm), registered.get(item.hostname_norm)
        last_report = report["last_report"] if report else None
        if agent and agent["status"] == "revoked":
            status = "revoked"
        elif last_report and last_report >= since:
            status = "reporting"
        elif last_report or agent:
            status = "stale"
        else:
            status = "not_installed"
        summary[status] += 1
        hosts.append({
            "hostname": item.hostname, "os": item.os or (report or {}).get("os"), "last_logon": item.last_logon,
            "status": status, "last_report": last_report, "agent_last_seen": agent["last_seen_at"] if agent else None,
        })

    expected_names = {item.hostname_norm for item in expected}
    unexpected = sorted(
        ({"hostname": r["hostname"], "os": r["os"], "last_report": r["last_report"]}
         for norm, r in reported.items() if norm not in expected_names and r["last_report"] and r["last_report"] >= since),
        key=lambda r: r["hostname"].lower(),
    )
    first = expected[0] if expected else None
    return {
        "days": days,
        "list": {"total": len(expected), "imported_at": first.imported_at, "imported_by": first.imported_by,
                 "source": first.source} if first else None,
        "summary": {**summary, "unexpected": len(unexpected)},
        "hosts": hosts,
        "unexpected": unexpected,
    }
