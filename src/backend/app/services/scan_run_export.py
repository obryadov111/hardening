"""Выгрузка прогона: сводка, хосты, нарушения по правилам. Строки проверок каждого хоста не дублируются —
их по-прежнему отдаёт выгрузка снимка. Файл строится на лету и не пишется в exported_*_path.
"""
from __future__ import annotations

import io
from datetime import datetime
from xml.sax.saxutils import escape

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.services.remediation import REMEDIATION_BY_SEVERITY, SOURCE_NOTE
from app.services.scan_runs import list_findings, list_hosts, load_run, run_detail
from app.services.snapshot_export import _local, _register_fonts


def _fmt_pct(value) -> str:
    return "—" if value is None else f"{value:.2f}%".replace(".00%", "%")


def load_run_export(db: Session, run_id: str) -> dict | None:
    run = load_run(db, run_id)
    if run is None:
        return None
    detail = run_detail(db, run)
    hosts = list_hosts(db, run_id, q="", status="", environment_id=None, limit=10000, offset=0)["items"]
    findings = list_findings(db, run_id, limit=10000, offset=0)["items"]
    org = db_org_name(db, str(run.organization_id))
    return {"detail": detail, "hosts": hosts, "findings": findings, "organization": org}


def db_org_name(db: Session, organization_id: str) -> str:
    name = db.execute(
        text("SELECT name FROM client_organizations WHERE id = :id"), {"id": organization_id},
    ).scalar()
    return name or "—"


def filename_stem(detail: dict) -> str:
    opened = detail.get("opened_at")
    date = _local(opened if isinstance(opened, datetime) else None, "%Y-%m-%d", "без-даты")
    return f"run-{detail['run_number']}-{date}"


def _pairs(report: dict) -> list[tuple[str, str]]:
    detail = report["detail"]
    scope = detail.get("environment_name") or "вся организация"
    window = _local(detail.get("opened_at"), "%Y-%m-%d %H:%M", "—")
    if detail.get("window_ends_at"):
        window += " — " + _local(detail["window_ends_at"], "%Y-%m-%d %H:%M", "—")
    label = detail.get("label") or f"Прогон №{detail['run_number']}"
    return [
        ("Организация", report["organization"]),
        ("Прогон", f"№ {detail['run_number']} — {label}"),
        ("Область", scope),
        ("Окно", window),
        ("Состояние", "открыт" if detail["status"] == "open" else "закрыт"),
        ("Хостов", str(detail["hosts"])),
        ("Проверок всего", str(detail["total_checks"])),
        ("Соблюдено", str(detail["passed"])),
        ("Нарушений", str(detail["failed"])),
        ("Риск принят (не входит в оценку)", str(detail["accepted_risks"])),
        ("Не проверено", str(detail["not_checked"])),
        ("Соответствие", _fmt_pct(detail["compliance_score"])),
    ]


def to_xlsx(report: dict) -> bytes:
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter

    bold = Font(bold=True)
    header_fill = PatternFill("solid", fgColor="DDDDDD")

    def put(ws, row, col, value, font=None):
        cell = ws.cell(row=row, column=col)
        if isinstance(value, str):
            cell.value = value
            cell.data_type = "s"
        else:
            cell.value = value
        if font:
            cell.font = font
        return cell

    wb = Workbook()
    summary = wb.active
    summary.title = "Сводка"
    put(summary, 1, 1, "Прогон харденинга", Font(bold=True, size=14))
    line = 3
    for label, value in _pairs(report):
        put(summary, line, 1, label, bold)
        put(summary, line, 2, value)
        line += 1
    line += 1
    put(summary, line, 1, "Нарушения по правилам", Font(bold=True, size=12))
    line += 1
    if report["findings"]:
        for col, title in enumerate(("Проверка", "Название", "Уровень", "Хостов", "Срок"), start=1):
            put(summary, line, col, title, bold).fill = header_fill
        for item in report["findings"]:
            line += 1
            severity = (item["severity"] or "").lower()
            deadline = REMEDIATION_BY_SEVERITY[severity].deadline if severity in REMEDIATION_BY_SEVERITY else ""
            for col, value in enumerate((item["check_key"] or "—", item["title"] or "—", severity, item["hosts"], deadline), start=1):
                put(summary, line, col, value)
    else:
        put(summary, line, 1, "Нарушений нет.")
    line += 2
    put(summary, line, 1, SOURCE_NOTE).alignment = Alignment(wrap_text=True, vertical="top")
    summary.merge_cells(start_row=line, start_column=1, end_row=line, end_column=5)
    summary.row_dimensions[line].height = 48
    for col, width in enumerate((42, 36, 14, 12, 22), start=1):
        summary.column_dimensions[get_column_letter(col)].width = width

    hosts = wb.create_sheet("Хосты")
    headers = ("Хост", "IP", "Окружение", "ОС", "Статус снимка", "Проверок", "Соблюдено", "Нарушено",
               "Риск принят", "Не проверено", "Соответствие", "Метка", "Снято")
    widths = (22, 16, 16, 22, 14, 12, 12, 12, 14, 14, 14, 24, 18)
    for col, title in enumerate(headers, start=1):
        put(hosts, 1, col, title, bold).fill = header_fill
        hosts.column_dimensions[get_column_letter(col)].width = widths[col - 1]
    for line, row in enumerate(report["hosts"], start=2):
        values = (
            row["hostname"] or "—", row["ip_address"] or "", row["environment_name"] or "",
            row["os"] or "", row["status"] or "", row["total_checks"] or 0, row["passed"] or 0,
            row["failed"] or 0, row["accepted_risks"] or 0, row["not_checked"],
            _fmt_pct(row["compliance_score"]), row["snapshot_label"] or "",
            _local(row["collected_at"], "%Y-%m-%d %H:%M", ""),
        )
        for col, value in enumerate(values, start=1):
            put(hosts, line, col, value)
    hosts.freeze_panes = "A2"
    hosts.auto_filter.ref = f"A1:{get_column_letter(len(headers))}{max(len(report['hosts']) + 1, 1)}"

    buffer = io.BytesIO()
    wb.save(buffer)
    return buffer.getvalue()


def to_pdf(report: dict) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    regular, bold = _register_fonts()
    body = ParagraphStyle("body", fontName=regular, fontSize=8, leading=10)
    small = ParagraphStyle("small", parent=body, fontSize=7, leading=9, textColor=colors.HexColor("#555555"))
    head = ParagraphStyle("head", parent=body, fontName=bold)
    h1 = ParagraphStyle("h1", fontName=bold, fontSize=15, leading=19, spaceAfter=6)
    h2 = ParagraphStyle("h2", fontName=bold, fontSize=11, leading=14, spaceBefore=8, spaceAfter=4)

    def p(value, style=body):
        return Paragraph(escape(str(value)).replace("\n", "<br/>"), style)

    def table(data, widths):
        drawn = Table(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
        drawn.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E5E5E5")),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#BBBBBB")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))
        return drawn

    detail = report["detail"]
    story = [p("Прогон харденинга", h1)]
    story.append(Table(
        [[p(label, head), p(value)] for label, value in _pairs(report)],
        colWidths=[70 * mm, 120 * mm],
        style=TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("BOTTOMPADDING", (0, 0), (-1, -1), 1)]),
        hAlign="LEFT",
    ))
    story.append(p("Нарушения по правилам", h2))
    if report["findings"]:
        data = [[p(title, head) for title in ("Проверка", "Уровень", "Хостов", "Срок")]]
        for item in report["findings"]:
            severity = (item["severity"] or "").lower()
            deadline = REMEDIATION_BY_SEVERITY[severity].deadline if severity in REMEDIATION_BY_SEVERITY else "—"
            data.append([
                [p(item["title"] or "—"), p(item["check_key"] or "—", small)],
                p(severity or "—"), p(item["hosts"]), p(deadline),
            ])
        story.append(table(data, [110 * mm, 28 * mm, 22 * mm, 40 * mm]))
    else:
        story.append(p("Нарушений нет."))
    story.append(Spacer(1, 3 * mm))
    story.append(p(SOURCE_NOTE, small))

    story.append(p("Хосты прогона", h2))
    if report["hosts"]:
        data = [[p(title, head) for title in ("Хост", "Окружение", "Нарушено", "Соблюдено", "Соответствие", "Метка")]]
        for row in report["hosts"]:
            data.append([
                p(row["hostname"] or "—"),
                p(row["environment_name"] or "—"),
                p(row["failed"] or 0),
                p(row["passed"] or 0),
                p(_fmt_pct(row["compliance_score"])),
                p(row["snapshot_label"] or ""),
            ])
        story.append(table(data, [45 * mm, 35 * mm, 25 * mm, 28 * mm, 30 * mm, 50 * mm]))
    else:
        story.append(p("В прогоне нет хостов."))

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont(regular, 7)
        canvas.drawString(10 * mm, 7 * mm, f"{report['organization']} · прогон № {detail['run_number']}")
        canvas.drawRightString(doc.pagesize[0] - 10 * mm, 7 * mm, f"стр. {doc.page}")
        canvas.restoreState()

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=landscape(A4), leftMargin=10 * mm, rightMargin=10 * mm, topMargin=10 * mm, bottomMargin=12 * mm,
        title=f"Прогон харденинга № {detail['run_number']}", author="Харденинг",
    )
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()
