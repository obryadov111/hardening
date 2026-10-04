"""Выгрузка снимка сканирования в Excel и PDF.

Файл формируется на лету по данным снимка и не хранится. Снимок неизменен: результаты вместе с
метаданными проверок (название, критичность, рекомендация) сохраняются в scan_check_results в
момент прогона, поэтому повторная выгрузка даёт то же содержимое. Хранилище и подписанные ссылки
не нужны, и отчёт аудита не получает публичного URL.

Значения и доказательства приходят с проверяемых хостов (строки их конфигурации), их содержимое
контролирует тот, кто управляет хостом. Поэтому в Excel все значения пишутся строго как текст:
иначе строка вида `=HYPERLINK(...)` стала бы формулой в файле аудитора. В PDF текст экранируется
перед разметкой Paragraph.
"""
from __future__ import annotations

import io
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from xml.sax.saxutils import escape
from zoneinfo import ZoneInfo

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import settings
from app.services.remediation import REMEDIATION_BY_SEVERITY, SOURCE_NOTE, get_remediation


def _local(value: datetime | None, fmt: str, fallback: str) -> str:
    """Время из БД (UTC) — в поясе DISPLAY_TIMEZONE, как его видит читатель отчёта."""
    if value is None:
        return fallback
    return value.astimezone(ZoneInfo(settings.DISPLAY_TIMEZONE)).strftime(fmt)


STATUS_LABELS = {"pass": "Соблюдено", "fail": "Нарушение", "error": "Не проверено"}
ACCEPTED_LABEL = "Нарушение (риск принят)"
# Порядок строк: сначала нарушения по убыванию критичности, затем принятые риски, «не проверено», соблюдённые.
_STATUS_ORDER = {"fail": 0, "accepted": 1, "error": 2, "pass": 3}


@dataclass
class ResultRow:
    hostname: str
    check_id: str
    title: str
    severity: str
    status: str
    actual: str
    expected: str
    remediation: str
    pack: str
    evidence: str
    checked_at: datetime | None
    exception_reason: str | None = None  # принятый риск на момент прогона

    @property
    def accepted(self) -> bool:
        return self.status == "fail" and self.exception_reason is not None

    @property
    def status_label(self) -> str:
        return ACCEPTED_LABEL if self.accepted else STATUS_LABELS.get(self.status, self.status)

    @property
    def fix_text(self) -> str:
        if self.accepted:
            return f"Риск принят: {self.exception_reason}"
        return self.remediation if self.status == "fail" else ""

    @property
    def fix(self):
        # Принятое нарушение не устраняется — срока устранения у него нет.
        return None if self.accepted else get_remediation(self.status, self.severity)


@dataclass
class PlanRow:
    severity: str
    count: int
    assets: int
    deadline: str
    procedure: str


@dataclass
class SnapshotReport:
    organization: str
    scan_number: int
    label: str | None
    created_at: datetime | None
    total: int
    passed: int
    failed: int
    compliance_score: float | None
    total_assets: int
    accepted: int = 0
    rows: list[ResultRow] = field(default_factory=list)

    @property
    def not_evaluated(self) -> int:
        return self.total - self.passed - self.failed - self.accepted

    @property
    def coverage(self) -> float | None:
        return round((self.passed + self.failed + self.accepted) / self.total * 100, 2) if self.total else None

    @property
    def plan(self) -> list[PlanRow]:
        groups: dict[str, tuple[int, set[str]]] = {}
        for row in self.rows:
            if row.fix is None:
                continue
            count, assets = groups.get(row.severity, (0, set()))
            assets.add(row.hostname)
            groups[row.severity] = (count + 1, assets)
        return [
            PlanRow(sev, count, len(assets), REMEDIATION_BY_SEVERITY[sev].deadline, REMEDIATION_BY_SEVERITY[sev].procedure)
            for sev, (count, assets) in sorted(groups.items(), key=lambda item: REMEDIATION_BY_SEVERITY[item[0]].order)
        ]

    @property
    def filename_stem(self) -> str:
        date = _local(self.created_at, "%Y-%m-%d", "без-даты")
        return f"scan-{self.scan_number}-{date}"


def _sort_key(row: ResultRow):
    fix = row.fix
    return (_STATUS_ORDER.get("accepted" if row.accepted else row.status, 4), fix.order if fix else 9, row.hostname, row.check_id)


def load_snapshot_report(db: Session, snapshot_id: str) -> SnapshotReport | None:
    head = db.execute(
        text("""
            SELECT s.scan_number, s.snapshot_label, COALESCE(s.completed_at, s.created_at) AS created_at,
                   s.total_checks, s.passed, s.failed, s.accepted_risks, s.compliance_score, s.total_assets,
                   o.name AS organization
            FROM scan_snapshots s
            LEFT JOIN client_organizations o ON o.id = s.organization_id
            WHERE s.id = :sid
        """),
        {"sid": snapshot_id},
    ).mappings().first()
    if head is None:
        return None

    rows = db.execute(
        text("""
            SELECT a.hostname, scr.status, scr.actual_value, scr.checked_at, scr.evidence,
                   scr.pack_id, scr.pack_version,
                   COALESCE(scr.expected_value, r.expected_value) AS expected_value,
                   -- у результатов пака нет строки в hardening_rules: метаданные — в самой записи снимка
                   COALESCE(r.rule_code, scr.check_id) AS check_id,
                   COALESCE(r.title, scr.title) AS title,
                   COALESCE(r.severity, scr.severity) AS severity,
                   COALESCE(r.remediation, scr.remediation) AS remediation,
                   re.reason AS exception_reason
            FROM scan_check_results scr
            LEFT JOIN assets a ON a.id = scr.asset_id
            LEFT JOIN hardening_rules r ON r.id = scr.rule_id
            LEFT JOIN risk_exceptions re ON re.id = scr.risk_exception_id
            WHERE scr.snapshot_id = :sid
        """),
        {"sid": snapshot_id},
    ).mappings().all()

    report = SnapshotReport(
        organization=head["organization"] or "—",
        scan_number=head["scan_number"],
        label=head["snapshot_label"],
        created_at=head["created_at"],
        total=head["total_checks"] or 0,
        passed=head["passed"] or 0,
        failed=head["failed"] or 0,
        accepted=head["accepted_risks"] or 0,
        compliance_score=float(head["compliance_score"]) if head["compliance_score"] is not None else None,
        total_assets=head["total_assets"] or 0,
    )
    report.rows = sorted(
        (
            ResultRow(
                hostname=r["hostname"] or "—",
                check_id=r["check_id"] or "—",
                title=r["title"] or "—",
                severity=(r["severity"] or "").lower(),
                status=r["status"],
                actual=r["actual_value"] or "",
                expected=r["expected_value"] or "",
                remediation=r["remediation"] or "",
                pack=f"{r['pack_id']} {r['pack_version']}" if r["pack_id"] else "",
                evidence=r["evidence"] or "",
                checked_at=r["checked_at"],
                exception_reason=r["exception_reason"],
            )
            for r in rows
        ),
        key=_sort_key,
    )
    return report


def _summary_pairs(report: SnapshotReport) -> list[tuple[str, str]]:
    def fmt_pct(value):
        return "—" if value is None else f"{value:.2f}%".replace(".00%", "%")

    return [
        ("Организация", report.organization),
        ("Снимок", f"№ {report.scan_number}" + (f" — {report.label}" if report.label else "")),
        ("Дата", _local(report.created_at, "%Y-%m-%d %H:%M", "—")),
        ("Активов", str(report.total_assets)),
        ("Проверок всего", str(report.total)),
        ("Соблюдено", str(report.passed)),
        ("Нарушений", str(report.failed)),
        ("Риск принят (не входит в оценку)", str(report.accepted)),
        ("Не проверено", str(report.not_evaluated)),
        ("Соответствие (соблюдено / выполненные)", fmt_pct(report.compliance_score)),
        ("Покрытие (выполненные / все)", fmt_pct(report.coverage)),
    ]


# ============================== Excel ==============================

def to_xlsx(report: SnapshotReport) -> bytes:
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter

    bold = Font(bold=True)
    header_fill = PatternFill("solid", fgColor="DDDDDD")

    def put(ws, row, col, value, font=None):
        cell = ws.cell(row=row, column=col)
        if isinstance(value, str):
            # Строго текст: значение с «=», «+», «-», «@» в начале иначе стало бы формулой.
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
    line = 1
    put(summary, line, 1, "Отчёт о проверке харденинга", Font(bold=True, size=14))
    line += 2
    for label, value in _summary_pairs(report):
        put(summary, line, 1, label, bold)
        put(summary, line, 2, value)
        line += 1

    line += 1
    put(summary, line, 1, "Что устранить и в какие сроки", Font(bold=True, size=12))
    line += 1
    plan = report.plan
    if plan:
        for col, title in enumerate(("Уровень", "Нарушений", "Активов", "Срок устранения", "Порядок"), start=1):
            put(summary, line, col, title, bold).fill = header_fill
        for item in plan:
            line += 1
            for col, value in enumerate((item.severity, item.count, item.assets, item.deadline, item.procedure), start=1):
                put(summary, line, col, value)
    else:
        put(summary, line, 1, "Нарушений нет.")
    line += 2
    put(summary, line, 1, SOURCE_NOTE).alignment = Alignment(wrap_text=True, vertical="top")
    summary.merge_cells(start_row=line, start_column=1, end_row=line, end_column=5)
    summary.row_dimensions[line].height = 48
    for col, width in enumerate((42, 30, 12, 18, 34), start=1):
        summary.column_dimensions[get_column_letter(col)].width = width

    results = wb.create_sheet("Результаты")
    headers = ("Актив", "Проверка", "Название", "Уровень", "Статус", "Факт", "Ожидалось",
               "Срок устранения", "Порядок", "Как исправить", "Пак", "Доказательство", "Проверено")
    widths = (18, 34, 44, 11, 14, 22, 22, 16, 30, 50, 20, 40, 18)
    for col, title in enumerate(headers, start=1):
        put(results, 1, col, title, bold).fill = header_fill
        results.column_dimensions[get_column_letter(col)].width = widths[col - 1]
    for line, row in enumerate(report.rows, start=2):
        fix = row.fix
        values = (
            row.hostname, row.check_id, row.title, row.severity, row.status_label,
            row.actual, row.expected, fix.deadline if fix else "", fix.procedure if fix else "",
            row.fix_text, row.pack, row.evidence,
            _local(row.checked_at, "%Y-%m-%d %H:%M", ""),
        )
        for col, value in enumerate(values, start=1):
            put(results, line, col, value).alignment = Alignment(wrap_text=True, vertical="top")
    results.freeze_panes = "A2"
    results.auto_filter.ref = f"A1:{get_column_letter(len(headers))}{max(len(report.rows) + 1, 1)}"

    buffer = io.BytesIO()
    wb.save(buffer)
    return buffer.getvalue()


# ============================== PDF ==============================

FONT_CANDIDATES = (
    os.environ.get("EXPORT_FONT_DIR"),
    "/usr/share/fonts/truetype/dejavu",   # Debian/Ubuntu: fonts-dejavu-core
    "/usr/share/fonts/dejavu",            # Fedora/Alpine
)


class ExportFontError(RuntimeError):
    """Нет шрифта с кириллицей: встроенные шрифты PDF кириллицу не отображают."""


def _register_fonts() -> tuple[str, str]:
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont

    if "DejaVuSans" in pdfmetrics.getRegisteredFontNames():
        return "DejaVuSans", "DejaVuSans-Bold"
    for directory in filter(None, FONT_CANDIDATES):
        regular, bold = Path(directory, "DejaVuSans.ttf"), Path(directory, "DejaVuSans-Bold.ttf")
        if regular.exists() and bold.exists():
            pdfmetrics.registerFont(TTFont("DejaVuSans", str(regular)))
            pdfmetrics.registerFont(TTFont("DejaVuSans-Bold", str(bold)))
            return "DejaVuSans", "DejaVuSans-Bold"
    raise ExportFontError(
        "не найден шрифт DejaVuSans (пакет fonts-dejavu-core) — без него PDF не покажет кириллицу; "
        "задайте EXPORT_FONT_DIR"
    )


def to_pdf(report: SnapshotReport) -> bytes:
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
        t = Table(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E5E5E5")),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#BBBBBB")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))
        return t

    story = [p("Отчёт о проверке харденинга", h1)]
    story.append(Table(
        [[p(label, head), p(value)] for label, value in _summary_pairs(report)],
        colWidths=[75 * mm, 120 * mm],
        style=TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("BOTTOMPADDING", (0, 0), (-1, -1), 1)]),
        hAlign="LEFT",
    ))

    story.append(p("Что устранить и в какие сроки", h2))
    plan = report.plan
    if plan:
        story.append(table(
            [[p(t, head) for t in ("Уровень", "Нарушений", "Активов", "Срок устранения", "Порядок")]]
            + [[p(i.severity), p(i.count), p(i.assets), p(i.deadline), p(i.procedure)] for i in plan],
            [30 * mm, 25 * mm, 22 * mm, 35 * mm, 65 * mm],
        ))
    else:
        story.append(p("Нарушений нет."))
    story.append(Spacer(1, 3 * mm))
    story.append(p(SOURCE_NOTE, small))

    story.append(p("Результаты проверок", h2))
    if report.rows:
        data = [[p(t, head) for t in ("Актив", "Проверка", "Уровень", "Статус", "Факт / ожидалось", "Срок", "Как исправить")]]
        for row in report.rows:
            fix = row.fix
            data.append([
                p(row.hostname),
                [p(row.title), p(row.check_id, small)],
                p(row.severity or "—"),
                p(row.status_label),
                [p(row.actual or "—"), p(f"ожидалось: {row.expected or '—'}", small)],
                [p(fix.deadline), p(fix.procedure, small)] if fix else p("—"),
                p(row.fix_text),
            ])
        story.append(table(data, [28 * mm, 62 * mm, 18 * mm, 22 * mm, 45 * mm, 30 * mm, 62 * mm]))
    else:
        story.append(p("В снимке нет результатов."))

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont(regular, 7)
        canvas.drawString(10 * mm, 7 * mm, f"{report.organization} · снимок № {report.scan_number}")
        canvas.drawRightString(doc.pagesize[0] - 10 * mm, 7 * mm, f"стр. {doc.page}")
        canvas.restoreState()

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=landscape(A4), leftMargin=10 * mm, rightMargin=10 * mm, topMargin=10 * mm, bottomMargin=12 * mm,
        title=f"Отчёт харденинга — снимок {report.scan_number}", author="Харденинг",
    )
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()
