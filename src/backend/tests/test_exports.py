"""Выгрузка снимка в Excel / PDF: доступ, содержимое, защита от формул из данных хоста."""
import io
import uuid

import pytest
from openpyxl import load_workbook
from sqlalchemy import text

from app.services.snapshot_export import FONT_CANDIDATES
from tests.test_ingest_packs import pack_payload, pack_registry  # noqa: F401 — фикстура пака

MALICIOUS = '=HYPERLINK("http://evil.example/x","нажми")'


@pytest.fixture
def snapshot(client, db, make_org, make_agent_key, pack_registry):  # noqa: F811
    """Снимок организации: одно нарушение critical (с формулой в доказательстве), одно соблюдение
    и одна непроверенная проверка — через настоящий ingest."""
    org_id = make_org("Export Org")
    key = make_agent_key(org_id)
    payload = pack_payload(probe_results={
        "ssh.permit_root_login": {"found": True, "value": "yes", "evidence": MALICIOUS},
        "ssh.max_auth_tries": {"found": False, "error": "нет файла"},
    })
    body = client.post("/api/ingest", json=payload, headers={"X-Agent-Api-Key": key}).json()
    return org_id, body["snapshot_id"]


@pytest.fixture
def viewer(make_user, add_membership, auth_header):
    def _viewer(org_id, email="export-viewer@example.com"):
        add_membership(make_user(email), org_id)
        return auth_header(email)
    return _viewer


def url(snapshot_id, fmt):
    return f"/api/exports/snapshots/{snapshot_id}/download?format={fmt}"


# ---------- доступ ----------

def test_export_requires_login(client, snapshot):
    _, snapshot_id = snapshot
    assert client.get(url(snapshot_id, "excel")).status_code in (401, 403)


def test_export_of_another_organizations_snapshot_is_forbidden(client, snapshot, make_org, viewer):
    _, snapshot_id = snapshot
    headers = viewer(make_org("Чужая"))
    assert client.get(url(snapshot_id, "excel"), headers=headers).status_code == 403


def test_unknown_snapshot_is_404_and_bad_format_is_422(client, snapshot, viewer):
    org_id, snapshot_id = snapshot
    headers = viewer(org_id)
    assert client.get(url(uuid.uuid4(), "excel"), headers=headers).status_code == 404
    assert client.get(url(snapshot_id, "docx"), headers=headers).status_code == 422


# ---------- Excel ----------

def test_excel_export_has_summary_plan_and_results(client, snapshot, viewer):
    org_id, snapshot_id = snapshot
    resp = client.get(url(snapshot_id, "excel"), headers=viewer(org_id))

    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/vnd.openxmlformats")
    assert resp.headers["cache-control"] == "no-store"
    assert 'filename="scan-1-' in resp.headers["content-disposition"]

    wb = load_workbook(io.BytesIO(resp.content))
    summary = {row[0]: row[1] for row in wb["Сводка"].iter_rows(values_only=True) if row[0]}
    assert summary["Организация"] == "Export Org"
    assert (summary["Проверок всего"], summary["Соблюдено"], summary["Нарушений"], summary["Не проверено"]) == ("2", "0", "1", "1")
    assert summary["Покрытие (выполненные / все)"] == "50%"
    assert summary["critical"] == 1  # строка плана устранения: уровень -> число нарушений

    rows = list(wb["Результаты"].iter_rows(values_only=True))
    header, first, second = rows[0], rows[1], rows[2]
    record = dict(zip(header, first, strict=True))
    # нарушения идут первыми, со сроком и порядком устранения
    assert (record["Проверка"], record["Статус"], record["Уровень"]) == ("ssh.permit_root_login", "Нарушение", "critical")
    assert (record["Срок устранения"], record["Порядок"]) == ("до 24 часов", "Обязательно (п. 3.4.4)")
    assert dict(zip(header, second, strict=True))["Статус"] == "Не проверено"


def test_excel_never_turns_host_data_into_formulas(client, snapshot, viewer):
    org_id, snapshot_id = snapshot
    wb = load_workbook(io.BytesIO(client.get(url(snapshot_id, "excel"), headers=viewer(org_id)).content))
    sheet = wb["Результаты"]
    header = [c.value for c in sheet[1]]
    cell = sheet.cell(row=2, column=header.index("Доказательство") + 1)
    assert cell.value == MALICIOUS
    assert cell.data_type == "s"  # строка, а не формула


# ---------- PDF ----------

@pytest.mark.skipif(
    not any(p and __import__("os").path.exists(f"{p}/DejaVuSans.ttf") for p in FONT_CANDIDATES),
    reason="нет шрифта DejaVuSans (fonts-dejavu-core)",
)
def test_pdf_export_is_a_pdf_with_an_embedded_cyrillic_font(client, snapshot, viewer):
    org_id, snapshot_id = snapshot
    resp = client.get(url(snapshot_id, "pdf"), headers=viewer(org_id))

    assert resp.status_code == 200 and resp.headers["content-type"] == "application/pdf"
    assert resp.content.startswith(b"%PDF-")
    assert b"DejaVuSans" in resp.content  # встроенный шрифт с кириллицей, а не Helvetica
    assert resp.headers["content-disposition"].endswith('.pdf"')


def test_snapshot_without_results_still_exports(client, db, make_org, viewer):
    org_id = make_org("Empty Export Org")
    snapshot_id = db.execute(
        text("""INSERT INTO scan_snapshots (organization_id, scan_number, status, total_assets, total_software, created_at)
                VALUES (:org, 1, 'completed', 0, 0, now()) RETURNING id"""),
        {"org": org_id},
    ).scalar()
    db.commit()
    resp = client.get(url(snapshot_id, "excel"), headers=viewer(org_id))
    assert resp.status_code == 200
    summary = {row[0]: row[1] for row in load_workbook(io.BytesIO(resp.content))["Сводка"].iter_rows(values_only=True) if row[0]}
    assert "Нарушений нет." in summary and summary["Проверок всего"] == "0"


def test_report_times_are_shown_in_display_timezone(monkeypatch):
    """В БД время в UTC; в отчёте — в поясе DISPLAY_TIMEZONE (раньше печаталось UTC)."""
    from datetime import UTC, datetime

    from app.core.config import settings
    from app.services.snapshot_export import SnapshotReport, _summary_pairs

    monkeypatch.setattr(settings, "DISPLAY_TIMEZONE", "Asia/Yekaterinburg")
    report = SnapshotReport(
        organization="Org", scan_number=7, label=None, created_at=datetime(2026, 10, 4, 22, 26, tzinfo=UTC),
        total=0, passed=0, failed=0, compliance_score=None, total_assets=0,
    )

    assert dict(_summary_pairs(report))["Дата"] == "2026-10-05 03:26"  # +05, уже следующий день
    assert report.filename_stem == "scan-7-2026-10-05"
