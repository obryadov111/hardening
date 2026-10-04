"""Принятый риск: исключения из оценки, права, влияние на текущее состояние, снимки, сравнение и отчёты."""
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text

from app.api.routes.snapshots import classify
from app.services.snapshot_export import load_snapshot_report
from tests.test_ingest_packs import pack_payload, pack_registry  # noqa: F401 — фикстура пака

ROOT = "ssh.permit_root_login"  # в pack_payload по умолчанию нарушена (PermitRootLogin yes)


@pytest.fixture
def org(client, make_org, make_agent_key, make_user, add_membership, auth_header, pack_registry):  # noqa: F811
    org_id = make_org("Risk Org")
    key = make_agent_key(org_id)
    add_membership(make_user("risk-admin@example.com"), org_id, role="admin")
    add_membership(make_user("risk-viewer@example.com"), org_id, role="viewer")

    def ingest(hostname="web-01", **overrides):
        payload = pack_payload(asset={"hostname": hostname, "asset_type": "linux-server"}, **overrides)
        resp = client.post("/api/ingest", json=payload, headers={"X-Agent-Api-Key": key})
        assert resp.status_code == 200, resp.text
        return resp.json()

    return {
        "id": org_id, "ingest": ingest,
        "admin": auth_header("risk-admin@example.com"), "viewer": auth_header("risk-viewer@example.com"),
    }


def url(org_id, suffix=""):
    return f"/api/organizations/{org_id}/risk-exceptions{suffix}"


def accept(client, org, check_key=ROOT, asset_id=None, reason="Вход root нужен для аварийного доступа", **extra):
    body = {"check_key": check_key, "reason": reason, **extra}
    if asset_id:
        body["asset_id"] = asset_id
    return client.post(url(org["id"]), json=body, headers=org["admin"])


def hardening(client, org):
    rows = client.get(f"/api/organizations/{org['id']}/hardening", headers=org["viewer"]).json()
    return {(r["asset"]["hostname"], r["rule"]["rule_code"]): r for r in rows}


def dashboard(client, org):
    return client.get(f"/api/organizations/{org['id']}/dashboard", headers=org["viewer"]).json()


# ---------- классификация в сравнении ----------

@pytest.mark.parametrize(("before", "after", "before_accepted", "after_accepted", "expected"), [
    ("fail", "fail", False, True, "accepted"),   # риск приняли между снимками
    ("fail", "fail", True, True, None),          # принят в обоих — не требует внимания
    ("fail", "fail", True, False, "still_failed"),  # исключение отозвали
    (None, "fail", False, True, "accepted"),
    ("error", "fail", False, True, "accepted"),
    ("pass", "fail", False, True, "regressed"),  # хост стал хуже — это видно и при принятом риске
    ("fail", "pass", True, False, "fixed"),
])
def test_classify_with_accepted_risk(before, after, before_accepted, after_accepted, expected):
    assert classify(before, after, before_accepted, after_accepted) == expected


# ---------- влияние на оценку ----------

def test_accepting_risk_updates_current_state_and_dashboard_at_once(client, org):
    asset_id = org["ingest"]()["asset_id"]
    assert dashboard(client, org)["failedChecks"] == 1

    resp = accept(client, org, asset_id=asset_id)

    assert resp.status_code == 201, resp.text
    created = resp.json()
    assert (created["check_key"], created["asset_hostname"], created["state"], created["created_by_email"]) == (
        ROOT, "web-01", "active", "risk-admin@example.com",
    )
    row = hardening(client, org)[("web-01", ROOT)]
    assert row["status"] == "fail"  # факт с хоста не переписывается
    assert row["risk_exception"]["reason"] == "Вход root нужен для аварийного доступа"
    assert row["risk_exception"]["org_wide"] is False
    body = dashboard(client, org)
    assert (body["passedChecks"], body["failedChecks"], body["acceptedChecks"], body["notEvaluatedChecks"]) == (1, 0, 1, 0)
    assert body["coverage"] == 100.0
    assert float(body["latestReport"]["compliance_score"]) == 100.0  # отчёт пересчитан сразу, без прогона агента


def test_next_scan_records_accepted_risk_in_snapshot_and_excludes_it_from_score(client, db, org):
    asset_id = org["ingest"]()["asset_id"]
    accept(client, org, asset_id=asset_id)

    body = org["ingest"]()

    assert body["checks"] == {"total": 2, "passed": 1, "failed": 0, "errors": 0}
    assert body["accepted_risks"] == 1
    assert body["compliance_score"] == 100.0
    snapshot = db.execute(
        text("SELECT failed, accepted_risks, compliance_score FROM scan_snapshots WHERE id = :sid"), {"sid": body["snapshot_id"]}
    ).one()
    assert (snapshot.failed, snapshot.accepted_risks, float(snapshot.compliance_score)) == (0, 1, 100.0)
    status, exception_id = db.execute(
        text("SELECT status, risk_exception_id FROM scan_check_results WHERE snapshot_id = :sid AND check_id = :c"),
        {"sid": body["snapshot_id"], "c": ROOT},
    ).one()
    assert status == "fail" and exception_id is not None


def test_org_wide_exception_covers_every_asset_and_only_failed_checks(client, org):
    org["ingest"]("web-01")
    org["ingest"]("web-02", probe_results={
        ROOT: {"found": True, "value": "no"}, "ssh.max_auth_tries": {"found": True, "value": "3"},
    })

    assert accept(client, org).status_code == 201  # без asset_id — на всю организацию
    second = org["ingest"]("web-03")

    rows = hardening(client, org)
    assert rows[("web-01", ROOT)]["risk_exception"]["org_wide"] is True
    assert rows[("web-02", ROOT)]["risk_exception"] is None  # проверка соблюдена — исключать нечего
    assert rows[("web-03", ROOT)]["risk_exception"] is not None
    assert second["accepted_risks"] == 1


def test_revoking_brings_the_violation_back_but_keeps_history(client, db, org):
    asset_id = org["ingest"]()["asset_id"]
    exception = accept(client, org, asset_id=asset_id).json()
    accepted_snapshot = org["ingest"]()["snapshot_id"]

    assert client.delete(url(org["id"], f"/{exception['id']}"), headers=org["admin"]).status_code == 204

    assert hardening(client, org)[("web-01", ROOT)]["risk_exception"] is None
    assert dashboard(client, org)["failedChecks"] == 1
    assert org["ingest"]()["accepted_risks"] == 0
    # прежний снимок по-прежнему показывает, что риск тогда был принят
    still_linked = db.execute(
        text("SELECT risk_exception_id FROM scan_check_results WHERE snapshot_id = :sid AND check_id = :c"),
        {"sid": accepted_snapshot, "c": ROOT},
    ).scalar()
    assert str(still_linked) == exception["id"]
    assert client.get(url(org["id"]), headers=org["viewer"]).json() == []
    history = client.get(url(org["id"], "?include_inactive=true"), headers=org["viewer"]).json()
    assert [(e["id"], e["state"], e["revoked_by_email"]) for e in history] == [(exception["id"], "revoked", "risk-admin@example.com")]


def test_expired_exception_is_not_applied(client, db, org):
    asset_id = org["ingest"]()["asset_id"]
    exception = accept(client, org, asset_id=asset_id, expires_at=(datetime.now(UTC) + timedelta(days=30)).isoformat()).json()
    db.execute(text("UPDATE risk_exceptions SET expires_at = now() - interval '1 day' WHERE id = :id"), {"id": exception["id"]})
    db.commit()

    assert org["ingest"]()["accepted_risks"] == 0
    history = client.get(url(org["id"], "?include_inactive=true"), headers=org["viewer"]).json()
    assert history[0]["state"] == "expired"
    # после истечения можно принять риск заново
    assert accept(client, org, asset_id=asset_id).status_code == 201


def test_asset_specific_exception_wins_over_org_wide(client, org):
    asset_id = org["ingest"]()["asset_id"]
    accept(client, org, reason="Общее решение для всей организации")
    accept(client, org, asset_id=asset_id, reason="Решение именно для web-01")

    org["ingest"]()

    assert hardening(client, org)[("web-01", ROOT)]["risk_exception"]["reason"] == "Решение именно для web-01"


# ---------- сравнение и отчёты ----------

def test_compare_shows_accepted_risk_instead_of_still_failed(client, org):
    first = org["ingest"]()
    accept(client, org, asset_id=first["asset_id"])
    second = org["ingest"]()

    body = client.get(
        f"/api/snapshots/compare?before_snapshot_id={first['snapshot_id']}&after_snapshot_id={second['snapshot_id']}",
        headers=org["viewer"],
    ).json()

    assert body["summary"]["accepted"] == 1 and body["summary"]["stillFailed"] == 0
    (diff,) = body["diffs"]
    assert (diff["changeType"], diff["afterAccepted"], diff["exceptionReason"]) == (
        "accepted", True, "Вход root нужен для аварийного доступа",
    )
    assert body["afterSnapshot"]["accepted_risks"] == 1


def test_snapshot_report_marks_accepted_risk_without_remediation_deadline(client, db, org):
    accept(client, org, asset_id=org["ingest"]()["asset_id"])
    snapshot_id = org["ingest"]()["snapshot_id"]

    report = load_snapshot_report(db, snapshot_id)

    assert (report.failed, report.accepted, report.not_evaluated, report.coverage) == (0, 1, 0, 100.0)
    row = next(r for r in report.rows if r.check_id == ROOT)
    assert row.status_label == "Нарушение (риск принят)"
    assert row.fix is None and row.fix_text == "Риск принят: Вход root нужен для аварийного доступа"
    assert report.plan == []  # принятое нарушение не попадает в план устранения


# ---------- права и проверки ввода ----------

def test_viewer_cannot_accept_or_revoke(client, org):
    asset_id = org["ingest"]()["asset_id"]
    body = {"check_key": ROOT, "asset_id": asset_id, "reason": "Вход root нужен для аварийного доступа"}
    assert client.post(url(org["id"]), json=body, headers=org["viewer"]).status_code == 403
    exception = accept(client, org, asset_id=asset_id).json()
    assert client.delete(url(org["id"], f"/{exception['id']}"), headers=org["viewer"]).status_code == 403


def test_other_organization_cannot_see_or_use_exceptions(client, org, make_org, make_user, add_membership, auth_header):
    asset_id = org["ingest"]()["asset_id"]
    exception = accept(client, org, asset_id=asset_id).json()
    other_org = make_org("Other Risk Org")
    add_membership(make_user("other-risk-admin@example.com"), other_org, role="admin")
    other = auth_header("other-risk-admin@example.com")

    assert client.get(url(org["id"]), headers=other).status_code == 403
    assert client.delete(url(other_org, f"/{exception['id']}"), headers=other).status_code == 404
    # чужой актив в своей организации — как несуществующий
    body = {"check_key": ROOT, "asset_id": asset_id, "reason": "Попытка исключить чужой актив"}
    assert client.post(url(other_org), json=body, headers=other).status_code == 404


@pytest.mark.parametrize(("overrides", "status"), [
    ({"reason": "коротко"}, 422),
    ({"reason": "          "}, 422),
    ({"check_key": "  "}, 422),
    ({"expires_at": "2020-01-01T00:00:00Z"}, 422),
    ({"unexpected": "x"}, 422),
])
def test_invalid_input_is_rejected(client, org, overrides, status):
    body = {"check_key": ROOT, "reason": "Вход root нужен для аварийного доступа", **overrides}
    assert client.post(url(org["id"]), json=body, headers=org["admin"]).status_code == status


def test_duplicate_active_exception_is_rejected(client, org):
    asset_id = org["ingest"]()["asset_id"]
    assert accept(client, org, asset_id=asset_id).status_code == 201
    assert accept(client, org, asset_id=asset_id).status_code == 409
    assert accept(client, org).status_code == 201  # общее на организацию — другое исключение
