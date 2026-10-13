"""Сравнение снимков: классификация изменений, общие активы, «предыдущий снимок того же актива»."""
import uuid

import pytest
from sqlalchemy import text

from app.api.routes.snapshots import classify
from tests.test_ingest_packs import pack_payload, pack_registry  # noqa: F401 — фикстура пака


@pytest.mark.parametrize(("before", "after", "expected"), [
    ("fail", "pass", "fixed"),
    ("pass", "fail", "regressed"),
    ("fail", "fail", "still_failed"),
    (None, "fail", "new"),
    (None, "pass", "new"),
    ("pass", None, "removed"),
    ("pass", "error", "changed"),
    ("error", "fail", "changed"),
    ("pass", "pass", None),
    ("error", "error", None),
])
def test_classify(before, after, expected):
    assert classify(before, after) == expected


@pytest.fixture
def org(client, make_org, make_agent_key, make_user, add_membership, auth_header, pack_registry):  # noqa: F811
    org_id = make_org("Compare Org")
    key = make_agent_key(org_id)
    add_membership(make_user("compare-viewer@example.com"), org_id)
    headers = auth_header("compare-viewer@example.com")

    def ingest(hostname, root_login, max_tries):
        results = {}
        for check_id, value in (("ssh.permit_root_login", root_login), ("ssh.max_auth_tries", max_tries)):
            results[check_id] = {"found": False, "error": "нет файла"} if value is None else {"found": True, "value": value}
        payload = pack_payload(asset={"hostname": hostname, "asset_type": "linux-server"}, probe_results=results)
        resp = client.post("/api/ingest", json=payload, headers={"X-Agent-Api-Key": key})
        assert resp.status_code == 200, resp.text
        return resp.json()["snapshot_id"]

    return org_id, headers, ingest


def compare(client, headers, before, after):
    return client.get(f"/api/snapshots/compare?before_snapshot_id={before}&after_snapshot_id={after}", headers=headers)


def test_fixed_and_regressed_on_the_same_asset(client, org):
    _, headers, ingest = org
    first = ingest("web-01", root_login="yes", max_tries="3")   # root: fail, tries: pass
    second = ingest("web-01", root_login="no", max_tries="6")   # root: pass, tries: fail

    body = compare(client, headers, first, second).json()

    assert body["commonAssets"] == 1
    assert body["summary"] == {"fixed": 1, "regressed": 1, "stillFailed": 0, "newIssues": 0, "removed": 0, "changed": 0, "accepted": 0}
    changes = {d["rule"]["rule_code"]: (d["beforeStatus"], d["afterStatus"], d["changeType"]) for d in body["diffs"]}
    assert changes == {
        "ssh.max_auth_tries": ("pass", "fail", "regressed"),
        "ssh.permit_root_login": ("fail", "pass", "fixed"),
    }
    assert body["diffs"][0]["changeType"] == "regressed"  # ухудшения — первыми


def test_still_failed_and_became_unverified(client, org):
    _, headers, ingest = org
    first = ingest("web-01", root_login="yes", max_tries="3")
    second = ingest("web-01", root_login="yes", max_tries=None)  # tries: pass -> error

    summary = compare(client, headers, first, second).json()["summary"]
    assert (summary["stillFailed"], summary["changed"], summary["fixed"]) == (1, 1, 0)


def test_unchanged_results_are_not_listed(client, org):
    _, headers, ingest = org
    first = ingest("web-01", root_login="no", max_tries="3")
    second = ingest("web-01", root_login="no", max_tries="3")
    assert compare(client, headers, first, second).json()["diffs"] == []


def test_snapshots_of_different_assets_have_nothing_to_compare(client, org):
    _, headers, ingest = org
    web = ingest("web-01", root_login="yes", max_tries="3")
    db_host = ingest("db-01", root_login="no", max_tries="6")

    body = compare(client, headers, web, db_host).json()

    # раньше «Сравнить» вело к соседнему снимку — и всё выглядело бы как «удалено» + «новое»
    assert (body["commonAssets"], body["onlyBeforeAssets"], body["onlyAfterAssets"]) == (0, 1, 1)
    assert body["diffs"] == [] and set(body["summary"].values()) == {0}


def test_previous_snapshot_is_the_previous_run_of_the_same_asset(client, org):
    org_id, headers, ingest = org
    web_1 = ingest("web-01", root_login="yes", max_tries="3")
    db_1 = ingest("db-01", root_login="yes", max_tries="3")
    web_2 = ingest("web-01", root_login="no", max_tries="3")

    body = client.get(f"/api/organizations/{org_id}/snapshots", headers=headers).json()
    previous = {row["id"]: row["previous_snapshot_id"] for row in body["items"]}
    hosts = {row["id"]: row["hosts"] for row in body["items"]}

    assert previous[web_2] == web_1  # не db_1, хотя он ближе по номеру
    assert previous[db_1] is None and previous[web_1] is None
    assert hosts[web_2] == ["web-01"] and hosts[db_1] == ["db-01"]
    assert body["total"] == 3 and body["summary"]["total"] == 3 and body["summary"]["latest"]["id"] == web_2

    # предыдущий снимок находится и когда он на другой странице
    page = client.get(f"/api/organizations/{org_id}/snapshots", params={"limit": 1}, headers=headers).json()
    assert [r["id"] for r in page["items"]] == [web_2] and page["items"][0]["previous_snapshot_id"] == web_1

    # фильтр по хосту
    web = client.get(f"/api/organizations/{org_id}/snapshots", params={"host": "web-01"}, headers=headers).json()
    assert [r["id"] for r in web["items"]] == [web_2, web_1] and web["total"] == 2
    assert client.get(f"/api/organizations/{org_id}/snapshots", params={"limit": 501}, headers=headers).status_code == 422


def test_daily_reports_keep_the_last_report_of_each_day(client, db, org):
    org_id, headers, ingest = org
    for _ in range(3):
        ingest("web-01", root_login="yes", max_tries="3")
    reports = client.get(f"/api/organizations/{org_id}/reports", headers=headers).json()
    assert len(reports) == 3
    # два отчёта «вчера», один «сегодня» — по дням остаются последний вчерашний и сегодняшний
    db.execute(text("UPDATE hardening_reports SET generated_at = generated_at - interval '1 day' WHERE id IN (:a, :b)"),
               {"a": reports[1]["id"], "b": reports[2]["id"]})
    db.commit()
    daily = client.get(f"/api/organizations/{org_id}/reports", params={"daily": "true"}, headers=headers).json()
    assert [r["id"] for r in daily] == [reports[0]["id"], reports[1]["id"]]
    assert len(client.get(f"/api/organizations/{org_id}/reports", params={"limit": 1}, headers=headers).json()) == 1


def test_compare_access(client, org, make_org, make_user, add_membership, auth_header):
    _, headers, ingest = org
    first, second = ingest("web-01", "yes", "3"), ingest("web-01", "no", "3")

    add_membership(make_user("stranger@example.com"), make_org("Чужая"))
    assert compare(client, auth_header("stranger@example.com"), first, second).status_code == 403
    assert compare(client, headers, uuid.uuid4(), second).status_code == 404
    assert client.get(f"/api/snapshots/compare?before_snapshot_id={first}&after_snapshot_id={second}").status_code in (401, 403)
