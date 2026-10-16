"""Проверка по опросу (transport: manual): аудитор отвечает на вопросы пака по экранам системы управления, сервер
оценивает ответы теми же утверждениями, что и пробы агента, и пишет обычный снимок с источником «опрос»."""
import pytest
from sqlalchemy import text

from app.api.deps import get_pack_registry
from app.core.config import settings
from app.main import app
from app.services.packs.models import Pack
from app.services.packs.registry import PackRegistry
from tests.test_ingest_packs import SSH_PACK
from tests.test_packs import BASE_PACK

MANUAL_PACK = {
    "pack": "gateway-test", "version": "1.0.0", "maturity": "draft", "transport": "manual",
    "tags": ["network-device", "security-gateway"], "asset_type": "network-device",
    "firmware": {"vendor": "Вендор", "product": "шлюз тест. версия 4",
                 "version_probe": {"type": "manual", "answer": "text", "question": "Версия ПО узла?"}},
    "checks": [
        {"id": "gw.default_password_changed", "title": "Заводской пароль сменён", "severity": "critical",
         "probe": {"type": "manual", "question": "Заводской пароль сменён?", "hint": "Меню → Настройки"},
         "assert": {"op": "eq", "value": "yes"}},
        {"id": "gw.password_min_length", "title": "Длина пароля не меньше 8", "severity": "medium",
         "probe": {"type": "manual", "answer": "number", "unit": "символов", "question": "Минимальная длина пароля?"},
         "assert": {"op": "gte", "value": 8}},
        {"id": "gw.snmp", "title": "SNMP v3 или выключен", "severity": "medium",
         "probe": {"type": "manual", "answer": "choice", "choices": ["выключен", "v3", "v2"], "question": "Как настроен SNMP?"},
         "assert": {"op": "in", "value": ["выключен", "v3"]}},
    ],
}


@pytest.fixture(autouse=True)
def registry():
    reg = PackRegistry([Pack.model_validate(MANUAL_PACK), Pack.model_validate(SSH_PACK), Pack.model_validate(BASE_PACK)])
    app.dependency_overrides[get_pack_registry] = lambda: reg
    yield reg
    app.dependency_overrides.pop(get_pack_registry, None)


@pytest.fixture
def org(make_org, make_user, add_membership, auth_header):
    org_id = make_org("Manual Org")
    add_membership(make_user("manual-admin@example.com"), org_id, role="admin")
    add_membership(make_user("manual-viewer@example.com"), org_id, role="viewer")
    return {"id": org_id, "admin": auth_header("manual-admin@example.com"),
            "viewer": auth_header("manual-viewer@example.com")}


def submit(client, org, headers=None, **body):
    data = {"pack": "gateway-test", "hostname": "gw-01", **body}
    return client.post(f"/api/organizations/{org['id']}/manual-scans", headers=headers or org["admin"], json=data)


def test_packs_list_shows_questions_only_for_manual_packs(client, org):
    resp = client.get(f"/api/organizations/{org['id']}/manual-scans/packs", headers=org["viewer"])
    assert resp.status_code == 200, resp.text
    packs = resp.json()["packs"]
    assert [p["pack"] for p in packs] == ["gateway-test"]
    questions = {q["id"]: q for q in packs[0]["questions"]}
    assert questions["gw.default_password_changed"]["hint"] == "Меню → Настройки"
    assert questions["gw.snmp"]["choices"] == ["выключен", "v3", "v2"]
    assert packs[0]["firmware"]["question"] == "Версия ПО узла?"


def test_answers_become_a_snapshot_marked_as_manual(client, db, org):
    resp = submit(client, org, firmware_version="4.2.1", scan_label="опрос 16.10", answers={
        "gw.default_password_changed": {"value": True, "comment": "скриншот ЛМ"},
        "gw.password_min_length": {"value": "6"},
        "gw.snmp": {"value": "v2"},
    })
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["checks"] == {"total": 3, "passed": 1, "failed": 2, "errors": 0}

    snap = db.execute(text("SELECT collection FROM scan_snapshots WHERE id = :id"), {"id": body["snapshot_id"]}).scalar_one()
    assert snap["source"] == "manual" and snap["answered_by"] == "manual-admin@example.com" and snap["unanswered"] == []
    software = db.execute(text(
        "SELECT s.name, s.version, s.category FROM software s JOIN assets a ON a.id = s.asset_id WHERE a.hostname = 'gw-01'"
    )).all()
    assert [tuple(r) for r in software] == [("шлюз тест. версия 4", "4.2.1", "firmware")]
    evidence = db.execute(text(
        "SELECT h.check_id, h.status FROM hardening_checks h JOIN assets a ON a.id = h.asset_id WHERE a.hostname = 'gw-01'"
    )).all()
    assert dict(evidence) == {"gw.default_password_changed": "pass", "gw.password_min_length": "fail", "gw.snmp": "fail"}


def test_unanswered_question_is_not_checked_rather_than_passed(client, db, org):
    resp = submit(client, org, answers={"gw.default_password_changed": {"value": "да"}})
    assert resp.status_code == 200, resp.text
    assert resp.json()["checks"] == {"total": 3, "passed": 1, "failed": 0, "errors": 2}
    snap = db.execute(text("SELECT collection FROM scan_snapshots WHERE id = :id"), {"id": resp.json()["snapshot_id"]}).scalar_one()
    assert snap["unanswered"] == ["gw.password_min_length", "gw.snmp"]


@pytest.mark.parametrize("answers, message", [
    ({"gw.password_min_length": {"value": "восемь"}}, "ожидалось число"),
    ({"gw.snmp": {"value": "v1"}}, "ожидалось одно из"),
    ({"gw.default_password_changed": {"value": "может быть"}}, "да или нет"),
    ({"gw.unknown": {"value": "да"}}, "нет вопросов"),
    ({}, "Нет ни одного ответа"),
])
def test_invalid_answers_are_rejected(client, org, answers, message):
    resp = submit(client, org, answers=answers)
    assert resp.status_code == 422
    assert message in resp.text


def test_only_manual_packs_and_only_org_admin(client, org):
    assert submit(client, org, pack="cisco-test", answers={"x": {"value": "да"}}).status_code == 422
    assert submit(client, org, headers=org["viewer"], answers={"gw.snmp": {"value": "v3"}}).status_code == 403


def test_agent_never_receives_manual_packs(client, make_org, make_agent_key):
    key = make_agent_key(make_org("Agent Org"))
    resp = client.get("/api/agent/manifests", headers={"X-Agent-Api-Key": key})
    assert resp.status_code == 200, resp.text
    assert settings.PACK_SIGNING_KEY or settings.PACK_SIGNING_ED25519_KEY
    assert "gateway-test" not in [m["manifest"]["pack"] for m in resp.json()["manifests"]]


def test_report_source_label_says_it_is_an_interview_not_device_config():
    from app.services.snapshot_export import source_label

    label = source_label({"source": "manual", "answered_by": "a@b.c", "answered_at": "2026-10-16T09:00:00Z",
                          "unanswered": ["x"]})
    assert label.startswith("Опрос аудитора") and "не чтение конфигурации" in label
    assert "a@b.c" in label and "без ответа вопросов: 1" in label
