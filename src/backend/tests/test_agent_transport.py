"""Работа агентов через интернет: подпись паков Ed25519, ключи агентов (срок, отзыв, последний адрес),
повторная отправка из очереди агента, отчёт агента, перенесённый файлом."""
import json
import os
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import text

from app.core.config import settings
from app.services.packs.manifest import ed25519_public_key, generate_ed25519_key, sign_manifest_ed25519

AGENT_DIR = Path(__file__).resolve().parents[3] / "agent"
if not (AGENT_DIR / "probes.py").exists():
    pytest.skip("каталог agent/ недоступен", allow_module_level=True)
sys.path.insert(0, str(AGENT_DIR))

import collector  # noqa: E402
import probes  # noqa: E402

ED_KEY = generate_ed25519_key()


@pytest.fixture
def ed25519(monkeypatch):
    monkeypatch.setattr(settings, "PACK_SIGNING_ED25519_KEY", ED_KEY)
    return probes.decode_public_key(ed25519_public_key(ED_KEY))


@pytest.fixture
def org_admin(make_org, make_user, add_membership, auth_header):
    org_id = make_org("Transport Org")
    add_membership(make_user("transport-admin@example.com"), org_id, role="admin")
    return org_id, auth_header("transport-admin@example.com")


# ---------- Ed25519 ----------

def test_server_signature_is_verified_by_pure_python_agent():
    """Подпись сервера (cryptography) и проверка агента (чистый Python) совпадают на разных сообщениях."""
    public = probes.decode_public_key(ed25519_public_key(ED_KEY))
    for i in range(20):
        manifest = {"schema": 1, "pack": f"p{i}", "data": os.urandom(i * 7).hex(), "текст": "кириллица"}
        signature = sign_manifest_ed25519(manifest, ED_KEY)
        assert probes.verify_manifest_ed25519(manifest, signature, public)
        assert not probes.verify_manifest_ed25519({**manifest, "pack": "evil"}, signature, public)


def test_manifests_endpoint_signs_with_ed25519_and_agent_accepts(client, make_org, make_agent_key, ed25519):
    key = make_agent_key(make_org("Ed Org"))
    body = client.get("/api/agent/manifests?transport=local", headers={"X-Agent-Api-Key": key}).json()
    assert body["manifests"] and all("signature_ed25519" in m and "signature" in m for m in body["manifests"])
    assert len(probes.load_verified_manifests(body, None, ed25519)) == len(body["manifests"])
    body["manifests"][0]["manifest"]["checks"].append({"id": "evil", "probe": {"type": "cmd_regex"}})
    with pytest.raises(probes.ManifestError):
        probes.load_verified_manifests(body, None, ed25519)


def test_manifests_without_any_signing_key_are_not_served(client, make_org, make_agent_key, monkeypatch):
    key = make_agent_key(make_org("No Key Org"))
    monkeypatch.setattr(settings, "PACK_SIGNING_KEY", None)
    monkeypatch.setattr(settings, "PACK_SIGNING_ED25519_KEY", None)
    assert client.get("/api/agent/manifests", headers={"X-Agent-Api-Key": key}).status_code == 503


# ---------- ключи агентов ----------

def _ingest(client, key, **extra):
    payload = {"environment": "prod", "asset": {"hostname": "h1", "asset_type": "server"}, **extra}
    return client.post("/api/ingest", json=payload, headers={"X-Agent-Api-Key": key, "X-Real-IP": "203.0.113.7"})


def test_agent_key_lifecycle(client, org_admin, ed25519):
    org_id, headers = org_admin
    created = client.post(f"/api/organizations/{org_id}/agent-keys", json={"name": "Казань, ЦОД", "expires_in_days": 90}, headers=headers)
    assert created.status_code == 201
    key = created.json()
    assert key["key"].startswith("yak_") and key["state"] == "active"
    assert datetime.fromisoformat(key["expires_at"]) - datetime.now(UTC) > timedelta(days=89)

    assert _ingest(client, key["key"]).status_code == 200
    listing = client.get(f"/api/organizations/{org_id}/agent-keys", headers=headers).json()
    assert listing["pack_public_key"] == ed25519_public_key(ED_KEY)
    row = next(k for k in listing["keys"] if k["id"] == key["id"])
    assert row["last_used_ip"] == "203.0.113.7" and row["last_used_at"] and "key" not in row and "key_hash" not in row

    assert client.post(f"/api/organizations/{org_id}/agent-keys/{key['id']}/revoke", headers=headers).json()["state"] == "revoked"
    assert _ingest(client, key["key"]).status_code == 401


def test_expired_agent_key_is_refused(client, org_admin, db):
    org_id, headers = org_admin
    key = client.post(f"/api/organizations/{org_id}/agent-keys", json={"name": "old", "expires_in_days": 1}, headers=headers).json()
    db.execute(text("UPDATE agent_api_keys SET expires_at = now() - interval '1 minute' WHERE id = :id"), {"id": key["id"]})
    db.commit()
    assert _ingest(client, key["key"]).status_code == 401
    row = next(k for k in client.get(f"/api/organizations/{org_id}/agent-keys", headers=headers).json()["keys"] if k["id"] == key["id"])
    assert row["state"] == "expired"


def test_only_org_admin_manages_keys(client, org_admin, make_user, add_membership, auth_header):
    org_id, _ = org_admin
    add_membership(make_user("transport-viewer@example.com"), org_id, role="viewer")
    viewer = auth_header("transport-viewer@example.com")
    assert client.get(f"/api/organizations/{org_id}/agent-keys", headers=viewer).status_code == 403
    assert client.post(f"/api/organizations/{org_id}/agent-keys", json={"name": "x"}, headers=viewer).status_code == 403


# ---------- повторная отправка из очереди ----------

def test_same_run_is_accepted_once_and_snapshot_time_is_collection_time(client, make_org, make_agent_key, db):
    org_id = make_org("Queue Org")
    key = make_agent_key(org_id)
    run_id, collected = str(uuid.uuid4()), (datetime.now(UTC) - timedelta(days=2)).replace(microsecond=0)
    first = _ingest(client, key, run_id=run_id, collected_at=collected.isoformat())
    assert first.status_code == 200
    assert _ingest(client, key, run_id=run_id, collected_at=collected.isoformat()).status_code == 409
    started = db.execute(text("SELECT started_at FROM scan_snapshots WHERE id = :id"), {"id": first.json()["snapshot_id"]}).scalar()
    assert started == collected
    assert db.execute(text("SELECT count(*) FROM scan_snapshots WHERE organization_id = :o"), {"o": org_id}).scalar() == 1


@pytest.mark.parametrize("delta,needle", [(timedelta(hours=1), "будущем"), (timedelta(days=-40), "старше")])
def test_implausible_collection_time_is_rejected(client, make_org, make_agent_key, delta, needle):
    key = make_agent_key(make_org("Clock Org"))
    resp = _ingest(client, key, collected_at=(datetime.now(UTC) + delta).isoformat())
    assert resp.status_code == 422 and needle in resp.text


# ---------- отчёт агента, перенесённый файлом ----------

def _report(api_key, collected_at=None, **asset):
    payload = {
        "environment": "isolated", "asset": {"hostname": "asu-01", "asset_type": "server", **asset},
        "run_id": str(uuid.uuid4()), "collected_at": (collected_at or datetime.now(UTC)).isoformat(timespec="seconds"),
    }
    return collector.sign_report(payload, api_key)


def _upload(client, org_id, headers, report):
    files = {"file": ("report.json", json.dumps(report, ensure_ascii=False).encode(), "application/json")}
    return client.post(f"/api/organizations/{org_id}/agent-reports", files=files, headers=headers)


def test_signed_report_upload_creates_snapshot_marked_as_file(client, org_admin, db):
    org_id, headers = org_admin
    key = client.post(f"/api/organizations/{org_id}/agent-keys", json={"name": "АСУ ТП"}, headers=headers).json()
    report = _report(key["key"])
    resp = _upload(client, org_id, headers, report)
    assert resp.status_code == 200, resp.text
    collection = db.execute(text("SELECT collection FROM scan_snapshots WHERE id = :id"), {"id": resp.json()["snapshot_id"]}).scalar()
    assert collection["source"] == "agent-report" and collection["transfer"] == "file" and collection["agent_key"] == "АСУ ТП"
    assert collection["uploaded_by"] == "transport-admin@example.com" and len(collection["file_sha256"]) == 64
    assert _upload(client, org_id, headers, report).status_code == 409  # тот же отчёт второй раз


def test_tampered_or_foreign_report_is_rejected(client, org_admin, make_org, make_agent_key):
    org_id, headers = org_admin
    key = client.post(f"/api/organizations/{org_id}/agent-keys", json={"name": "k"}, headers=headers).json()["key"]
    report = _report(key)
    report["payload"]["asset"]["hostname"] = "подменён"
    assert "Подпись отчёта" in _upload(client, org_id, headers, report).text
    foreign = _report(make_agent_key(make_org("Other Org")))
    assert _upload(client, org_id, headers, foreign).status_code == 422
    assert _upload(client, org_id, headers, {"format": "something-else"}).status_code == 422


def test_report_taken_after_revocation_is_rejected_but_before_is_accepted(client, org_admin):
    org_id, headers = org_admin
    key = client.post(f"/api/organizations/{org_id}/agent-keys", json={"name": "k"}, headers=headers).json()
    before = _report(key["key"], datetime.now(UTC) - timedelta(hours=1))
    client.post(f"/api/organizations/{org_id}/agent-keys/{key['id']}/revoke", headers=headers)
    after = _report(key["key"], datetime.now(UTC) + timedelta(minutes=1))
    assert "после отзыва" in _upload(client, org_id, headers, after).text
    assert _upload(client, org_id, headers, before).status_code == 200
