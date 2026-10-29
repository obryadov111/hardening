"""Инвентаризация оборудования актива: агент присылает блок inventory, сервер хранит одну строку
на актив (asset_inventory) и отдаёт её на /assets/{id}/inventory. ПДн (имя пользователя, домен,
группы) приходят только если агент их собрал (--collect-identity)."""

INVENTORY = {
    "mac_address": "52:54:00:d7:b2:5b",
    "device_uuid": "b9e2c1a0f00d4e9b",
    "cpu_model": "Intel(R) Xeon(R) Gold 6338",
    "cpu_cores": 8,
    "memory_mb": 15936,
    "board_vendor": "ASUSTeK COMPUTER INC.",
    "board_product": "PRIME B560M-A",
    "disks": [{"name": "nvme0n1", "model": "Samsung SSD 980", "size_gb": 512.1, "type": "nvme"}],
}


def _ingest(client, agent_key, hostname="inv-01", inventory=None, run_id=None):
    payload = {
        "environment": "prod",
        "asset": {"hostname": hostname, "os": "Ubuntu 24.04", "asset_type": "server"},
        "facts": {"ssh": {"permit_root_login": "no"}},
    }
    if inventory is not None:
        payload["inventory"] = inventory
    if run_id is not None:
        payload["run_id"] = run_id
    resp = client.post("/api/ingest", json=payload, headers={"X-Agent-Api-Key": agent_key})
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_ingest_stores_inventory_and_read_endpoint_returns_it(
    client, make_org, make_agent_key, make_user, add_membership, auth_header
):
    org_id = make_org("Inv Org")
    agent_key = make_agent_key(org_id)
    body = _ingest(client, agent_key, inventory=INVENTORY)

    member = make_user("inv-member@example.com", "secret123")
    add_membership(member, org_id, role="viewer")
    headers = auth_header("inv-member@example.com", "secret123")

    resp = client.get(f"/api/assets/{body['asset_id']}/inventory", headers=headers)
    assert resp.status_code == 200, resp.text
    inv = resp.json()
    assert inv["mac_address"] == "52:54:00:d7:b2:5b"
    assert inv["cpu_cores"] == 8 and inv["memory_mb"] == 15936
    assert inv["disks"] == INVENTORY["disks"]
    # ПДн не собирались агентом — пусты
    assert inv["username"] is None and inv["domain_groups"] == []


def test_inventory_is_upserted_not_duplicated(client, make_org, make_agent_key, make_user, add_membership, auth_header):
    org_id = make_org("Inv Upsert Org")
    agent_key = make_agent_key(org_id)
    body = _ingest(client, agent_key, inventory=INVENTORY)
    updated = dict(INVENTORY, memory_mb=32768, cpu_cores=16)
    _ingest(client, agent_key, inventory=updated)

    member = make_user("inv-up@example.com", "secret123")
    add_membership(member, org_id, role="viewer")
    headers = auth_header("inv-up@example.com", "secret123")
    inv = client.get(f"/api/assets/{body['asset_id']}/inventory", headers=headers).json()
    assert inv["memory_mb"] == 32768 and inv["cpu_cores"] == 16


def test_inventory_omitted_does_not_wipe_previous(client, make_org, make_agent_key, make_user, add_membership, auth_header):
    org_id = make_org("Inv Keep Org")
    agent_key = make_agent_key(org_id)
    body = _ingest(client, agent_key, inventory=INVENTORY)
    # Следующий прогон без inventory (например, прогон пака) — прежнюю инвентаризацию не трогаем.
    _ingest(client, agent_key)

    member = make_user("inv-keep@example.com", "secret123")
    add_membership(member, org_id, role="viewer")
    headers = auth_header("inv-keep@example.com", "secret123")
    inv = client.get(f"/api/assets/{body['asset_id']}/inventory", headers=headers).json()
    assert inv is not None and inv["cpu_model"] == "Intel(R) Xeon(R) Gold 6338"


def test_inventory_identity_pii_stored_when_sent(client, make_org, make_agent_key, make_user, add_membership, auth_header):
    org_id = make_org("Inv PII Org")
    agent_key = make_agent_key(org_id)
    inv_with_pii = dict(INVENTORY, username="svc-hardening", domain="CORP.EXAMPLE.RU",
                        domain_groups=["domain users", "admins"])
    body = _ingest(client, agent_key, inventory=inv_with_pii)

    member = make_user("inv-pii@example.com", "secret123")
    add_membership(member, org_id, role="viewer")
    headers = auth_header("inv-pii@example.com", "secret123")
    inv = client.get(f"/api/assets/{body['asset_id']}/inventory", headers=headers).json()
    assert inv["username"] == "svc-hardening"
    assert inv["domain"] == "CORP.EXAMPLE.RU"
    assert inv["domain_groups"] == ["domain users", "admins"]


def test_inventory_read_is_org_scoped(client, make_org, make_agent_key, make_user, add_membership, auth_header):
    org_id = make_org("Inv Scope Org")
    other_org = make_org("Inv Scope Other")
    agent_key = make_agent_key(org_id)
    body = _ingest(client, agent_key, inventory=INVENTORY)

    outsider = make_user("inv-outsider@example.com", "secret123")
    add_membership(outsider, other_org, role="viewer")
    headers = auth_header("inv-outsider@example.com", "secret123")
    resp = client.get(f"/api/assets/{body['asset_id']}/inventory", headers=headers)
    assert resp.status_code == 403  # актив чужой организации
