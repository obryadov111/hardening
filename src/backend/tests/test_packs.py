import copy
from types import SimpleNamespace

import pytest
import yaml

from app.services.hardening_engine import compute_coverage, evaluate_asset
from app.services.packs.assertions import check_assertion, describe_assertion
from app.services.packs.evaluate import evaluate_pack
from app.services.packs.manifest import build_manifest, canonical_json, sign_manifest, verify_manifest
from app.services.packs.models import Pack
from app.services.packs.registry import PackError, PackRegistry, load_pack_file, load_registry

BASE_PACK = {
    "pack": "ubuntu-test",
    "version": "1.0.0",
    "maturity": "baseline",
    "verified_on": ["Ubuntu 24.04 (тестовый стенд)"],
    "tags": ["linux-server", "debian-family", "ubuntu"],
    "transport": "local",
    "asset_type": "linux-server",
    "detect": [
        {"probe": {"type": "file_kv", "path": "/etc/os-release", "key": "ID", "separator": "equals"}, "equals": "ubuntu"}
    ],
    "checks": [
        {
            "id": "ssh.permit_root_login",
            "title": "Запрет root по SSH",
            "probe": {"type": "file_kv", "path": "/etc/ssh/sshd_config", "key": "PermitRootLogin"},
            "assert": {"op": "in", "value": ["no", "prohibit-password"]},
            "severity": "critical",
        },
        {
            "id": "ssh.max_auth_tries",
            "title": "Число попыток",
            "probe": {"type": "file_kv", "path": "/etc/ssh/sshd_config", "key": "MaxAuthTries", "default": "6"},
            "assert": {"op": "lte", "value": 4},
        },
    ],
}


def make_pack(**overrides) -> dict:
    data = copy.deepcopy(BASE_PACK)
    data.update(overrides)
    return data


def probe_result(value, found=True, evidence=None):
    return SimpleNamespace(found=found, value=value, evidence=evidence)


# ---------- формат и валидация ----------

def test_valid_pack_loads():
    pack = Pack.model_validate(BASE_PACK)
    assert pack.pack == "ubuntu-test"
    assert pack.checks[1].assertion.op == "lte"


@pytest.mark.parametrize(
    "mutation, message",
    [
        (lambda d: d["checks"].append(copy.deepcopy(d["checks"][0])), "повторяются id"),
        (lambda d: d.update(checks=[]), "требует проверок"),
        (lambda d: d.update(maturity="full", verified_on=[]), "verified_on"),
        (lambda d: d.update(maturity="baseline", verified_on=[]), "verified_on"),
        (lambda d: d.update(maturity="inventory"), "только обнаружение"),
        (lambda d: d.update(version="1.0"), "MAJOR.MINOR.PATCH"),
        (lambda d: d.update(pack="Ubuntu_Test"), "id пака"),
        (lambda d: d.update(tags=[]), "at least 1"),
        (lambda d: d["checks"][0]["probe"].update(path="etc/ssh/sshd_config"), "абсолютным"),
        (lambda d: d["checks"][0]["probe"].update(path="/etc/../etc/shadow"), "абсолютным"),
        (lambda d: d["checks"][0]["assert"].update(op="contains"), "неизвестный оператор"),
        (lambda d: d["checks"][0]["assert"].update(value="no"), "непустой список"),
        (lambda d: d["checks"][1]["assert"].update(value="четыре"), "нужно число"),
        (lambda d: d["checks"][1].update(unexpected="x"), "Extra inputs"),
        (lambda d: d["checks"][1]["assert"].update(op="mode_within", value=640), "в кавычках"),
        (lambda d: d["checks"][1]["assert"].update(op="mode_within", value="rw-r"), "в кавычках"),
        (lambda d: d["checks"][0].update(id="Bad ID"), "категория.ключ"),
        (lambda d: d["checks"][0]["probe"].update(type="shell"), "does not match any of the expected tags"),
        (lambda d: d["detect"][0].update(regex="ubuntu"), "ровно одно"),
    ],
)
def test_invalid_packs_are_rejected(mutation, message):
    data = copy.deepcopy(BASE_PACK)
    mutation(data)
    with pytest.raises(ValueError, match=message):
        Pack.model_validate(data)


def test_inventory_pack_may_have_no_checks():
    pack = Pack.model_validate(make_pack(maturity="inventory", checks=[]))
    assert pack.checks == []


@pytest.mark.parametrize("command", ["show running-config; reload", "show version && reboot", "reload", "show $(id)", "show x\nreload"])
def test_cli_config_rejects_non_readonly_commands(command):
    data = make_pack(
        transport="ssh",
        detect=[{"probe": {"type": "cli_config", "cmd": "show version", "match": "Cisco"}, "equals": "Cisco"}],
        checks=[{
            "id": "net.x", "title": "x",
            "probe": {"type": "cli_config", "cmd": command, "match": "x"},
            "assert": {"op": "absent"},
        }],
    )
    with pytest.raises(ValueError, match="только команды на чтение"):
        Pack.model_validate(data)


def test_ssh_transport_forbids_local_probe_types():
    data = make_pack(transport="ssh")
    with pytest.raises(ValueError, match="транспорт ssh допускает только"):
        Pack.model_validate(data)


def test_ssh_transport_rejects_modifying_cmd_regex():
    data = make_pack(
        transport="ssh",
        detect=[{"probe": {"type": "cmd_regex", "cmd": ["show", "version"], "pattern": "Cisco"}, "regex": "Cisco"}],
        checks=[{"id": "net.x", "title": "x", "probe": {"type": "cmd_regex", "cmd": ["reload"], "pattern": "x"},
                 "assert": {"op": "absent"}}],
    )
    with pytest.raises(ValueError, match="только команды на чтение"):
        Pack.model_validate(data)


def test_cmd_regex_executable_must_be_bare_name():
    data = make_pack(checks=[{"id": "x.y", "title": "t", "probe": {"type": "cmd_regex", "cmd": ["/bin/sh", "-c", "id"], "pattern": "."},
                              "assert": {"op": "exists"}}])
    with pytest.raises(ValueError, match="без пути"):
        Pack.model_validate(data)


# ---------- операторы ----------

@pytest.mark.parametrize(
    "actual, op, expected, outcome",
    [
        ("no", "eq", "No", "pass"),
        ("yes", "eq", "no", "fail"),
        ("yes", "ne", "no", "pass"),
        (" NO ", "in", ["no", "prohibit-password"], "pass"),
        ("yes", "in", ["no"], "fail"),
        ("yes", "not_in", ["no"], "pass"),
        ("3", "lte", 4, "pass"),
        (4, "lte", 4, "pass"),
        ("5", "lte", 4, "fail"),
        ("14", "gte", 14, "pass"),
        ("13", "gt", 14, "fail"),
        ("2", "lt", 3, "pass"),
        ("abc", "lte", 4, "error"),
        (True, "lte", 4, "error"),
        ("ssh", "regex", "^s+h$", "pass"),
        ("telnet", "regex", "^ssh$", "fail"),
        ("x", "exists", None, "pass"),
        ("", "exists", None, "fail"),
        (None, "exists", None, "fail"),
        (None, "absent", None, "pass"),
        ("x", "absent", None, "fail"),
        (None, "eq", "no", "error"),
        (None, "lte", 4, "error"),
        (None, "in", ["no"], "error"),
        ("640", "mode_within", "640", "pass"),
        ("600", "mode_within", "640", "pass"),
        ("400", "mode_within", "640", "pass"),
        ("644", "mode_within", "640", "fail"),
        ("604", "mode_within", "640", "fail"),  # численно меньше 640, но читаемо всеми
        ("750", "mode_within", "640", "fail"),
        ("0640", "mode_within", "640", "pass"),
        ("rw-r--r--", "mode_within", "640", "error"),
    ],
)
def test_check_assertion(actual, op, expected, outcome):
    assert check_assertion(actual, op, expected) == outcome


def test_describe_assertion():
    assert describe_assertion("lte", 4) == "<= 4"
    assert describe_assertion("in", ["no", "prohibit-password"]) == "одно из: no, prohibit-password"
    assert describe_assertion("absent") == "не задано"


# ---------- оценка пака ----------

def test_evaluate_pack_pass_fail_error_and_versions():
    pack = Pack.model_validate(BASE_PACK)
    results = evaluate_pack(pack, {"ssh.permit_root_login": probe_result("yes", evidence="PermitRootLogin yes")})

    by_id = {r.check_id: r for r in results}
    assert by_id["ssh.permit_root_login"].status == "fail"
    assert by_id["ssh.permit_root_login"].evidence == "PermitRootLogin yes"
    assert by_id["ssh.max_auth_tries"].status == "error"  # проба не прислана — нечего сравнивать
    assert all(r.pack_id == "ubuntu-test" and r.pack_version == "1.0.0" for r in results)
    assert all(r.rule_id is None for r in results)


def test_probe_that_could_not_run_is_error_not_fail():
    pack = Pack.model_validate(BASE_PACK)
    results = evaluate_pack(pack, {"ssh.permit_root_login": probe_result(None, found=False)})
    assert {r.check_id: r.status for r in results}["ssh.permit_root_login"] == "error"


def test_unknown_probe_result_keys_are_ignored():
    pack = Pack.model_validate(BASE_PACK)
    results = evaluate_pack(pack, {"nope.check": probe_result("x")})
    assert len(results) == 2


def test_coverage_shows_how_much_was_actually_evaluated():
    pack = Pack.model_validate(BASE_PACK)
    results = evaluate_pack(pack, {"ssh.max_auth_tries": probe_result("3")})

    coverage = compute_coverage(results)

    assert coverage == {"total": 2, "evaluated": 1, "errors": 1, "ratio": 50.0}
    assert compute_coverage([]) == {"total": 0, "evaluated": 0, "errors": 0, "ratio": None}


# ---------- platform_tags в движке правил ----------

def rule(rule_code, expected_value, product_type=None):
    return SimpleNamespace(id="rule-id", rule_code=rule_code, expected_value=expected_value, product_type=product_type)


def test_rule_applies_when_product_type_is_in_platform_tags():
    rules = [
        rule("ssh.permit_root_login", "no", product_type="linux-server"),
        rule("astra.mac_enabled", "true", product_type="astra-se"),
        rule("win.smb1_disabled", "true", product_type="windows-server"),
    ]
    facts = {"ssh": {"permit_root_login": "no"}, "astra": {"mac_enabled": "true"}}

    results = evaluate_asset(facts, rules, "server", platform_tags=["linux-server", "debian-family", "astra-se"])

    assert {r.rule_code: r.status for r in results} == {"ssh.permit_root_login": "pass", "astra.mac_enabled": "pass"}


def test_platform_tags_are_case_insensitive_and_optional():
    rules = [rule("astra.mac_enabled", "true", product_type="Astra-SE")]
    assert len(evaluate_asset({}, rules, "server", platform_tags=["astra-se"])) == 1
    assert evaluate_asset({}, rules, "server") == []  # без тегов поведение прежнее: asset_type не совпал


# ---------- манифест и подпись ----------

def test_manifest_contains_probes_but_not_assertions():
    manifest = build_manifest(Pack.model_validate(BASE_PACK))

    assert manifest["pack"] == "ubuntu-test" and manifest["tags"] == BASE_PACK["tags"]
    assert manifest["checks"][0] == {
        "id": "ssh.permit_root_login",
        "probe": {"type": "file_kv", "path": "/etc/ssh/sshd_config", "key": "PermitRootLogin",
                  "separator": "whitespace", "match": "first", "ignore_case": True, "follow_include": False},
    }
    dumped = str(manifest)
    assert "assert" not in dumped and "severity" not in dumped and "remediation" not in dumped


def test_signature_detects_any_tampering():
    manifest = build_manifest(Pack.model_validate(BASE_PACK))
    signature = sign_manifest(manifest, "key-1")

    assert verify_manifest(manifest, signature, "key-1")
    assert not verify_manifest(manifest, signature, "other-key")
    tampered = copy.deepcopy(manifest)
    tampered["checks"][0]["probe"]["path"] = "/etc/shadow"
    assert not verify_manifest(tampered, signature, "key-1")


def test_canonical_json_is_key_order_independent():
    assert canonical_json({"b": 1, "a": [1, 2]}) == canonical_json({"a": [1, 2], "b": 1})


# ---------- реестр ----------

def test_registry_latest_uses_numeric_version_order(tmp_path):
    for version in ("1.9.0", "1.10.0", "1.2.0"):
        (tmp_path / f"p-{version}.yaml").write_text(yaml.safe_dump(make_pack(version=version)), encoding="utf-8")

    registry = load_registry(tmp_path)

    assert registry.get("ubuntu-test").version == "1.10.0"
    assert registry.get("ubuntu-test", "1.2.0").version == "1.2.0"
    assert registry.get("ubuntu-test", "9.9.9") is None
    assert registry.get("missing") is None


def test_registry_filters_by_transport():
    ssh_pack = make_pack(
        pack="cisco-test", transport="ssh",
        detect=[{"probe": {"type": "cli_config", "cmd": "show version", "match": "Cisco"}, "equals": "Cisco"}],
        checks=[{"id": "cisco.x", "title": "x", "probe": {"type": "cli_config", "cmd": "show running-config", "match": "^ip http server"},
                 "assert": {"op": "absent"}}],
    )
    registry = PackRegistry([Pack.model_validate(BASE_PACK), Pack.model_validate(ssh_pack)])

    assert [p.pack for p in registry.latest("ssh")] == ["cisco-test"]
    assert [p.pack for p in registry.latest("local")] == ["ubuntu-test"]
    assert len(registry.latest()) == 2


def test_registry_rejects_duplicate_version():
    pack = Pack.model_validate(BASE_PACK)
    with pytest.raises(PackError, match="дважды"):
        PackRegistry([pack, pack])


def test_broken_pack_error_names_the_file(tmp_path):
    (tmp_path / "broken.yaml").write_text(yaml.safe_dump(make_pack(version="x")), encoding="utf-8")
    with pytest.raises(PackError, match=r"broken\.yaml.*version"):
        load_registry(tmp_path)
    (tmp_path / "broken.yaml").write_text("pack: [unclosed", encoding="utf-8")
    with pytest.raises(PackError, match=r"broken\.yaml"):
        load_pack_file(tmp_path / "broken.yaml")


def test_missing_packs_directory_gives_empty_registry(tmp_path):
    assert load_registry(tmp_path / "nope").latest() == []


# ---------- first_of и follow_include в формате пака ----------

def _first_of_pack(probe, transport="local", detect=None):
    return make_pack(
        transport=transport,
        detect=detect or BASE_PACK["detect"],
        checks=[{"id": "fw.enabled", "title": "x", "probe": probe, "assert": {"op": "in", "value": ["active", "yes"]}}],
    )


UFW_STATUS = {"type": "cmd_regex", "cmd": ["ufw", "status", "verbose"], "pattern": "Status:\\s*(\\w+)"}
UFW_CONF = {"type": "file_kv", "path": "/etc/ufw/ufw.conf", "key": "ENABLED", "separator": "equals"}


def test_first_of_probe_is_valid_and_reaches_the_manifest():
    pack = Pack.model_validate(_first_of_pack({"type": "first_of", "probes": [UFW_STATUS, UFW_CONF]}))
    probe = build_manifest(pack)["checks"][0]["probe"]
    assert probe["type"] == "first_of" and [p["type"] for p in probe["probes"]] == ["cmd_regex", "file_kv"]


@pytest.mark.parametrize(
    "probe, message",
    [
        ({"type": "first_of", "probes": [UFW_CONF]}, "at least 2"),
        ({"type": "first_of", "probes": [UFW_CONF] * 6}, "at most 5"),
        ({"type": "first_of", "probes": [{"type": "first_of", "probes": [UFW_STATUS, UFW_CONF]}, UFW_CONF]}, "does not match any"),
        ({"type": "first_of", "probes": [UFW_STATUS, {**UFW_CONF, "path": "relative/path"}]}, "абсолютным"),
    ],
)
def test_invalid_first_of_is_rejected(probe, message):
    with pytest.raises(ValueError, match=message):
        Pack.model_validate(_first_of_pack(probe))


def test_ssh_pack_rejects_local_probe_hidden_inside_first_of():
    cli = {"type": "cli_config", "cmd": "show version", "match": "x"}
    data = _first_of_pack(
        {"type": "first_of", "probes": [cli, UFW_CONF]}, transport="ssh",
        detect=[{"probe": cli, "equals": "x"}],
    )
    with pytest.raises(ValueError, match="транспорт ssh допускает только"):
        Pack.model_validate(data)


def test_ssh_pack_rejects_modifying_command_inside_first_of():
    cli = {"type": "cli_config", "cmd": "show version", "match": "x"}
    reload_probe = {"type": "cmd_regex", "cmd": ["reload"], "pattern": "x"}
    data = _first_of_pack({"type": "first_of", "probes": [cli, reload_probe]}, transport="ssh", detect=[{"probe": cli, "equals": "x"}])
    with pytest.raises(ValueError, match="только команды на чтение"):
        Pack.model_validate(data)


def test_follow_include_is_a_known_option_and_defaults_off():
    data = make_pack()
    data["checks"][0]["probe"]["follow_include"] = True
    assert Pack.model_validate(data).checks[0].probe.follow_include is True
    assert Pack.model_validate(BASE_PACK).checks[0].probe.follow_include is False


def test_default_registry_ships_ubuntu_server_pack():
    from app.api.deps import get_pack_registry

    pack = get_pack_registry().get("ubuntu-server")

    assert pack is not None and pack.maturity == "baseline" and pack.transport == "local"
    assert pack.version == "1.3.0"
    # 12 перенесённых из старого агента + auditd (1.1.0) + pam_pwquality (1.3.0); Samba с 1.2.0 — в паке samba
    assert len(pack.checks) == 14
    assert "ubuntu" in pack.tags and "linux-server" in pack.tags


# ---------- этап 2: cmd_foreach, require, уровни зрелости ----------

FOREACH_PROBE = {
    "type": "cmd_foreach", "list_cmd": ["docker", "ps", "-q"],
    "item_cmd": ["docker", "inspect", "--format", "{{.HostConfig.Privileged}}"], "pattern": "^true$",
}


def _foreach_pack(probe, **overrides):
    return make_pack(checks=[{"id": "docker.x", "title": "x", "probe": probe, "assert": {"op": "eq", "value": 0}}], **overrides)


def test_cmd_foreach_is_valid_and_reaches_the_manifest():
    pack = Pack.model_validate(_foreach_pack(FOREACH_PROBE))
    probe = build_manifest(pack)["checks"][0]["probe"]
    assert probe["type"] == "cmd_foreach" and probe["max_items"] == 100 and probe["list_cmd"] == ["docker", "ps", "-q"]


@pytest.mark.parametrize(
    "mutation, message",
    [
        ({"list_cmd": ["/usr/bin/docker", "ps"]}, "без пути"),
        ({"item_cmd": ["sh", "-c\nid"]}, "перевод строки"),
        ({"max_items": 0}, "greater than or equal to 1"),
        ({"max_items": 500}, "less than or equal to 200"),
        ({"pattern": "(unclosed"}, "регулярное выражение"),
        ({"list_cmd": []}, "at least 1"),
    ],
)
def test_invalid_cmd_foreach_is_rejected(mutation, message):
    with pytest.raises(ValueError, match=message):
        Pack.model_validate(_foreach_pack({**FOREACH_PROBE, **mutation}))


def test_ssh_transport_rejects_cmd_foreach():
    cli = {"type": "cli_config", "cmd": "show version", "match": "x"}
    data = _foreach_pack(FOREACH_PROBE, transport="ssh", detect=[{"probe": cli, "equals": "x"}])
    with pytest.raises(ValueError, match="транспорт ssh допускает только"):
        Pack.model_validate(data)


def test_cli_config_require_must_be_a_valid_regex():
    probe = {"type": "cli_config", "cmd": "show running-config", "match": "x", "require": "(unclosed"}
    data = make_pack(transport="ssh", detect=[{"probe": {"type": "cli_config", "cmd": "show version", "match": "x"}, "equals": "x"}],
                     checks=[{"id": "n.x", "title": "x", "probe": probe, "assert": {"op": "exists"}}])
    with pytest.raises(ValueError, match="регулярное выражение"):
        Pack.model_validate(data)


def test_draft_pack_may_have_checks_without_verified_on_but_baseline_may_not():
    assert Pack.model_validate(make_pack(maturity="draft", verified_on=[])).maturity == "draft"
    with pytest.raises(ValueError, match="verified_on"):
        Pack.model_validate(make_pack(maturity="baseline", verified_on=[]))


def test_shipped_packs_and_their_maturity():
    from app.api.deps import get_pack_registry

    packs = {p.pack: p for p in get_pack_registry().latest()}

    assert {name: p.maturity for name, p in packs.items()} == {
        "ubuntu-server": "baseline", "docker": "baseline", "cisco-ios": "draft", "astra-linux": "inventory",
        "postgresql": "draft", "samba": "draft", "windows-server": "draft", "windows-client": "draft",
    }
    assert packs["astra-linux"].checks == [] and packs["cisco-ios"].verified_on == []
    assert all(p.verified_on for p in packs.values() if p.maturity == "baseline")  # baseline = подтверждено на оборудовании
