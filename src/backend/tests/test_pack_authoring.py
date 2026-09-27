"""Инструменты автора пака (этап 3): валидатор и прогон на образцах.

Первая часть — требования к паку в репозитории (CI не пропустит пак без фикстуры и проверку без
образцов нарушения и соблюдения). Вторая — сами инструменты ловят то, что должны ловить."""
import copy
import textwrap

import pytest

from app.services.packs.authoring import (
    AGENT_DIR,
    FIXTURES_DIR,
    PACKS_DIR,
    run_fixture,
    run_fixtures,
    validate_directory,
)
from app.services.packs.models import CmdRegexProbe
from app.services.packs.registry import PackError, load_registry

if not (AGENT_DIR / "probes.py").exists():
    pytest.skip("каталог agent/ недоступен (тесты запущены вне репозитория)", allow_module_level=True)

REGISTRY = load_registry(PACKS_DIR)
FIXTURE_RESULTS = {result.pack: result for result in run_fixtures()}


# ---------- требования к пакам в репозитории ----------

def test_shipped_packs_have_no_validation_errors():
    errors = [str(f) for f in validate_directory() if f.level == "error"]
    assert errors == []


@pytest.mark.parametrize("pack", [p.pack for p in REGISTRY.latest()])
def test_latest_version_of_every_pack_has_a_passing_fixture(pack):
    result = FIXTURE_RESULTS.get(pack)
    assert result is not None, f"нет фикстуры для пака {pack} в {FIXTURES_DIR.name}/"
    assert result.version == REGISTRY.get(pack).version, "фикстура должна проверять последнюю версию пака"
    assert [p for case in result.cases for p in case.problems] == []


@pytest.mark.parametrize("pack", [p.pack for p in REGISTRY.latest()])
def test_every_check_is_shown_both_failing_and_passing(pack):
    assert FIXTURE_RESULTS[pack].uncovered == []


# ---------- валидатор ловит то, что пропускает схема ----------

GOOD_CHECK = {
    "id": "t.ok", "title": "ok",
    "probe": {"type": "file_kv", "path": "/etc/ssh/sshd_config", "key": "X11Forwarding"},
    "assert": {"op": "eq", "value": "no"}, "refs": [{"source": "test"}],
}


def write_pack(directory, name, checks, pack="t-pack", version="1.0.0", transport="local"):
    import yaml

    body = {
        "pack": pack, "version": version, "maturity": "draft", "tags": ["linux-server"], "transport": transport,
        "detect": [{"probe": {"type": "file_kv", "path": "/etc/os-release", "key": "ID"}, "equals": "ubuntu"}]
        if transport == "local" else [{"probe": {"type": "cli_config", "cmd": "show version", "match": "(IOS)"}, "regex": "IOS"}],
        "checks": checks,
    }
    (directory / name).write_text(yaml.safe_dump(body, allow_unicode=True), encoding="utf-8")


def messages(directory):
    return [f.message for f in validate_directory(directory)]


def test_validator_accepts_a_correct_pack(tmp_path):
    write_pack(tmp_path, "t-pack-1.0.0.yaml", [GOOD_CHECK])
    assert validate_directory(tmp_path) == []


def test_validator_rejects_command_outside_agent_whitelist(tmp_path):
    check = {**GOOD_CHECK, "probe": {"type": "cmd_regex", "cmd": ["curl", "http://example.com"], "pattern": "(.*)"}}
    write_pack(tmp_path, "t-pack-1.0.0.yaml", [check])
    assert any("вне белого списка агента" in m for m in messages(tmp_path))


def test_validator_rejects_docker_inspect_field_outside_whitelist(tmp_path):
    # Config.Env может содержать секреты — агент его не отдаёт, пак не должен на него рассчитывать
    check = {**GOOD_CHECK, "probe": {
        "type": "cmd_foreach", "list_cmd": ["docker", "ps", "-q"],
        "item_cmd": ["docker", "inspect", "--format", "{{.Config.Env}}"], "pattern": "PASSWORD",
    }, "assert": {"op": "eq", "value": 0}}
    write_pack(tmp_path, "t-pack-1.0.0.yaml", [check])
    assert any("docker inspect --format {{.Config.Env}}" in m for m in messages(tmp_path))


def test_validator_rejects_secret_paths(tmp_path):
    check = {**GOOD_CHECK, "probe": {"type": "file_regex", "path": "/etc/shadow", "pattern": "root:(.*)"}, "assert": {"op": "exists"}}
    write_pack(tmp_path, "t-pack-1.0.0.yaml", [check])
    assert any("запрещён агенту" in m for m in messages(tmp_path))


def test_validator_rejects_cli_config_in_a_local_pack(tmp_path):
    check = {**GOOD_CHECK, "probe": {"type": "cli_config", "cmd": "show running-config", "match": "^x"}, "assert": {"op": "absent"}}
    write_pack(tmp_path, "t-pack-1.0.0.yaml", [check])
    assert any("только по SSH" in m for m in messages(tmp_path))


def test_validator_requires_refs_and_matching_file_name(tmp_path):
    write_pack(tmp_path, "whatever.yaml", [{k: v for k, v in GOOD_CHECK.items() if k != "refs"}])
    found = messages(tmp_path)
    assert any("имя файла должно быть t-pack-1.0.0.yaml" in m for m in found)
    assert any("нет refs" in m for m in found)


def test_validator_reports_schema_errors_per_file_and_keeps_going(tmp_path):
    (tmp_path / "broken-1.0.0.yaml").write_text("pack: broken\nversion: 1\n", encoding="utf-8")
    write_pack(tmp_path, "t-pack-1.0.0.yaml", [GOOD_CHECK])
    findings = validate_directory(tmp_path)
    assert [f.where for f in findings] == ["broken-1.0.0.yaml"]


def test_validator_warns_about_removed_checks_and_changed_severity(tmp_path):
    second = {**GOOD_CHECK, "id": "t.second"}
    write_pack(tmp_path, "t-pack-1.0.0.yaml", [GOOD_CHECK, second])
    write_pack(tmp_path, "t-pack-1.1.0.yaml", [{**GOOD_CHECK, "severity": "critical"}], version="1.1.0")
    findings = validate_directory(tmp_path)
    assert {f.level for f in findings} == {"warning"}
    assert sorted(f.message for f in findings) == [
        "проверка t.second удалена",
        "у t.ok изменилась критичность: medium → critical",
    ]


def test_validator_checks_ssh_commands_are_read_only(tmp_path):
    check = {**GOOD_CHECK, "probe": {"type": "cli_config", "cmd": "show running-config | redirect tftp://x", "match": "^x"},
             "assert": {"op": "absent"}}
    write_pack(tmp_path, "t-pack-1.0.0.yaml", [check], transport="ssh")
    assert any("не «только чтение»" in m for m in messages(tmp_path))


# ---------- прогон на образцах ----------

def fixture(tmp_path, text):
    path = tmp_path / "f.yaml"
    path.write_text(textwrap.dedent(text), encoding="utf-8")
    return path


def test_fixture_mismatch_is_reported_with_the_actual_value(tmp_path):
    path = fixture(tmp_path, """
        pack: ubuntu-server
        cases:
          - name: X11 включён
            files: {/etc/ssh/sshd_config: "X11Forwarding yes\\n"}
            expect: {ssh.x11_forwarding: pass}
    """)
    result = run_fixture(path, REGISTRY)
    assert not result.ok
    assert result.cases[0].problems == ["ssh.x11_forwarding: ожидалось pass, получено fail (значение 'yes')"]


def test_fixture_cannot_allow_a_command_the_agent_refuses(tmp_path):
    # Вывод «разрешён» фикстурой, но команда вне белого списка агента — как на хосте, это error
    registry = copy.deepcopy(REGISTRY)
    pack = registry.get("ubuntu-server")
    pack.checks[0].probe = CmdRegexProbe(type="cmd_regex", cmd=["cat", "/etc/ssh/sshd_config"], pattern="PermitRootLogin (\\S+)")
    path = fixture(tmp_path, """
        pack: ubuntu-server
        cases:
          - commands: {"cat /etc/ssh/sshd_config": "PermitRootLogin no\\n"}
            expect: {ssh.permit_root_login: pass}
    """)
    [case] = run_fixture(path, registry).cases
    assert case.statuses["ssh.permit_root_login"] == "error"


def test_fixture_with_unknown_pack_or_without_cases_is_an_error(tmp_path):
    with pytest.raises(PackError, match="не найден"):
        run_fixture(fixture(tmp_path, "pack: no-such-pack\ncases: [{name: x}]\n"), REGISTRY)
    with pytest.raises(PackError, match="нужны ключи"):
        run_fixture(fixture(tmp_path, "pack: docker\n"), REGISTRY)


def test_validator_allows_file_stat_on_secret_files_but_not_reading_them(tmp_path):
    """Права /etc/shadow проверять можно (file_stat не читает содержимое), читать его — нельзя."""
    stat_check = {**GOOD_CHECK, "probe": {"type": "file_stat", "path": "/etc/shadow", "field": "mode"},
                  "assert": {"op": "mode_within", "value": "640"}}
    write_pack(tmp_path, "t-pack-1.0.0.yaml", [stat_check])
    assert validate_directory(tmp_path) == []
