"""python -m app.commands.pack evaluate — оценка прогона агента в CI (контейнеры Linux, Windows Server)."""
import json

import yaml

from app.commands.pack import main
from app.services.packs.authoring import FIXTURES_DIR, PACKS_DIR, FixtureHost, _merge, load_agent_probes
from app.services.packs.manifest import build_manifest
from app.services.packs.registry import load_registry


def _payload(tmp_path, errors: dict[str, str], pack_id="ubuntu-server"):
    """Прогон настоящих проб агента на образце укреплённого хоста; у проверок из errors — ошибка пробы."""
    pack = load_registry(PACKS_DIR).get(pack_id)
    spec = yaml.safe_load((FIXTURES_DIR / f"{pack_id}.yaml").read_text(encoding="utf-8"))
    agent = load_agent_probes()
    host = FixtureHost(agent, pack.transport, **_merge(spec.get("base") or {}, spec["cases"][0]))
    probe_results = agent.run_manifest(host, build_manifest(pack))
    for check_id, error in errors.items():
        probe_results[check_id] = {"found": False, "error": error}
    path = tmp_path / "payload.json"
    path.write_text(json.dumps({
        "asset": {"hostname": "ci", "os": "Ubuntu 24.04"},
        "packs": [{"id": pack.pack, "version": pack.version, "probe_results": probe_results}],
    }), encoding="utf-8")
    return path, [check.id for check in pack.checks]


def test_missing_command_errors_are_allowed_by_reason_not_by_id(tmp_path, capsys):
    ids = load_registry(PACKS_DIR).get("ubuntu-server").checks
    service, kernel, other = ids[0].id, ids[1].id, ids[2].id
    path, _ = _payload(tmp_path, {
        service: "команда systemctl не найдена",
        kernel: "команда modprobe не найдена",
        other: "нет прав на чтение /etc/shadow",
    })
    base = ["evaluate", str(path), "--pack", "ubuntu-server"]

    assert main(base) == 1
    assert "не выполнилась" in capsys.readouterr().out

    # отсутствующие команды разрешены, а «нет прав» — нет
    assert main([*base, "--allow-missing-command", "systemctl", "--allow-missing-command", "modprobe"]) == 1
    out = capsys.readouterr().out
    assert other in out and service not in out and kernel not in out

    assert main([*base, "--allow-missing-command", "systemctl", "--allow-missing-command", "modprobe", "--allow-error", other]) == 0
    assert capsys.readouterr().out.startswith("✓")

    # разрешена другая команда — ошибка systemctl остаётся ошибкой
    assert main([*base, "--allow-missing-command", "firewall-cmd", "--allow-error", other, "--allow-error", kernel]) == 1


def test_pack_not_run_on_this_platform_fails(tmp_path, capsys):
    path, _ = _payload(tmp_path, {})
    assert main(["evaluate", str(path), "--pack", "astra-linux"]) == 1
    assert "не выполнен" in capsys.readouterr().out


def test_errors_allowed_by_message_pattern(tmp_path):
    check = load_registry(PACKS_DIR).get("ubuntu-server").checks[0].id
    path, _ = _payload(tmp_path, {check: "systemctl is-active inetd: состояние не получено (System has not been booted "
                                         "with systemd as init system (PID 1). Can't operate.)"})
    base = ["evaluate", str(path), "--pack", "ubuntu-server"]
    assert main(base) == 1
    assert main([*base, "--allow-error-matching", "not been booted with systemd"]) == 0
    assert main([*base, "--allow-error-matching", "нет прав"]) == 1
