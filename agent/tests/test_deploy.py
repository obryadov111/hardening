"""Unit-файл службы и образец настроек согласованы с CLI агента: переименование флага или новая
переменная в unit-файле без образца — провал теста, а не ошибка на хосте при первом прогоне."""
import re
import shlex
from pathlib import Path

import collector

DEPLOY = Path(__file__).resolve().parents[1] / "deploy"
UNIT = (DEPLOY / "hardening-agent@.service").read_text(encoding="utf-8")
ENV_EXAMPLE = (DEPLOY / "agent.env.example").read_text(encoding="utf-8")


def exec_start() -> str:
    line = re.search(r"^ExecStart=(.+?)(?<!\\)$", UNIT, re.M | re.S).group(1)
    return line.replace("\\\n", " ")


def example_env() -> dict:
    return dict(line.split("=", 1) for line in ENV_EXAMPLE.splitlines() if line and not line.startswith("#"))


def test_every_variable_used_by_the_unit_is_in_the_example():
    used = set(re.findall(r"\$\{?([A-Z_]+)\}?", exec_start()))
    assert used <= set(example_env()), used - set(example_env())
    # ключи читает collector.py из окружения — они тоже должны быть в образце
    assert {"HARDENING_AGENT_API_KEY", "HARDENING_PACK_KEY"} <= set(example_env())


def test_exec_start_arguments_are_accepted_by_the_agent_cli():
    env = example_env()
    command = exec_start()
    # как systemd: ${VAR} — одним аргументом, $VAR — по пробелам
    argv = []
    for token in shlex.split(re.sub(r"\$\{([A-Z_]+)\}", lambda m: shlex.quote(env[m.group(1)]), command)):
        if re.fullmatch(r"\$[A-Z_]+", token):
            argv.extend(env[token[1:]].split())
        else:
            argv.append(token)
    assert argv[:2] == ["/usr/bin/python3", "/opt/hardening-agent/collector.py"]
    args = collector.parse_args(argv[2:])
    assert args.use_packs and args.environment == env["HARDENING_ENVIRONMENT"] and args.criticality == env["HARDENING_CRITICALITY"]


def test_unit_is_hardened_and_unprivileged():
    for directive in ("User=hardening-agent", "NoNewPrivileges=yes", "ProtectSystem=strict", "CapabilityBoundingSet=\n"):
        assert directive in UNIT, directive
