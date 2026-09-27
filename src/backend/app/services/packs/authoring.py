"""Инструменты автора пака (этап 3): валидатор и прогон пака на образцах (fixture).

Схему пака проверяет сама модель (models.py). Валидатор ловит то, что схема пропускает, но
что на хосте обернётся отказом агента или путаницей в отчётах:
  * команда пробы вне белого списка агента (LOCAL_COMMAND_POLICY) или не «только чтение» по SSH —
    агент откажется её выполнять, и проверка всегда будет error;
  * путь из запрещённых агенту (секреты) — то же самое;
  * cli_config в локальном паке — агент выполняет её только по SSH;
  * имя файла не совпадает с `<pack>-<version>.yaml`;
  * проверка без ссылки на источник (refs);
  * между версиями одного пака пропала проверка или поменялась её критичность (предупреждение).

Прогон на образцах использует настоящие пробы агента (agent/probes.py) и настоящую оценку сервера
(evaluate_pack): отличается только транспорт — файлы, права и вывод команд берутся из фикстуры, а
команды при этом проходят тот же белый список, что и на хосте.
"""
from __future__ import annotations

import fnmatch
import importlib.util
import os
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace

import yaml

from app.services.packs.evaluate import evaluate_pack
from app.services.packs.manifest import build_manifest
from app.services.packs.models import Pack, leaf_probes
from app.services.packs.registry import PackError, PackRegistry, load_pack_file

BACKEND_DIR = Path(__file__).resolve().parents[3]
PACKS_DIR = BACKEND_DIR / "app" / "packs"
FIXTURES_DIR = BACKEND_DIR / "pack_tests"
# Каталог агента — в репозитории рядом с бэкендом; в образе бэкенда его нет.
AGENT_DIR = Path(os.environ.get("HARDENING_AGENT_DIR") or BACKEND_DIR.parents[1] / "agent")
SAMPLE_CONTAINER_ID = "0123456789ab"
STATUSES = ("pass", "fail", "error")


def load_agent_probes():
    """Модуль проб агента. Агент — отдельный компонент без зависимостей, поэтому грузится по пути,
    а не как пакет бэкенда."""
    path = AGENT_DIR / "probes.py"
    if not path.exists():
        raise PackError(f"не найден {path}: инструменты автора пака работают из репозитория (или задайте HARDENING_AGENT_DIR)")
    spec = importlib.util.spec_from_file_location("hardening_agent_probes", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ============================== валидатор ==============================

@dataclass
class Finding:
    level: str  # error | warning
    where: str
    message: str

    def __str__(self) -> str:
        return f"[{self.level}] {self.where}: {self.message}"


def _local_argvs(probe) -> list[list[str]]:
    """Команды, которые агент выполнит для пробы на локальном транспорте (для белого списка)."""
    if probe.type == "cmd_regex":
        return [list(probe.cmd)]
    if probe.type == "cmd_foreach":
        return [list(probe.list_cmd), [*probe.item_cmd, SAMPLE_CONTAINER_ID]]
    if probe.type == "service_state":
        return [["systemctl", "is-enabled" if probe.field == "enabled" else "is-active", probe.service]]
    if probe.type == "pkg_version":
        return [["dpkg-query", "-W", "-f=${Status}|${Version}", probe.package]]
    return []


def _probe_findings(pack: Pack, probe, where: str, agent) -> list[Finding]:
    findings = []
    path = getattr(probe, "path", None)
    if path and any(p.search(path) for p in agent.DENIED_PATH_PATTERNS):
        findings.append(Finding("error", where, f"путь {path} запрещён агенту (секреты) — проба всегда будет error"))

    if pack.transport == "ssh":
        command = probe.cmd if probe.type == "cli_config" else " ".join(probe.cmd) if probe.type == "cmd_regex" else None
        if command is not None and not agent.is_readonly_cli(command):
            findings.append(Finding("error", where, f"агент не выполнит по SSH команду {command!r}: не «только чтение»"))
        return findings

    if probe.type == "cli_config":
        findings.append(Finding("error", where, "cli_config выполняется только по SSH, в локальном паке агент её отклонит"))
    for argv in _local_argvs(probe):
        policy = agent.LOCAL_COMMAND_POLICY.get(argv[0])
        if policy is None or not policy.match(" ".join(argv[1:])):
            findings.append(Finding(
                "error", where,
                f"команда вне белого списка агента: {' '.join(argv)!r} — добавьте её в LOCAL_COMMAND_POLICY "
                "(agent/probes.py) осознанно или замените пробу",
            ))
    return findings


def validate_pack(pack: Pack, path: Path | None = None, agent=None) -> list[Finding]:
    agent = agent or load_agent_probes()
    name = path.name if path else f"{pack.pack}-{pack.version}"
    findings = []
    if path is not None and path.name != f"{pack.pack}-{pack.version}.yaml":
        findings.append(Finding("error", name, f"имя файла должно быть {pack.pack}-{pack.version}.yaml"))

    for i, rule in enumerate(pack.detect):
        for leaf in leaf_probes(rule.probe):
            findings += _probe_findings(pack, leaf, f"{name} detect[{i}]", agent)
    for check in pack.checks:
        where = f"{name} {check.id}"
        if not check.refs:
            findings.append(Finding("error", where, "нет refs: у проверки должен быть источник требования (CIS, методика ФСТЭК, вендор)"))
        for leaf in leaf_probes(check.probe):
            findings += _probe_findings(pack, leaf, where, agent)
    return findings


def compare_versions(older: Pack, newer: Pack) -> list[Finding]:
    """Предупреждения при переходе между версиями: пропавшая проверка ломает сравнение сканов,
    сменившаяся критичность меняет оценку прошлых нарушений задним числом."""
    where = f"{newer.pack} {older.version} → {newer.version}"
    old = {c.id: c for c in older.checks}
    new = {c.id: c for c in newer.checks}
    findings = [Finding("warning", where, f"проверка {cid} удалена") for cid in sorted(old.keys() - new.keys())]
    findings += [
        Finding("warning", where, f"у {cid} изменилась критичность: {old[cid].severity} → {new[cid].severity}")
        for cid in sorted(old.keys() & new.keys()) if old[cid].severity != new[cid].severity
    ]
    return findings


def validate_directory(directory: Path = PACKS_DIR) -> list[Finding]:
    agent = load_agent_probes()
    findings, registry = [], PackRegistry()
    by_id: dict[str, list[Pack]] = {}
    for path in sorted([*directory.rglob("*.yaml"), *directory.rglob("*.yml")]):
        try:
            pack = load_pack_file(path)
            registry.add(pack)
        except PackError as exc:
            findings.append(Finding("error", path.name, str(exc).removeprefix(f"{path.name}: ")))
            continue
        findings += validate_pack(pack, path, agent)
        by_id.setdefault(pack.pack, []).append(pack)
    for versions in by_id.values():
        versions.sort(key=lambda p: p.version_tuple)
        for older, newer in zip(versions, versions[1:], strict=False):
            findings += compare_versions(older, newer)
    return findings


# ============================== прогон на образцах ==============================

class FixtureHost:
    """Транспорт агента поверх фикстуры. Команды проходят белый список агента, как на хосте:
    фикстура не может «разрешить» то, что агент на хосте не выполнит."""

    def __init__(self, agent, transport: str, files=None, stats=None, commands=None, cli=None):
        self.agent, self.name = agent, transport
        self.files = dict(files or {})
        self.stats = dict(stats or {})
        self.commands = {k: _command_output(v) for k, v in (commands or {}).items()}
        self.cli = dict(cli or {})

    def read_file(self, path):
        if any(p.search(path) for p in self.agent.DENIED_PATH_PATTERNS):
            raise self.agent.ProbeError(f"чтение {path} запрещено политикой агента")
        if path not in self.files:
            raise self.agent.ProbeError(f"нет файла {path}")
        return self.files[path]

    def stat_file(self, path):
        spec = self.stats.get(path)
        if spec is None:
            raise self.agent.ProbeError(f"нет файла {path}")
        spec = {"mode": spec} if isinstance(spec, (str, int)) else spec
        return SimpleNamespace(st_mode=int(str(spec.get("mode", "644")), 8), st_uid=spec.get("uid", 0), st_gid=spec.get("gid", 0))

    def glob(self, pattern):
        return sorted(p for p in self.files if fnmatch.fnmatch(p, pattern))

    def run(self, argv):
        if self.name == "ssh":
            return self.run_cli(" ".join(argv))
        policy = self.agent.LOCAL_COMMAND_POLICY.get(argv[0]) if argv else None
        if policy is None or not policy.match(" ".join(argv[1:])):
            raise self.agent.ProbeError(f"команда вне белого списка агента: {' '.join(argv)}")
        out = self.commands.get(" ".join(argv))
        if out is None:
            raise self.agent.ProbeError(f"команда {argv[0]} не найдена")
        return self.agent.CmdOutput(*out)

    def run_cli(self, command):
        if self.name != "ssh":
            raise self.agent.ProbeError("cli_config недоступна на локальном транспорте")
        if not self.agent.is_readonly_cli(command):
            raise self.agent.ProbeError(f"по SSH допустимы только команды на чтение: {command!r}")
        return self.agent.CmdOutput(self.cli.get(command, "% Invalid input detected at '^' marker.\n"), "", 0)


def _command_output(value) -> tuple[str, str, int]:
    if isinstance(value, str):
        return value, "", 0
    return value.get("stdout", ""), value.get("stderr", ""), int(value.get("code", 0))


def _merge(base: dict, case: dict) -> dict:
    merged = {key: {**(base.get(key) or {}), **(case.get(key) or {})} for key in ("files", "stats", "commands", "cli")}
    for path in case.get("drop") or []:
        for key in ("files", "stats"):
            merged[key].pop(path, None)
    for command in case.get("drop_commands") or []:
        merged["commands"].pop(command, None)
        merged["cli"].pop(command, None)
    return merged


@dataclass
class CaseResult:
    name: str
    problems: list[str] = field(default_factory=list)
    statuses: dict[str, str] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not self.problems


@dataclass
class FixtureResult:
    fixture: str
    pack: str
    version: str
    cases: list[CaseResult]
    uncovered: list[str]

    @property
    def ok(self) -> bool:
        return all(case.ok for case in self.cases)


def run_fixture(path: Path, registry: PackRegistry, agent=None) -> FixtureResult:
    agent = agent or load_agent_probes()
    spec = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(spec, dict) or "pack" not in spec or not spec.get("cases"):
        raise PackError(f"{path.name}: нужны ключи pack и cases")
    pack = registry.get(spec["pack"], spec.get("version"))
    if pack is None:
        raise PackError(f"{path.name}: пак {spec['pack']} {spec.get('version') or '(последняя версия)'} не найден")
    manifest = build_manifest(pack)
    check_ids = [check.id for check in pack.checks]
    base = spec.get("base") or {}
    covered: dict[str, set[str]] = {cid: set() for cid in check_ids}

    results = []
    for i, case in enumerate(spec["cases"]):
        result = CaseResult(name=case.get("name") or f"case {i + 1}")
        host = FixtureHost(agent, pack.transport, **_merge(base, case))

        if "detect" in case:
            detected = agent.matches_detect(host, manifest["detect"])
            if detected != bool(case["detect"]):
                result.problems.append(f"detect: ожидалось {bool(case['detect'])}, получено {detected}")

        expect = case.get("expect") or {}
        unknown = sorted(set(expect) - set(check_ids))
        if unknown:
            result.problems.append(f"в expect есть id, которых нет в паке: {', '.join(unknown)}")
        bad = sorted(cid for cid, status in expect.items() if status not in STATUSES)
        if bad:
            result.problems.append(f"статус должен быть одним из {', '.join(STATUSES)}: {', '.join(bad)}")

        if expect:
            raw = agent.run_manifest(host, manifest)
            for check_result in evaluate_pack(pack, {k: SimpleNamespace(**v) for k, v in raw.items()}):
                result.statuses[check_result.check_id] = check_result.status
                want = expect.get(check_result.check_id)
                if want is None:
                    continue
                covered[check_result.check_id].add(want)
                if want != check_result.status:
                    detail = raw[check_result.check_id].get("error") or f"значение {check_result.actual_value!r}"
                    result.problems.append(f"{check_result.check_id}: ожидалось {want}, получено {check_result.status} ({detail})")
        results.append(result)

    # Проверка «покрыта», только если образцы показывают и нарушение, и соблюдение: одно pass
    # ничего не говорит о том, что проверка вообще умеет ловить нарушение.
    uncovered = [cid for cid in check_ids if not {"pass", "fail"} <= covered[cid]]
    return FixtureResult(path.name, pack.pack, pack.version, results, uncovered)


def run_fixtures(directory: Path = FIXTURES_DIR, packs_dir: Path = PACKS_DIR) -> list[FixtureResult]:
    from app.services.packs.registry import load_registry

    registry, agent = load_registry(packs_dir), load_agent_probes()
    return [run_fixture(path, registry, agent) for path in sorted(directory.glob("*.yaml"))]
