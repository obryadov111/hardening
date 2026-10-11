"""Проверка по выгрузке конфигурации, загруженной через интерфейс, — без агента.

Для устройств, к которым нет SSH-доступа, и вендоров без стенда: администратор загружает вывод команд
(show running-config и т. п.), сервер выполняет по нему те же пробы, что агент с --offline-dir.
Пробы берутся из самого агента (agent/probes.py, OfflineConfigTransport), а не переписываются на
сервере: иначе загрузка через интерфейс и прогон агента могли бы дать разный результат по одной выгрузке.
"""
import functools
import tempfile
from dataclasses import dataclass
from pathlib import Path

from app.services.packs.authoring import load_agent_probes
from app.services.packs.manifest import build_manifest
from app.services.packs.models import Pack, leaf_probes
from app.services.packs.registry import PackRegistry

MAX_FILES = 10
MAX_FILE_BYTES = 5_000_000  # как MAX_OFFLINE_BYTES агента


class OfflineScanError(Exception):
    """Выгрузку нельзя проверить: понятная пользователю причина."""


@functools.cache
def agent_probes():
    return load_agent_probes()


def _commands(probes) -> list[str]:
    commands = []
    for probe in probes:
        for leaf in leaf_probes(probe):
            cmd = getattr(leaf, "cmd", None)
            command = " ".join(cmd) if isinstance(cmd, list) else cmd
            if command and command not in commands:
                commands.append(command)
    return commands


def offline_packs(registry: PackRegistry) -> list[dict]:
    """Паки, которые можно проверить по выгрузке (транспорт ssh), и какие команды им нужны."""
    agent = agent_probes()
    result = []
    for pack in registry.latest("ssh"):
        detect = _commands(rule.probe for rule in pack.detect)
        checks = _commands(check.probe for check in pack.checks)
        result.append({
            "pack": pack.pack, "version": pack.version, "maturity": pack.maturity, "tags": list(pack.tags),
            "asset_type": pack.asset_type,
            "commands": [
                {"command": c, "file": agent.offline_file_name(c), "detect": c in detect, "checks": c in checks}
                for c in detect + [c for c in checks if c not in detect]
            ],
        })
    return result


@dataclass
class OfflineRun:
    packs: list[tuple[Pack, dict]]  # пак и результаты проб {id проверки: результат}
    tags: list[str]
    asset_type: str | None
    collection: dict


def run_offline(registry: PackRegistry, files: dict[str, bytes], declared_pack: str | None) -> OfflineRun:
    """files — {команда: вывод}. Выполняет пробы подошедших паков, как агент с --offline-dir."""
    if not files:
        raise OfflineScanError("не загружено ни одного файла")
    if len(files) > MAX_FILES:
        raise OfflineScanError(f"не больше {MAX_FILES} файлов за раз")
    agent = agent_probes()
    known = {c["command"] for p in offline_packs(registry) for c in p["commands"]}
    for command, data in files.items():
        if command not in known:
            raise OfflineScanError(f"команда {command!r} не используется ни одним паком")
        if len(data) > MAX_FILE_BYTES:
            raise OfflineScanError(f"выгрузка {command!r} больше {MAX_FILE_BYTES} байт")

    packs = registry.latest("ssh")
    if declared_pack and declared_pack not in {p.pack for p in packs}:
        raise OfflineScanError(f"нет пака {declared_pack!r} для сетевых устройств")
    manifests = {p.pack: build_manifest(p) for p in packs}
    candidates = [m for m in manifests.values() if not declared_pack or m["pack"] == declared_pack]

    with tempfile.TemporaryDirectory(prefix="offline-config-") as directory:
        for command, data in files.items():
            (Path(directory) / agent.offline_file_name(command)).write_bytes(data)
        transport = agent.OfflineConfigTransport(directory)
        matched = agent.select_manifests(transport, candidates, declared=declared_pack)
        if not matched:
            if declared_pack:
                raise OfflineScanError(f"выгрузка не похожа на {declared_pack}: проверка платформы (detect) не совпала")
            raise OfflineScanError("платформа по выгрузке не распознана: выберите пак явно или загрузите выгрузку "
                                   "команды распознавания (например, show version)")
        runs = [(pack_by_id, agent.run_manifest(transport, manifests[pack_by_id.pack]))
                for pack_by_id in packs if manifests[pack_by_id.pack] in matched]
        declared = any(not agent.matches_detect(transport, m["detect"]) for m in matched)
        collection = transport.describe()

    tags: list[str] = []
    for pack, _ in runs:
        tags.extend(t for t in pack.tags if t not in tags)
    collection["declared_pack"] = declared
    return OfflineRun(packs=runs, tags=tags, asset_type=next((p.asset_type for p, _ in runs if p.asset_type), None),
                      collection=collection)
