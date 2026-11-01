"""Проверка по выгрузке конфигурации, загруженной через интерфейс, — без агента.

Для устройств, к которым нет SSH-доступа, и вендоров без стенда: администратор загружает вывод команд
(show running-config и т. п.), сервер выполняет по нему те же пробы, что агент с --offline-dir.
Пробы берутся из самого агента (agent/probes.py, OfflineConfigTransport), а не переписываются на
сервере: иначе загрузка через интерфейс и прогон агента могли бы дать разный результат по одной выгрузке.
"""
import functools
import tempfile
from dataclasses import dataclass, field
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
        firmware = [pack.firmware.version_probe, pack.firmware.product_probe] if pack.firmware else []
        checks = _commands([check.probe for check in pack.checks] + [p for p in firmware if p is not None])
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
    software: list[dict] = field(default_factory=list)  # модель и версия прошивки (поле firmware пака) — для БДУ


def _continent4():
    """Модуль ЦУС Континент 4. Грузится по пути, как пробы: агент не пакет бэкенда."""
    import importlib.util

    from app.services.packs.authoring import AGENT_DIR

    path = AGENT_DIR / "continent4.py"
    if not path.exists():
        return None
    spec = importlib.util.spec_from_file_location("hardening_agent_continent4", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _finish(agent, packs, manifests, transport, matched) -> OfflineRun:
    runs = [(pack_by_id, agent.run_manifest(transport, manifests[pack_by_id.pack]))
            for pack_by_id in packs if manifests[pack_by_id.pack] in matched]
    declared = any(not agent.matches_detect(transport, manifest["detect"]) for manifest in matched)
    software = []
    for manifest in matched:
        entry = agent.collect_firmware(transport, manifest)
        if entry and entry not in software:
            software.append(entry)
    collection = transport.describe()
    collection["declared_pack"] = declared
    tags: list[str] = []
    for pack, _ in runs:
        tags.extend(tag for tag in pack.tags if tag not in tags)
    return OfflineRun(
        packs=runs, tags=tags, asset_type=next((pack.asset_type for pack, _ in runs if pack.asset_type), None),
        collection=collection, software=software,
    )


def run_offline(registry: PackRegistry, files: dict[str, bytes], declared_pack: str | None) -> OfflineRun:
    """files — {команда: вывод} или JSON выгрузки ЦУС Континент 4. Пробы те же, что у агента с --offline-dir."""
    if not files:
        raise OfflineScanError("не загружено ни одного файла")
    if len(files) > MAX_FILES:
        raise OfflineScanError(f"не больше {MAX_FILES} файлов за раз")
    for command, data in files.items():
        if len(data) > MAX_FILE_BYTES:
            raise OfflineScanError(f"выгрузка {command!r} больше {MAX_FILE_BYTES} байт")

    agent = agent_probes()
    packs = registry.latest("ssh")
    if declared_pack and declared_pack not in {pack.pack for pack in packs}:
        raise OfflineScanError(f"нет пака {declared_pack!r} для сетевых устройств")
    manifests = {pack.pack: build_manifest(pack) for pack in packs}
    candidates = [manifest for manifest in manifests.values() if not declared_pack or manifest["pack"] == declared_pack]

    continent4 = _continent4()
    if continent4 is not None:
        try:
            c4_transport = continent4.Continent4Transport.from_uploads(files)
        except ValueError as exc:
            raise OfflineScanError(str(exc)) from exc
        if c4_transport is not None:
            c4_transport.bind_manifests(candidates)
            matched = agent.select_manifests(c4_transport, candidates, declared=declared_pack)
            if not matched:
                if declared_pack:
                    raise OfflineScanError(
                        f"выгрузка не похожа на {declared_pack}: проверка платформы (detect) не совпала"
                    )
                raise OfflineScanError("JSON не распознан как выгрузка Континент 4")
            return _finish(agent, packs, manifests, c4_transport, matched)

    known = {item["command"] for pack in offline_packs(registry) for item in pack["commands"]}
    for command in files:
        if command not in known:
            raise OfflineScanError(f"команда {command!r} не используется ни одним паком")

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
        return _finish(agent, packs, manifests, transport, matched)
