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

from app.services.packs.authoring import AGENT_DIR, load_agent_probes
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
            "single_file": True,
            "single_file_hint": _SINGLE_FILE_HINTS.get(pack.pack, _SINGLE_FILE_HINT),
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


_SINGLE_FILE_HINT = (
    "Один журнал сессии (приглашение hostname# или user@host:~$), бэкап Oxidized/RANCID "
    "или архив файлов из каталога --offline-dir. Если в файле только конфигурация и платформа "
    "по ней узнаётся (например строка version у Cisco IOS), пак выберется сам. Иначе подтвердите его."
)
_SINGLE_FILE_HINTS = {
    "usergate-ngfw": (
        "Журнал CLI (приглашение Admin@узел# или >), архив файлов show_….txt или JSON вида {команда: текст}. "
        "Ответы XML-RPC агент в один файл не складывает — их на этой странице не разобрать."
    ),
    "kontinent-4": (
        "Один JSON export-config-for-cgw или bundle {export, cgw}, архив каталога --offline-dir "
        "либо журнал команд show continent. Версия для БДУ берётся из cgw, если он в том же файле."
    ),
    "qtech-qsw": (
        "Журнал сессии, бэкап или архив. Одного show running-config мало, чтобы отличить Qtech от SNR: подтвердите пак."
    ),
    "snr-switch": (
        "Журнал сессии, бэкап или архив. Одного show running-config мало, чтобы отличить SNR от Qtech: подтвердите пак."
    ),
}


@functools.cache
def offline_split():
    """Общий с агентом разборщик одного файла. Грузится по пути, как пробы."""
    import importlib.util

    path = AGENT_DIR / "offline_split.py"
    if not path.exists():
        raise OfflineScanError("на сервере нет разборщика выгрузки (offline_split.py)")
    spec = importlib.util.spec_from_file_location("hardening_agent_offline_split", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _primary_command(pack: dict) -> str | None:
    checks = [item["command"] for item in pack["commands"] if item["checks"]]
    for name in ("show running-config", "show configuration commands", "show configuration"):
        if name in checks:
            return name
    if checks:
        return checks[0]
    return pack["commands"][0]["command"] if pack["commands"] else None


def _manifests_for_split(packs: list[dict]) -> list[dict]:
    return [
        {"pack": pack["pack"], "detect": [{"probe": {"cmd": item["command"]}} for item in pack["commands"] if item["detect"]]}
        for pack in packs
    ]


def _annotate(run: OfflineRun, split, recognized_by: str | None) -> OfflineRun:
    if recognized_by == "config":
        run.collection["declared_pack"] = False
    run.collection["recognized_by"] = recognized_by or ("declared" if run.collection.get("declared_pack") else "detect")
    run.collection["bundle_format"] = split.kind
    return run


def split_bundle(registry: PackRegistry, raw: bytes, filename: str, declared_pack: str | None):
    """Один файл → разбор. declared_pack задаёт, куда положить безымянный текст, если пак уже выбран."""
    splitter = offline_split()
    packs = offline_packs(registry)
    commands: list[str] = []
    by_pack = {}
    for pack in packs:
        by_pack[pack["pack"]] = pack
        for item in pack["commands"]:
            if item["command"] not in commands:
                commands.append(item["command"])
    fallback = _primary_command(by_pack[declared_pack]) if declared_pack and declared_pack in by_pack else None
    try:
        return splitter.split_bytes(raw, commands, filename=filename or "", fallback_command=fallback)
    except splitter.SplitError as exc:
        raise OfflineScanError(str(exc)) from exc


def run_offline_bundle(registry: PackRegistry, raw: bytes, filename: str, declared_pack: str | None) -> OfflineRun:
    """Один файл выгрузки: журнал, бэкап, конфигурация, архив или JSON. Пробы те же, что у набора файлов."""
    split = split_bundle(registry, raw, filename, declared_pack)
    if split.mode == "json":
        # На сервере continent4.py грузит свой экземпляр probes.py. Ошибка «это не команда ЦУС»
        # не является ProbeError того модуля, которым select_manifests ловит промахи detect.
        # Поэтому кандидатов сразу сужаем до kontinent-4: файл уже узнан как JSON ЦУС.
        if _continent4() is None:
            raise OfflineScanError("JSON Континент 4 на этом сервере не разбирается")
        if not split.files:
            raise OfflineScanError("в файле не найдено выводов команд")
        if declared_pack and declared_pack != "kontinent-4":
            raise OfflineScanError(f"по файлу это JSON Континент 4, а не {declared_pack}")
        run = run_offline(registry, split.files, declared_pack or "kontinent-4")
        return _annotate(run, split, "detect" if not run.collection.get("declared_pack") else "declared")
    if not split.files:
        raise OfflineScanError("в файле не найдено выводов команд")
    packs = offline_packs(registry)
    try:
        effective, recognized_by = offline_split().choose_declared(split, declared_pack, _manifests_for_split(packs))
    except offline_split().SplitError as exc:
        raise OfflineScanError(str(exc)) from exc
    run = run_offline(registry, split.files, effective)
    return _annotate(run, split, recognized_by)


def preview_bundle(registry: PackRegistry, raw: bytes, filename: str, declared_pack: str | None) -> dict:
    """Что узнали в файле, без записи снимка. Неузнанная платформа — не ошибка, а просьба подтвердить пак."""
    split = split_bundle(registry, raw, filename, declared_pack)
    packs = offline_packs(registry)
    try:
        run = run_offline_bundle(registry, raw, filename, declared_pack)
    except OfflineScanError as exc:
        text = str(exc)
        if "не распознана" not in text and "выберите пак" not in text:
            raise
        return _preview(split, packs, None, declared_pack, text)
    pack_id = run.packs[0][0].pack if run.packs else None
    return _preview(split, packs, pack_id, declared_pack, None, run.collection.get("recognized_by"))


def _preview(split, packs, pack_id, declared_pack, error, recognized_by=None) -> dict:
    info = next((pack for pack in packs if pack["pack"] == pack_id), None)
    if info is None and declared_pack:
        info = next((pack for pack in packs if pack["pack"] == declared_pack), None)
    found = list(split.found)
    missing = []
    rows = []
    if info is not None:
        if split.mode == "json":
            found = [item["command"] for item in info["commands"]]
        for item in info["commands"]:
            present = item["command"] in found or item["command"] in split.files
            rows.append({**item, "found": present})
            if not present:
                missing.append(item["command"])
    needs = recognized_by == "declared" or (pack_id is None and error is not None)
    return {
        "format": split.kind,
        "format_label": split.label(),
        "pack": pack_id,
        "recognized_by": recognized_by,
        "needs_declared": bool(needs),
        "found": found,
        "missing": missing,
        "commands": rows,
        "ambiguous_packs": list(split.ambiguous_packs),
        "notes": list(split.notes) + ([error] if error else []),
    }
