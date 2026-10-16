"""Сетевые паки распознают платформу взаимоисключающе: вывод команд одного устройства подходит ровно одному паку.

Иначе к устройству применятся два пака с чужими проверками. Так было с криптошлюзом С-Терра: его show version
эмулирует Cisco IOS, и пак cisco-ios до 1.3.0 принимал шлюз за Cisco. Образцы — base и сценарии с detect: true
из pack_tests/ всех ssh-паков: каждый такой вывод прогоняется через detect ВСЕХ ssh-паков сразу."""
import pytest
import yaml

from app.services.packs.authoring import (
    AGENT_DIR,
    FIXTURES_DIR,
    PACKS_DIR,
    FixtureHost,
    _merge,
    load_agent_probes,
)
from app.services.packs.manifest import build_manifest
from app.services.packs.registry import load_registry

if not (AGENT_DIR / "probes.py").exists():
    pytest.skip("каталог agent/ недоступен (тесты запущены вне репозитория)", allow_module_level=True)

AGENT = load_agent_probes()
REGISTRY = load_registry(PACKS_DIR)
SSH_MANIFESTS = [build_manifest(p) for p in REGISTRY.latest("ssh")]
SSH_PACKS = {m["pack"] for m in SSH_MANIFESTS}


def _samples():
    for path in sorted(FIXTURES_DIR.glob("*.yaml")):
        spec = yaml.safe_load(path.read_text(encoding="utf-8"))
        if spec.get("pack") not in SSH_PACKS:
            continue
        base = spec.get("base") or {}
        yield pytest.param(spec["pack"], _merge(base, {}), id=f"{spec['pack']}:base")
        for case in spec["cases"]:
            if case.get("detect") is True:
                yield pytest.param(spec["pack"], _merge(base, case), id=f"{spec['pack']}:{case['name'][:40]}")


@pytest.mark.parametrize("pack, sources", list(_samples()))
def test_device_output_is_recognised_by_exactly_one_pack(pack, sources):
    host = FixtureHost(AGENT, "ssh", **sources)
    matched = sorted(m["pack"] for m in AGENT.select_manifests(host, SSH_MANIFESTS))
    assert matched == [pack]


def test_russian_network_vendors_are_covered():
    expected = {"eltex-esr", "eltex-mes", "qtech-qsw", "snr-switch", "vipnet-coordinator", "s-terra-gate"}
    assert expected <= SSH_PACKS
