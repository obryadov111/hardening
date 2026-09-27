"""Паки, которые генерируются из общего описания, не правятся вручную: YAML в app/packs совпадает с генерацией."""
import importlib.util
from pathlib import Path

import yaml

BACKEND = Path(__file__).resolve().parents[1]


def test_windows_packs_match_their_source(tmp_path):
    spec = importlib.util.spec_from_file_location("windows_packs", BACKEND / "pack_sources" / "windows.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for kind in ("server", "client"):
        committed = (BACKEND / "app" / "packs" / f"windows-{kind}-1.0.0.yaml").read_text(encoding="utf-8")
        generated = module.HEADER[kind] + "\n" + yaml.safe_dump(module.build(kind), allow_unicode=True, sort_keys=False, width=200)
        assert committed == generated, f"windows-{kind}: YAML правили вручную — перегенерируйте из pack_sources/windows.py"


def test_debian_family_packs_match_their_source_and_share_ubuntu_checks():
    """debian-server и astra-linux генерируются из проверок ubuntu-server: совпадают с генерацией, и их
    проверки (проба + утверждение + критичность) те же, что у последней версии ubuntu-server."""
    spec = importlib.util.spec_from_file_location("debian_family", BACKEND / "pack_sources" / "debian_family.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _, ubuntu = module.ubuntu_checks()
    core = lambda checks: [(c["id"], c["probe"], c["assert"], c["severity"]) for c in checks]  # noqa: E731
    for pack_id, meta in module.PACKS.items():
        path = BACKEND / "app" / "packs" / f"{pack_id}-{meta['version']}.yaml"
        committed = path.read_text(encoding="utf-8")
        assert committed == module.render(pack_id), f"{path.name}: правили вручную — перегенерируйте из pack_sources/debian_family.py"
        assert core(yaml.safe_load(committed)["checks"]) == core(ubuntu)
