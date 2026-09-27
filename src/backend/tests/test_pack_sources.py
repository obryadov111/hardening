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
