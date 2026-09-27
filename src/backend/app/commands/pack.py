"""Инструменты автора пака.

    python -m app.commands.pack validate [каталог паков]        # по умолчанию app/packs
    python -m app.commands.pack test [фикстура.yaml ...]        # по умолчанию все pack_tests/*.yaml

Код выхода 1 — есть ошибки валидации или несовпадения в фикстурах; предупреждения на код не влияют.
Формат фикстур — pack_tests/README.md.
"""
import argparse
import sys
from pathlib import Path

from app.services.packs.authoring import (
    FIXTURES_DIR,
    PACKS_DIR,
    load_agent_probes,
    run_fixture,
    validate_directory,
)
from app.services.packs.registry import PackError, load_registry


def cmd_validate(args) -> int:
    findings = validate_directory(Path(args.directory))
    for finding in findings:
        print(finding)
    errors = sum(f.level == "error" for f in findings)
    warnings = len(findings) - errors
    print(f"\nОшибок: {errors}, предупреждений: {warnings}")
    return 1 if errors else 0


def cmd_test(args) -> int:
    paths = [Path(p) for p in args.fixtures] or sorted(FIXTURES_DIR.glob("*.yaml"))
    if not paths:
        print(f"Нет фикстур в {FIXTURES_DIR}")
        return 1
    registry, agent = load_registry(Path(args.packs)), load_agent_probes()
    failed = 0
    for path in paths:
        try:
            result = run_fixture(path, registry, agent)
        except PackError as exc:
            print(f"✗ {exc}")
            failed += 1
            continue
        passed = sum(case.ok for case in result.cases)
        print(f"{'✓' if result.ok else '✗'} {result.fixture}: {result.pack} {result.version} — сценариев {passed}/{len(result.cases)}")
        for case in result.cases:
            for problem in case.problems:
                print(f"    {case.name}: {problem}")
        if result.uncovered:
            print(f"    не показано и нарушение, и соблюдение: {', '.join(result.uncovered)}")
        failed += not result.ok
    return 1 if failed else 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.commands.pack", description="Инструменты автора пака")
    sub = parser.add_subparsers(dest="command", required=True)
    validate = sub.add_parser("validate", help="проверить паки: схема, белый список агента, refs, версии")
    validate.add_argument("directory", nargs="?", default=str(PACKS_DIR))
    validate.set_defaults(func=cmd_validate)
    test = sub.add_parser("test", help="прогнать паки на образцах (фикстурах) без живого хоста")
    test.add_argument("fixtures", nargs="*")
    test.add_argument("--packs", default=str(PACKS_DIR), help="каталог паков")
    test.set_defaults(func=cmd_test)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
