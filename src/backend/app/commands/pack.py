"""Инструменты автора пака.

    python -m app.commands.pack validate [каталог паков]        # по умолчанию app/packs
    python -m app.commands.pack test [фикстура.yaml ...]        # по умолчанию все pack_tests/*.yaml
    python -m app.commands.pack live [--pack id ...] [--json файл] [--require-found]
                                                                # паки на ЭТОЙ машине настоящими пробами
    python -m app.commands.pack manifests --key-file файл --out файл [--transport local]
                                                                # подписанные манифесты для --manifests-file агента
    python -m app.commands.pack evaluate результат.json --pack id [--allow-error check_id ...]
                                                                # оценка сохранённого прогона агента (--dry-run)

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
    run_live,
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


def cmd_live(args) -> int:
    """Код 1 при --require-found, если распознанный (или явно названный) пак не выполнил хотя бы одну пробу
    или если явно названный пак не распознал платформу."""
    import json
    from dataclasses import asdict

    results = run_live(load_registry(Path(args.packs)), args.pack or None)
    failed = False
    for pack in results:
        print(f"{'✓' if pack.detected else '·'} {pack.pack} {pack.version}: {'платформа распознана' if pack.detected else 'не распознана'}")
        for check in pack.checks:
            shown = check.error or f"значение {check.value!r}"
            print(f"    {check.status:5} {check.check_id}: {shown}"[:200])
        if pack.checks:
            counts = {s: sum(c.status == s for c in pack.checks) for s in ("pass", "fail", "error")}
            print(f"    итого: соблюдено {counts['pass']}, нарушено {counts['fail']}, не проверено {counts['error']}")
        if args.require_found and args.pack and (not pack.detected or pack.not_executed):
            failed = True
    if args.json:
        Path(args.json).write_text(json.dumps([asdict(p) for p in results], ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    return 1 if failed else 0


def cmd_manifests(args) -> int:
    """Подписанные манифесты последних версий паков — в формате ответа GET /api/agent/manifests. Для агента
    без связи с сервером (--manifests-file) и для проверки собранного агента в CI. Ключ читается из файла,
    а не из аргумента, — чтобы не остаться в истории shell и в списке процессов."""
    import json

    from app.services.packs.manifest import build_manifest, sign_manifest

    key = Path(args.key_file).read_text(encoding="utf-8").strip()
    if not key:
        print("Пустой ключ подписи", file=sys.stderr)
        return 1
    packs = load_registry(Path(args.packs)).latest(args.transport)
    response = {"manifests": [{"manifest": m, "signature": sign_manifest(m, key)} for m in (build_manifest(p) for p in packs)]}
    Path(args.out).write_text(json.dumps(response, ensure_ascii=False), encoding="utf-8")
    print(f"{len(packs)} манифестов ({', '.join(p.pack for p in packs)}) -> {args.out}")
    return 0


def cmd_evaluate(args) -> int:
    """Результат агента (--dry-run, JSON запроса ingest) — через оценку сервера. Код 1, если пак не был
    выполнен агентом (платформа не распознана) или проба не выполнилась у проверки не из --allow-error.
    Для проверки паков на реальных ОС, где агент запускается отдельно (контейнеры, CI)."""
    import json
    from types import SimpleNamespace

    from app.services.packs.evaluate import evaluate_pack

    payload = json.loads(Path(args.payload).read_text(encoding="utf-8"))
    runs = {run["id"]: run for run in payload.get("packs", [])}
    os_name = (payload.get("asset") or {}).get("os")
    if args.pack not in runs:
        print(f"✗ {args.payload}: пак {args.pack} не выполнен (распознаны: {', '.join(runs) or 'нет'}; ОС: {os_name})")
        return 1
    run = runs[args.pack]
    pack = load_registry(Path(args.packs)).get(args.pack, run["version"])
    results = evaluate_pack(pack, {k: SimpleNamespace(**v) for k, v in run["probe_results"].items()})
    unexpected = [r for r in results if r.status == "error" and r.check_id not in (args.allow_error or [])]
    counts = {s: sum(r.status == s for r in results) for s in ("pass", "fail", "error")}
    mark = "✗" if unexpected else "✓"
    print(f"{mark} {os_name}: {pack.pack} {pack.version} — соблюдено {counts['pass']}, нарушено {counts['fail']}, не проверено {counts['error']}")
    for r in unexpected:
        print(f"    не выполнилась: {r.check_id} — {run['probe_results'].get(r.check_id, {}).get('error')}")
    return 1 if unexpected else 0


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
    live = sub.add_parser("live", help="прогнать паки на этой машине настоящими пробами агента (только чтение)")
    live.add_argument("--pack", action="append", help="только этот пак (можно несколько); иначе все распознанные")
    live.add_argument("--json", help="сохранить результат в файл (образцы с реальной ОС)")
    live.add_argument("--require-found", action="store_true", help="код 1, если названный пак не распознан или проба не выполнилась")
    live.add_argument("--packs", default=str(PACKS_DIR), help="каталог паков")
    live.set_defaults(func=cmd_live)
    manifests = sub.add_parser("manifests", help="выгрузить подписанные манифесты (формат /api/agent/manifests)")
    manifests.add_argument("--key-file", required=True, help="файл с ключом подписи (PACK_SIGNING_KEY)")
    manifests.add_argument("--out", required=True)
    manifests.add_argument("--transport", default="local", choices=["local", "ssh"])
    manifests.add_argument("--packs", default=str(PACKS_DIR), help="каталог паков")
    manifests.set_defaults(func=cmd_manifests)
    evaluate = sub.add_parser("evaluate", help="оценить сохранённый прогон агента (--dry-run) логикой сервера")
    evaluate.add_argument("payload")
    evaluate.add_argument("--pack", required=True)
    evaluate.add_argument("--allow-error", action="append", help="проверка, которой разрешено «не проверено» (можно несколько)")
    evaluate.add_argument("--packs", default=str(PACKS_DIR), help="каталог паков")
    evaluate.set_defaults(func=cmd_evaluate)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
