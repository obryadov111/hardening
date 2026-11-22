#!/usr/bin/env python3
"""Собрать печатный справочник из глав docs/how-it-works.

Источник истины — главы. Этот скрипт только склеивает их в одном порядке.
Запуск из корня репозитория:

    python3 docs/how-it-works/assemble_full.py
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "POLNYJ-SPRAVOCHNIK.md"
CHAPTERS = [
    "README.md",
    "00-cheatsheet.md",
    "01-auth.md",
    "02-organizations-hosts.md",
    "03-enrollment-keys.md",
    "04-agent-publish.md",
    "05-agent-install.md",
    "06-agent-modes.md",
    "07-packs.md",
    "08-probes.md",
    "09-network-devices.md",
    "10-manual.md",
    "11-ingest-snapshots.md",
    "12-scoring-fstec.md",
    "13-exceptions.md",
    "14-bdu.md",
    "15-inventory.md",
    "16-reports.md",
    "17-ui.md",
    "18-api.md",
    "19-data-model.md",
    "20-schedulers.md",
    "21-deploy.md",
    "22-scale.md",
    "23-tests-ci.md",
    "24-history-limits.md",
    "25-faq-glossary.md",
    "26-module-map.md",
    "27-worked-examples.md",
    "28-evidence-matrix.md",
    "29-defense-qa.md",
    "30-diploma-show.md",
    "31-diagnostics.md",
    "32-proposed-changes.md",
    "33-proposed-pr23.md",
    "34-operator-files.md",
]

HEADER = """<!-- Сгенерировано docs/how-it-works/assemble_full.py. Не редактировать вручную. -->

# Харденинг. Полный справочник для защиты

Файл собран из глав каталога `docs/how-it-works/` в фиксированном порядке.
Если текст расходится с главой, верна глава: её и нужно править, затем снова
запустить `python3 docs/how-it-works/assemble_full.py`.

Якоря одинаковых заголовков в длинном файле на GitHub могут совпасть.
Для перехода по ссылке открывайте отдельную главу.

"""


def main() -> None:
    parts = [HEADER]
    missing = [name for name in CHAPTERS if not (ROOT / name).is_file()]
    if missing:
        raise SystemExit("нет глав: " + ", ".join(missing))
    for name in CHAPTERS:
        text = (ROOT / name).read_text(encoding="utf-8").rstrip() + "\n"
        parts.append(f"\n\n---\n\n<!-- {name} -->\n\n")
        parts.append(text)
    OUT.write_text("".join(parts), encoding="utf-8")
    print(f"{OUT.name}: {sum(1 for _ in OUT.open(encoding='utf-8'))} строк, глав {len(CHAPTERS)}")


if __name__ == "__main__":
    main()
