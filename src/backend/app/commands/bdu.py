"""Банк данных угроз ФСТЭК: загрузка выгрузки и состояние локальной копии.

    python -m app.commands.bdu import /path/vulxml.zip   # заменить копию БДУ целиком
    python -m app.commands.bdu status                    # когда загружено и сколько

Выгрузка — https://bdu.fstec.ru/files/documents/vulxml.zip. Сайт ФСТЭК использует сертификат
российского удостоверяющего центра (Russian Trusted Root CA) и отклоняет запросы без заголовка
браузера; как скачать — README репозитория, раздел про БДУ.
"""
import sys
import time
from pathlib import Path

from app.db.session import SessionLocal
from app.services.bdu.importer import import_bdu
from app.services.bdu.matching import latest_import


def main(argv: list[str]) -> int:
    if len(argv) >= 1 and argv[0] == "status":
        with SessionLocal() as db:
            info = latest_import(db)
        print(info or "БДУ ещё не загружалась")
        return 0
    if len(argv) == 2 and argv[0] == "import":
        path = Path(argv[1])
        if not path.is_file():
            print(f"Файл не найден: {path}")
            return 1
        started = time.monotonic()
        with SessionLocal() as db:
            stats = import_bdu(db, path)
        print(
            f"Загружено уязвимостей: {stats.vulnerabilities}, записей ПО с версиями: {stats.software_rows}, "
            f"пропущено записей ПО без разбираемой версии: {stats.skipped_rows} ({time.monotonic() - started:.0f} с)"
        )
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
