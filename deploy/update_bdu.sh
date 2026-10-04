#!/usr/bin/env bash
# Обновляет локальную копию Банка данных угроз ФСТЭК (БДУ) в работающем hardening_backend:
# скачивает официальную выгрузку и загружает её командой `python -m app.commands.bdu import`.
#
# Сайт ФСТЭК использует сертификат российского удостоверяющего центра, которого нет в системном
# хранилище: цепочка (Russian Trusted Root CA + Sub CA) лежит в deploy/certs и передаётся только
# этому запросу — системное хранилище не меняется. Без заголовка браузера сайт отвечает 403.
#
# Использование: ./deploy/update_bdu.sh [путь-к-уже-скачанному-vulxml.zip]
set -euo pipefail

cd "$(dirname "$0")/.."

CONTAINER="hardening_backend"
URL="https://bdu.fstec.ru/files/documents/vulxml.zip"
UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

if [[ $# -ge 1 ]]; then
  ARCHIVE="$1"
else
  ARCHIVE="$WORK/vulxml.zip"
  echo "==> Скачиваю выгрузку БДУ (~35 МБ)..."
  curl -fsS --retry 3 --cacert deploy/certs/russian-trusted-ca.pem -A "$UA" -o "$ARCHIVE" "$URL"
fi

echo "==> Загружаю в ${CONTAINER} (около минуты)..."
docker cp "$ARCHIVE" "${CONTAINER}:/tmp/vulxml.zip"
docker exec "$CONTAINER" python -m app.commands.bdu import /tmp/vulxml.zip
docker exec "$CONTAINER" rm -f /tmp/vulxml.zip
