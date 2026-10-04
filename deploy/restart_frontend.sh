#!/usr/bin/env bash
# Пересобирает и перезапускает продакшен-фронтенд hardening_frontend: nginx отдаёт собранное
# React-приложение и проксирует /api и /health в hardening_backend (deploy/nginx.conf).
#
# Запускается как бэкенд в restart_backend.sh: на default bridge ради публикации порта, затем
# подключается к diplom-hardening_default, чтобы разрешать hardening_backend по имени.
#
# Усиление контейнера — под проверки пака docker (ФСТЭК СКО.1.x): не root (uid 101 из образа
# nginx-unprivileged), лимиты памяти и CPU, файловая система только для чтения (запись — только
# во временный /tmp), без capabilities и без повышения привилегий.
set -euo pipefail

cd "$(dirname "$0")/.."

IMAGE="hardening-frontend:latest"
CONTAINER="hardening_frontend"
DB_NETWORK="diplom-hardening_default"
# Порт на хосте: 80 на всех интерфейсах (локально, в LAN и через VPN). Можно переопределить,
# например FRONTEND_PUBLISH=127.0.0.1:80 — только с этого хоста.
PUBLISH="${FRONTEND_PUBLISH:-80}"

echo "==> Собираю образ ${IMAGE}..."
docker build -t "$IMAGE" -f Dockerfile.frontend .

if docker ps -a --format '{{.Names}}' | grep -qx "$CONTAINER"; then
  echo "==> Останавливаю и удаляю старый контейнер ${CONTAINER}..."
  docker stop "$CONTAINER" >/dev/null
  docker rm "$CONTAINER" >/dev/null
fi

echo "==> Запускаю ${CONTAINER} на default bridge (${PUBLISH} -> 8080)..."
docker run -d \
  --name "$CONTAINER" \
  --network bridge \
  -p "${PUBLISH}:8080" \
  --restart unless-stopped \
  --memory 128m --cpus 0.5 \
  --read-only --tmpfs /tmp \
  --cap-drop ALL --security-opt no-new-privileges \
  "$IMAGE"

echo "==> Подключаю к ${DB_NETWORK} (резолв hardening_backend по имени)..."
docker network connect "$DB_NETWORK" "$CONTAINER"

echo "==> Готово. Логи: docker logs -f ${CONTAINER}"
