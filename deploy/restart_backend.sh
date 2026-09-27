#!/usr/bin/env bash
# Пересобирает и перезапускает hardening_backend вручную.
#
# Почему не просто `docker compose up`: файрвол этого хоста режет новые
# входящие соединения на кастомных docker-бриджах и разрешает свежий
# host-port-forward только на дефолтном bridge-network. Compose не умеет
# подключить сервис к безымянному "bridge" (ему всегда нужен network-scoped
# alias, а Docker их на default bridge не даёт), поэтому контейнер поднимается
# руками: сначала на bridge — ради публикации порта 8000, — затем
# подключается к diplom-hardening_default, чтобы резолвить diploma_db по
# имени. См. комментарий в docker-compose.yml.
#
# Как только firewall-правило будет исправлено, этот скрипт станет не нужен —
# используй `docker compose up -d` из docker-compose.yml.
set -euo pipefail

cd "$(dirname "$0")/.."

IMAGE="volkodav-backend:latest"
CONTAINER="hardening_backend"
DB_NETWORK="diplom-hardening_default"

echo "==> Собираю образ ${IMAGE}..."
docker build -t "$IMAGE" ./src/backend

if docker ps -a --format '{{.Names}}' | grep -qx "$CONTAINER"; then
  echo "==> Останавливаю и удаляю старый контейнер ${CONTAINER}..."
  docker stop "$CONTAINER" >/dev/null
  docker rm "$CONTAINER" >/dev/null
fi

# Лимиты ресурсов: проверки docker.memory_limit_set / docker.cpu_limit_set (ФСТЭК СКО.1.5).
# Обычное потребление — около 100 МБ; 1 ГБ с запасом покрывает выгрузку PDF/Excel.
echo "==> Запускаю ${CONTAINER} на default bridge (для host-port-forward)..."
docker run -d \
  --name "$CONTAINER" \
  --network bridge \
  -p 8000:8000 \
  --env-file ./src/backend/.env \
  --restart unless-stopped \
  --memory 1g --cpus 2 \
  "$IMAGE"

echo "==> Подключаю к ${DB_NETWORK} (резолв diploma_db по имени)..."
docker network connect "$DB_NETWORK" "$CONTAINER"

echo "==> Готово. Логи: docker logs -f ${CONTAINER}"
