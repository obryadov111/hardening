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
# Режим: без домена — HTTP на 80 (локальная сеть, VPN). С доменом — HTTPS: deploy/enable_https.sh получает
# сертификат и записывает HARDENING_DOMAIN в deploy/frontend.env; тогда 80 → 8080 (переадресация на HTTPS
# и проверка Let's Encrypt), 443 → 8443, конфигурация — из deploy/nginx-tls.conf.template.
[[ -f deploy/frontend.env ]] && source deploy/frontend.env
DOMAIN="${HARDENING_DOMAIN:-}"
TLS_DIR="/etc/hardening-tls"           # сертификат для nginx (копия из Let's Encrypt, читает uid 101)
ACME_WEBROOT="/var/lib/hardening-acme" # сюда certbot кладёт файлы проверки домена
# Порт HTTP на хосте: 80 на всех интерфейсах (локально, в LAN и через VPN). Можно переопределить,
# например FRONTEND_PUBLISH=127.0.0.1:80 — только с этого хоста.
PUBLISH="${FRONTEND_PUBLISH:-80}"

MOUNTS=()
PORTS=(-p "${PUBLISH}:8080")
if [[ -d "$ACME_WEBROOT" ]]; then
  MOUNTS+=(-v "${ACME_WEBROOT}:/var/www/acme:ro")
fi
if [[ -n "$DOMAIN" ]]; then
  if ! [[ "$DOMAIN" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ ]]; then
    echo "HARDENING_DOMAIN=${DOMAIN}: ожидается имя домена (латиница, punycode для .рф)" >&2; exit 1
  fi
  # Каталог 0750 root:101 — пользователю его не прочитать, но существует он только после enable_https.sh.
  if [[ ! -d "$TLS_DIR" ]]; then
    echo "Нет ${TLS_DIR} — сначала: sudo deploy/enable_https.sh ${DOMAIN}" >&2; exit 1
  fi
  mkdir -p deploy/generated
  sed "s/__DOMAIN__/${DOMAIN}/g" deploy/nginx-tls.conf.template > deploy/generated/nginx-tls.conf
  chmod 644 deploy/generated/nginx-tls.conf
  MOUNTS+=(-v "$(pwd)/deploy/generated/nginx-tls.conf:/etc/nginx/conf.d/default.conf:ro" -v "${TLS_DIR}:${TLS_DIR}:ro")
  PORTS+=(-p "${FRONTEND_PUBLISH_TLS:-443}:8443")
  echo "==> Режим HTTPS: ${DOMAIN}"
fi

echo "==> Собираю образ ${IMAGE}..."
docker build -t "$IMAGE" -f Dockerfile.frontend .

if docker ps -a --format '{{.Names}}' | grep -qx "$CONTAINER"; then
  echo "==> Останавливаю и удаляю старый контейнер ${CONTAINER}..."
  docker stop "$CONTAINER" >/dev/null
  docker rm "$CONTAINER" >/dev/null
fi

echo "==> Запускаю ${CONTAINER} на default bridge (${PORTS[*]})..."
docker run -d \
  --name "$CONTAINER" \
  --network bridge \
  "${PORTS[@]}" "${MOUNTS[@]}" \
  --restart unless-stopped \
  --memory 128m --cpus 0.5 \
  --read-only --tmpfs /tmp \
  --cap-drop ALL --security-opt no-new-privileges \
  "$IMAGE"

echo "==> Подключаю к ${DB_NETWORK} (резолв hardening_backend по имени)..."
docker network connect "$DB_NETWORK" "$CONTAINER"

echo "==> Готово. Логи: docker logs -f ${CONTAINER}"
