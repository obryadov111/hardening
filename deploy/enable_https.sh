#!/usr/bin/env bash
# Включение HTTPS для сайта и агентов: сертификат Let's Encrypt для домена и перезапуск фронтенда на 443.
#
#   sudo deploy/enable_https.sh audit.example.ru admin@example.ru     # боевой сертификат
#   sudo deploy/enable_https.sh audit.example.ru admin@example.ru --staging   # пробный (браузеры ему не доверяют)
#
# До запуска: домен указывает (DNS A) на внешний IP, на роутере проброшены TCP 80 и 443 на этот хост.
# Проверка владения доменом — HTTP-01: certbot кладёт файл в /var/lib/hardening-acme, nginx фронтенда
# отдаёт его на http://<домен>/.well-known/acme-challenge/. Если провайдер закрывает входящий 80 —
# нужна DNS-проверка (certbot с плагином регистратора), этот скрипт её не делает.
#
# Ключ сертификата не меняется при продлении (--reuse-key): закреплённый в агентах отпечаток ключа
# (--pin-sha256) остаётся верным. Продление — таймер certbot; после него хук копирует сертификат
# в /etc/hardening-tls (читает nginx, uid 101) и перезагружает nginx.
set -euo pipefail

DOMAIN="${1:-}"
EMAIL="${2:-}"
EXTRA=()
[[ "${3:-}" == "--staging" ]] && EXTRA+=(--staging)

[[ $EUID -eq 0 ]] || { echo "Запускайте от root (sudo)" >&2; exit 1; }
[[ "$DOMAIN" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?\.[a-z0-9-]+$ ]] || { echo "Использование: $0 <домен> <email> [--staging]" >&2; exit 1; }
[[ -n "$EMAIL" ]] || { echo "Нужен email: Let's Encrypt пишет на него о проблемах с продлением" >&2; exit 1; }

REPO="$(cd "$(dirname "$0")/.." && pwd)"
OWNER="${SUDO_USER:-$(stat -c %U "$REPO")}"
TLS_DIR=/etc/hardening-tls
ACME_WEBROOT=/var/lib/hardening-acme
NGINX_UID=101   # пользователь nginx в образе nginx-unprivileged

command -v certbot >/dev/null || { apt-get update -qq && apt-get install -y -qq certbot; }

# 1) каталог проверки домена и фронтенд, который его отдаёт (пока по HTTP)
install -d -m 0755 "$ACME_WEBROOT"
sudo -u "$OWNER" "$REPO/deploy/restart_frontend.sh"

# 2) сертификат: ключ ECDSA P-256, при продлении тот же ключ
certbot certonly --webroot -w "$ACME_WEBROOT" -d "$DOMAIN" \
  --key-type ecdsa --elliptic-curve secp256r1 --reuse-key \
  --email "$EMAIL" --agree-tos --no-eff-email --non-interactive "${EXTRA[@]}"

# 3) хук после выпуска и каждого продления: копия для nginx (0640 root:101) и перезагрузка nginx
HOOK=/etc/letsencrypt/renewal-hooks/deploy/hardening-frontend.sh
cat > "$HOOK" <<HOOK
#!/usr/bin/env bash
# Создан deploy/enable_https.sh (репозиторий hardening): сертификат ${DOMAIN} для nginx фронтенда.
set -euo pipefail
install -d -m 0750 -o root -g ${NGINX_UID} ${TLS_DIR}
install -m 0640 -o root -g ${NGINX_UID} /etc/letsencrypt/live/${DOMAIN}/fullchain.pem ${TLS_DIR}/fullchain.pem
install -m 0640 -o root -g ${NGINX_UID} /etc/letsencrypt/live/${DOMAIN}/privkey.pem ${TLS_DIR}/privkey.pem
docker exec hardening_frontend nginx -s reload 2>/dev/null || true
HOOK
chmod 0755 "$HOOK"
RENEWED_LINEAGE="/etc/letsencrypt/live/$DOMAIN" "$HOOK"

# 4) фронтенд в режиме HTTPS (80 → переадресация, 443 → сайт и агенты)
# Остальные настройки файла (HARDENING_ADMIN_NETWORKS) сохраняются, меняется только строка домена.
ENV_FILE="$REPO/deploy/frontend.env"
touch "$ENV_FILE"
{ grep -v '^HARDENING_DOMAIN=' "$ENV_FILE" || true; printf 'HARDENING_DOMAIN=%s\n' "$DOMAIN"; } > "$ENV_FILE.new"
mv "$ENV_FILE.new" "$ENV_FILE"
chown "$OWNER" "$ENV_FILE"
sudo -u "$OWNER" "$REPO/deploy/restart_frontend.sh"

# 5) межсетевой экран: 443 для агентов и сайта (80 уже открыт)
if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
  ufw allow 443/tcp comment "hardening frontend (nginx, HTTPS)" >/dev/null
fi

PIN=$(openssl x509 -in "$TLS_DIR/fullchain.pem" -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64)
cat <<MSG

HTTPS включён: https://${DOMAIN}
Отпечаток ключа сервера для агентов (HARDENING_PIN_SHA256): sha256//${PIN}
Проверка снаружи (с мобильного интернета): https://${DOMAIN}/health ; оценка TLS — https://www.ssllabs.com/ssltest/
MSG
