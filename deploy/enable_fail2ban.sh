#!/usr/bin/env bash
# fail2ban для сайта: блокирует адрес после 10 неудачных входов за 10 минут (неверный пароль или код 2FA),
# на 1 час, повторно — дольше (до недели). Фильтр и jail — deploy/fail2ban/.
#
#   sudo deploy/enable_fail2ban.sh
#
# Без блокировки — сети компании и внешний адрес NAT офиса (HARDENING_FAIL2BAN_IGNOREIP в deploy/frontend.env,
# через пробел): иначе сотрудник, ошибившийся паролем, заблокировал бы всех коллег за тем же NAT.
# Журнал nginx берётся из systemd-journal: deploy/restart_frontend.sh запускает фронтенд с --log-driver journald.
#
# Проверка: fail2ban-client status hardening-login ; снять блокировку: fail2ban-client unban <IP>
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "Запускайте от root (sudo)" >&2; exit 1; }
REPO="$(cd "$(dirname "$0")/.." && pwd)"
[[ -f "$REPO/deploy/frontend.env" ]] && source "$REPO/deploy/frontend.env"
IGNOREIP="${HARDENING_FAIL2BAN_IGNOREIP:-}"
for net in $IGNOREIP; do
  [[ "$net" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$ || "$net" =~ ^[0-9a-fA-F:]+(/[0-9]{1,3})?$ ]] \
    || { echo "HARDENING_FAIL2BAN_IGNOREIP: «${net}» — не адрес и не подсеть" >&2; exit 1; }
done

command -v fail2ban-client >/dev/null || { apt-get update -qq && apt-get install -y -qq fail2ban python3-systemd; }

install -m 0644 "$REPO/deploy/fail2ban/hardening-login.filter.conf" /etc/fail2ban/filter.d/hardening-login.conf
sed "s#__IGNOREIP__#${IGNOREIP}#" "$REPO/deploy/fail2ban/hardening-login.jail.conf" > /etc/fail2ban/jail.d/hardening-login.conf
chmod 0644 /etc/fail2ban/jail.d/hardening-login.conf

# Цепочку DOCKER-USER создаёт Docker: fail2ban, запущенный раньше него, не смог бы включить jail.
install -d -m 0755 /etc/systemd/system/fail2ban.service.d
printf '[Unit]\nAfter=docker.service\nWants=docker.service\n' > /etc/systemd/system/fail2ban.service.d/after-docker.conf
systemctl daemon-reload
systemctl enable --now fail2ban >/dev/null
fail2ban-client reload >/dev/null
fail2ban-client status hardening-login
