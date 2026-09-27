#!/usr/bin/env bash
# Установка агента «Харденинг» как службы systemd на целевой хост (запускать от root).
#   sudo ./install.sh              # экземпляр local (этот хост)
#   sudo ./install.sh sw-core      # ещё один экземпляр (например, сетевое устройство по SSH)
# Повторный запуск безопасен: обновляет код агента и unit-файлы, файл настроек не перезаписывает.
set -euo pipefail

INSTANCE="${1:-local}"
if ! [[ "$INSTANCE" =~ ^[a-z0-9][a-z0-9_-]*$ ]]; then
  echo "Имя экземпляра: строчные латинские буквы, цифры, - и _" >&2; exit 1
fi
[[ $EUID -eq 0 ]] || { echo "Запускайте от root (sudo)" >&2; exit 1; }
command -v python3 >/dev/null || { echo "Нужен python3 (3.9+)" >&2; exit 1; }

SRC="$(cd "$(dirname "$0")/.." && pwd)"   # каталог agent/ репозитория

# 1) отдельный системный пользователь без входа и без домашнего каталога
id hardening-agent >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin hardening-agent

# 2) код агента: принадлежит root, агент его только читает — подменить свой код он не может
install -d -m 0755 -o root -g root /opt/hardening-agent
install -m 0644 -o root -g root "$SRC/collector.py" "$SRC/probes.py" "$SRC/README.md" /opt/hardening-agent/

# 3) настройки: каталог 0750 root:hardening-agent, файл 0640 — читает только агент
install -d -m 0750 -o root -g hardening-agent /etc/hardening-agent
ENV_FILE="/etc/hardening-agent/$INSTANCE.env"
if [[ ! -f "$ENV_FILE" ]]; then
  install -m 0640 -o root -g hardening-agent "$SRC/deploy/agent.env.example" "$ENV_FILE"
  CREATED=1
fi

# 4) unit-файлы
install -m 0644 -o root -g root "$SRC/deploy/hardening-agent@.service" "$SRC/deploy/hardening-agent@.timer" /etc/systemd/system/
systemctl daemon-reload

if [[ -n "${CREATED:-}" ]]; then
  cat <<MSG
Создан $ENV_FILE — заполните адрес сервера и ключи, затем:
  sudo systemctl start hardening-agent@$INSTANCE.service     # пробный прогон
  journalctl -u hardening-agent@$INSTANCE -n 50              # журнал
  sudo systemctl enable --now hardening-agent@$INSTANCE.timer  # расписание
MSG
else
  echo "Обновлено. Настройки $ENV_FILE не менялись."
fi
