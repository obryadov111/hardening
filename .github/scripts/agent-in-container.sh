#!/bin/sh
# Запуск агента (--dry-run) внутри контейнера реальной ОС: типовые серверные пакеты с умолчаниями
# дистрибутива, системный python3, подписанные манифесты из файла. Результат (JSON запроса ingest) — в stdout.
# Используется workflow linux-packs.yml; монтирования: /agent (код агента), /work (manifests.json, key).
export DEBIAN_FRONTEND=noninteractive
. /etc/os-release
if [ "$ID" = altlinux ]; then
  # Альт: apt-get поверх RPM (apt-rpm), dpkg нет
  apt-get update -qq >/tmp/install.log 2>&1
  for pkg in python3 openssh-server audit; do
    apt-get install -y -qq "$pkg" >>/tmp/install.log 2>&1 || echo "не установлен: $pkg" >&2
  done
elif command -v apt-get >/dev/null && [ -d /etc/apt/apt.conf.d ] && command -v dpkg >/dev/null; then
  # Debian, Ubuntu, Astra: пакеты по одному — отсутствие одного (например, unattended-upgrades) не должно
  # оставить хост без python3
  if [ "$ID" = debian ] && [ "$VERSION_CODENAME" = bullseye ]; then
    # Debian 11: поддержка (LTS) закончилась в 2026 г., пакеты на deb.debian.org частично удалены (404) —
    # только для установки тестовых пакетов берётся архив. Агента и проверяемые файлы ОС это не меняет.
    echo "deb http://archive.debian.org/debian bullseye main" > /etc/apt/sources.list
    APT_OPTS="-o Acquire::Check-Valid-Until=false"
  fi
  apt-get $APT_OPTS update -qq >/tmp/install.log 2>&1
  for pkg in python3 openssh-server auditd libpam-pwquality ufw unattended-upgrades; do
    apt-get $APT_OPTS install -y -qq --no-install-recommends "$pkg" >>/tmp/install.log 2>&1 || echo "не установлен: $pkg" >&2
  done
else
  PM=$(command -v dnf || command -v yum)
  $PM -y -q install openssh-server audit libpwquality firewalld dnf-automatic crypto-policies selinux-policy-targeted python3 >/tmp/install.log 2>&1 \
    || $PM -y -q install openssh-server audit libpwquality python3 >>/tmp/install.log 2>&1
fi
command -v python3 >/dev/null || { echo "python3 не установлен:" >&2; tail -5 /tmp/install.log >&2; exit 1; }
echo "python: $(python3 --version 2>&1)" >&2
HARDENING_PACK_KEY="$(cat /work/key)" python3 /agent/collector.py --api-url http://localhost --environment ci \
  --use-packs --dry-run --manifests-file /work/manifests.json 2>/tmp/agent.err
code=$?
if [ $code -ne 0 ]; then echo "агент завершился с кодом $code" >&2; tail -5 /tmp/agent.err >&2; exit $code; fi
