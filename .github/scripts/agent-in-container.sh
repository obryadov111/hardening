#!/bin/sh
# Запуск агента (--dry-run) внутри контейнера реальной ОС: типовые серверные пакеты с умолчаниями
# дистрибутива, системный python3, подписанные манифесты из файла. Результат (JSON запроса ingest) — в stdout.
# Используется workflow linux-packs.yml; монтирования: /agent (код агента), /work (manifests.json, key).
PM=$(command -v dnf || command -v yum)
$PM -y -q install openssh-server audit libpwquality firewalld dnf-automatic crypto-policies selinux-policy-targeted python3 >/dev/null 2>&1 \
  || $PM -y -q install openssh-server audit libpwquality python3 >/dev/null 2>&1
echo "python: $(python3 --version 2>&1)" >&2
HARDENING_PACK_KEY="$(cat /work/key)" python3 /agent/collector.py --api-url http://localhost --environment ci \
  --use-packs --dry-run --manifests-file /work/manifests.json 2>/tmp/agent.err
code=$?
if [ $code -ne 0 ]; then echo "агент завершился с кодом $code" >&2; tail -5 /tmp/agent.err >&2; exit $code; fi
