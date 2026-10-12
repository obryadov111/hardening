#!/usr/bin/env bash
# Публикует агент для скачивания со страницы «Агенты»: https://<домен>/downloads/ (deploy/nginx/app.conf).
#
#   deploy/publish_agent.sh
#
# Собирает:
#   hardening-agent-linux.tar.gz — каталог agent/ (код, установщик, unit-файлы) и инструкция установки;
#   hardening-agent.exe          — из последней успешной сборки workflow «Windows packs» с тем же кодом
#                                  агента (собирается в CI на Windows, нужен gh с доступом к репозиторию);
#   version.json                 — версии, SHA-256, размеры, адрес и отпечаток ключа сервера для настроек агента.
#
# Новая ОС или проверки на существующих пробах — это паки на сервере: агенты получают их сами, публиковать
# агент заново не нужно. Публиковать — когда менялся agent/ (новая проба, исправление агента). Версия —
# дата и коммит последнего изменения agent/. .exe собирается в CI после пуша (~3 мин): если его ещё нет,
# архив для Linux публикуется, а для Windows остаётся прежний — повторите команду после сборки.
set -euo pipefail

cd "$(dirname "$0")/.."
[[ -f deploy/frontend.env ]] && source deploy/frontend.env
OUT=deploy/generated/downloads
WORKFLOW=windows-packs.yml

if [[ -n "$(git status --porcelain -- agent docs/agent-install.md)" ]]; then
  echo "В agent/ или docs/agent-install.md есть незакоммиченные изменения — публикуется только закоммиченное" >&2
  exit 1
fi
AGENT_COMMIT="$(git log -1 --format=%H -- agent)"
VERSION="$(git log -1 --format=%cd --date=format:%Y.%m.%d -- agent)-$(git rev-parse --short "$AGENT_COMMIT")"
mkdir -p "$OUT"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

sha() { sha256sum "$1" | cut -d' ' -f1; }

# --- Linux: архив из коммита (не из рабочего каталога), одинаковый при повторной сборке ---
mkdir -p "$WORK/stage"
git -c tar.umask=022 archive --format=tar --prefix=hardening-agent/ "$AGENT_COMMIT" agent/collector.py agent/probes.py agent/README.md agent/deploy \
  | tar -x -C "$WORK/stage" --strip-components=0
mv "$WORK/stage/hardening-agent/agent/"* "$WORK/stage/hardening-agent/" && rmdir "$WORK/stage/hardening-agent/agent"
git show "HEAD:docs/agent-install.md" > "$WORK/stage/hardening-agent/INSTALL.md"
echo "$VERSION" > "$WORK/stage/hardening-agent/VERSION"
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$(git log -1 --format=%ct "$AGENT_COMMIT")" \
  -C "$WORK/stage" -czf "$WORK/hardening-agent-linux.tar.gz" hardening-agent
# файлы заменяются переименованием внутри каталога: он смонтирован в контейнер nginx, сам каталог менять нельзя
install -m 0644 "$WORK/hardening-agent-linux.tar.gz" "$OUT/.linux.tmp" && mv -f "$OUT/.linux.tmp" "$OUT/hardening-agent-linux.tar.gz"
LINUX_VERSION="$VERSION"
echo "==> Linux: hardening-agent-linux.tar.gz, версия ${LINUX_VERSION}"

# --- Windows: .exe из CI, собранный из того же кода агента ---
WIN_VERSION="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(next((f["version"] for f in d["files"] if f["platform"]=="windows"), ""))' "$OUT/version.json" 2>/dev/null || true)"
RUN_ID=""
if command -v gh >/dev/null; then
  while read -r run sha_; do
    # .exe собран из collector.py и probes.py — правка README или установщика Linux новой сборки не требует
    if git cat-file -e "$sha_" 2>/dev/null && git diff --quiet "$sha_" "$AGENT_COMMIT" -- agent/collector.py agent/probes.py; then RUN_ID="$run"; break; fi
  done < <(gh run list --workflow "$WORKFLOW" --branch main --status success -L 30 --json databaseId,headSha -q '.[] | "\(.databaseId) \(.headSha)"')
fi
if [[ -n "$RUN_ID" ]]; then
  gh run download "$RUN_ID" -n hardening-agent-exe -D "$WORK/win" >/dev/null
  install -m 0644 "$WORK/win/hardening-agent.exe" "$OUT/.exe.tmp" && mv -f "$OUT/.exe.tmp" "$OUT/hardening-agent.exe"
  WIN_VERSION="$VERSION"
  echo "==> Windows: hardening-agent.exe из сборки CI ${RUN_ID}, версия ${WIN_VERSION}"
elif [[ -f "$OUT/hardening-agent.exe" ]]; then
  echo "==> Windows: сборки CI с этим кодом агента ещё нет — оставлен прежний .exe (${WIN_VERSION:-версия неизвестна}); повторите после CI" >&2
else
  echo "==> Windows: сборки CI с этим кодом агента ещё нет — .exe не опубликован; повторите после CI" >&2
fi

# --- отпечаток ключа сервера: агент закрепляет его (HARDENING_PIN_SHA256) ---
PIN=""
if [[ -n "${HARDENING_DOMAIN:-}" ]]; then
  PIN="sha256//$(openssl s_client -connect "${HARDENING_DOMAIN}:443" -servername "$HARDENING_DOMAIN" </dev/null 2>/dev/null \
    | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64)"
fi

python3 - "$OUT" "$LINUX_VERSION" "$WIN_VERSION" "$PIN" "${HARDENING_DOMAIN:+https://${HARDENING_DOMAIN}}" <<'PY'
import hashlib, json, os, sys
from datetime import datetime, timezone
out, linux_version, win_version, pin, server_url = sys.argv[1:6]
files = []
for platform, name, version in (("linux", "hardening-agent-linux.tar.gz", linux_version), ("windows", "hardening-agent.exe", win_version)):
    path = os.path.join(out, name)
    if os.path.exists(path):
        data = open(path, "rb").read()
        files.append({"platform": platform, "name": name, "version": version or None,
                      "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)})
doc = {"published_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "server_url": server_url or None,
       "server_pin": pin or None, "files": files}
tmp = os.path.join(out, ".version.tmp")
with open(tmp, "w") as f:
    json.dump(doc, f, ensure_ascii=False, indent=2)
os.chmod(tmp, 0o644)
os.replace(tmp, os.path.join(out, "version.json"))
PY
echo "==> Опубликовано: ${OUT}/ (https://${HARDENING_DOMAIN:-<домен>}/downloads/), отпечаток сервера: ${PIN:-не определён}"
