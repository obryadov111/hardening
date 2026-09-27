# Агент-сборщик

Скрипт `collector.py` собирает факты о конфигурации Linux-хоста (SSH, firewall,
автообновления, парольная политика, ядро, Docker) и список установленного ПО,
затем отправляет их на бэкенд (`POST /api/ingest`). Дальше движок сравнения
(`app/services/hardening_engine.py`) сверяет факты с `hardening_rules` и
пересчитывает `compliance_score`.

Зависимостей нет — только стандартная библиотека Python **3.6+**: системный python3 старых
дистрибутивов (RHEL 8 / Rocky 8 — 3.6, РЕД ОС 7.3 — 3.8, RHEL 9 — 3.9). Совместимость проверяет CI
(тесты агента на Rocky Linux 8). Поэтому в коде агента аннотации вида `str | None` — в кавычках, а
subprocess.run — без capture_output/text: иначе агент не запускается на RHEL 8/9 (так и было до 2026-09-27).
Копируется на целевой хост как один файл.

## Выдача ключа агента

На бэкенде для организации нужен ключ агента (хранится в БД только его хэш):

```bash
python -m app.commands.create_agent_key
```

## Запуск на целевом хосте

```bash
python3 collector.py \
  --api-url https://hardening.example.com \
  --environment prod \
  --criticality high \
  --scan-label "плановый прогон"
```

Ключ передаётся через переменную окружения (не остаётся в истории shell):

```bash
export HARDENING_AGENT_API_KEY=<ключ>
python3 collector.py --api-url https://hardening.example.com --environment prod
```

Проверить, что соберётся, без реальной отправки:

```bash
python3 collector.py --api-url http://localhost:8000 --environment prod --dry-run
```

## Что собирается

| Категория | Источник |
|---|---|
| `ssh.*` | `/etc/ssh/sshd_config` |
| `firewall.*` | `ufw status verbose`, `/etc/ufw/ufw.conf`, `/etc/default/ufw` |
| `updates.*` | `/etc/apt/apt.conf.d/20auto-upgrades` |
| `password_policy.*` | `/etc/login.defs`, `/etc/security/pwquality.conf`, `/etc/pam.d/common-auth` |
| `kernel.*` | `/proc/sys/net/ipv4/ip_forward` |
| `docker.*` | `docker ps` + `docker inspect` (если Docker установлен) |
| ПО | `dpkg-query` (Debian/Ubuntu), фолбэк на `rpm -qa` |

Правило, для которого агент не прислал факт (например `postgres.ssl_enabled`
на хосте без PostgreSQL), получает статус `error`, а не `fail` — движок
не считает отсутствие данных нарушением.


## Режим паков (`--use-packs`)

Вместо встроенных проверок агент собирает данные по **пакам платформ** — YAML-описаниям,
которые ведутся на сервере (`src/backend/app/packs/`). Добавление платформы или проверки
не требует нового релиза агента. Работает рядом с `probes.py` (движок проб; обычный режим
по-прежнему один файл `collector.py`).

Как это работает:

1. Агент запрашивает `GET /api/agent/manifests` — подписанные манифесты актуальных версий паков.
2. Проверяет подпись (HMAC-SHA256, ключ `HARDENING_PACK_KEY`). Подделка — остановка с кодом ошибки.
3. По условиям `detect` определяет, какие паки подходят платформе. Не распознана — ничего не отправляется.
   Подходит несколько (например, ОС + Docker + Samba) — выполняются все, одним прогоном и одним
   запросом; `--pack <id>` ограничивает прогон одним паком.
4. Выполняет пробы подошедших паков (только чтение) и отправляет их `probe_results` в `POST /api/ingest`.
   Сравнение с нормой (`assert`) делает сервер.

```bash
export HARDENING_AGENT_API_KEY=<ключ агента>
export HARDENING_PACK_KEY=<ключ проверки подписи; отдельный от ключа агента>
python3 collector.py --api-url https://hardening.example.com --environment prod --use-packs
```

Внешний сбор с сетевого устройства по SSH (с джамп-хоста; учётка на устройстве — только на чтение):

```bash
python3 collector.py --api-url https://hardening.example.com --environment net --use-packs \
  --ssh-host 10.0.0.1 --ssh-user audit --ssh-key ~/.ssh/audit_ed25519
```

Устройство должно быть в `known_hosts`: проверка ключа хоста включена и не отключается.

Что агент **не** делает, даже если так написано в подписанном манифесте: не запускает команды вне
белого списка (`LOCAL_COMMAND_POLICY`), не использует shell, не читает секреты (`/etc/shadow`,
приватные ключи и т. п. — для прав файла есть проба `file_stat`), не выполняет по SSH ничего,
кроме команд на чтение. В свидетельстве проверки секреты (хэши паролей, SNMP-community) маскируются.
Каждая выполненная проба пишется в журнал (stderr).

Проверить без отправки: `--dry-run` (можно с `--manifests-file` — манифесты из файла).

Ограничения текущей версии: текущее состояние актива (`hardening_checks`) перезаписывается целиком
каждым прогоном — паки, не подошедшие в этот раз, из него выпадают (история остаётся в снимках);
ключ подписи симметричный — см. `probes.py`.

## Семейство RHEL (пак `rhel-family`)

RHEL, Rocky Linux, AlmaLinux, Oracle Linux, CentOS Stream, **РЕД ОС 7.3 и 8** — один пак: распознаётся по
`ID_LIKE` (rhel/fedora). Агент тот же, запускается системным python3. Проверено: агент выполнен в контейнерах
официальных образов всех семи систем (workflow **Linux packs**), файловые пробы работают на настоящих файлах
ОС; пробы служб в контейнере без systemd — «не проверено» по построению.

## Windows (паки `windows-server`, `windows-client`)

На Windows-хостах нет Python, поэтому агент собирается в один файл `hardening-agent.exe` (PyInstaller) —
тот же `collector.py` + `probes.py`, только стандартная библиотека (реестр — модуль `winreg`). Готовый
файл — артефакт `hardening-agent-exe` каждого прогона workflow **Windows packs** в GitHub Actions; собрать
самому:

```powershell
pip install pyinstaller==6.11.1
pyinstaller --onefile --name hardening-agent --paths agent --hidden-import probes agent/collector.py
```

Запуск — только в режиме паков, **от имени администратора или SYSTEM**: `secedit` (политика паролей и
блокировки) и `auditpol` (политика аудита) без этих прав недоступны — такие проверки получают
«не проверено», а не «соблюдено».

```powershell
$env:HARDENING_AGENT_API_KEY = '<ключ агента>'
$env:HARDENING_PACK_KEY = '<ключ проверки подписи>'
.\hardening-agent.exe --api-url https://hardening.example.com --environment prod --use-packs
```

По расписанию — задача планировщика от SYSTEM (ключи — в переменных среды системы, доступных только
администраторам, а не в командной строке задачи):

```powershell
schtasks /Create /TN "Hardening agent" /RU SYSTEM /SC DAILY /ST 03:00 /RL HIGHEST `
  /TR "C:\Program Files\Hardening\hardening-agent.exe --api-url https://hardening.example.com --environment prod --use-packs"
```

Что читает агент на Windows и почему не `net accounts` / `netsh` / `auditpol /get`: на русской Windows их
вывод русский, разбор ломается. Источники, не зависящие от языка:

| Проба | Источник | Права |
|---|---|---|
| `reg_value` | реестр, только `HKLM`; кусты `SAM` и `SECURITY` (хэши паролей, секреты LSA) запрещены | пользователь |
| `win_secpol` | `secedit /export` — ключи вида `MinimumPasswordLength` | администратор |
| `win_auditpol` | `auditpol /backup` — GUID подкатегорий и числа 0–3 | администратор |
| `service_state` | `sc query` (состояние — число и константа) и `Start` службы в реестре | пользователь |

`secedit` и `auditpol` пишут результат во временный файл в новом временном каталоге агента — он читается
и сразу удаляется; системная конфигурация не меняется. Пустой экспорт — «не проверено», а не «не задано».

Проверено на **настоящих** Windows Server 2022 и 2025 (CI, `.github/workflows/windows-packs.yml`): все пробы
выполняются, распознавание верное, собранный `.exe` работает по подписанным манифестам и отказывает при
неверном ключе подписи. Windows 10/11 в CI нет — пак `windows-client` в статусе `draft`.

## Установка как служба systemd (`deploy/`)

Регулярный прогон по расписанию — шаблон `hardening-agent@.service` + таймер. Экземпляр = файл
настроек: `@local` — этот хост, `@<имя>` — ещё один источник (например, сетевое устройство по SSH).

```bash
sudo ./deploy/install.sh            # экземпляр local
sudoedit /etc/hardening-agent/local.env                 # адрес сервера и ключи (образец — deploy/agent.env.example)
sudo systemctl start hardening-agent@local.service      # пробный прогон
journalctl -u hardening-agent@local -n 50               # журнал: какие пробы, сколько заняли
sudo systemctl enable --now hardening-agent@local.timer # раз в сутки, случайная задержка до часа
```

Что делает `install.sh` (повторный запуск безопасен, настройки не перезаписывает):

| Что | Где | Права |
|---|---|---|
| Системный пользователь без входа | `hardening-agent` | — |
| Код агента (агент его только читает — подменить свой код не может) | `/opt/hardening-agent/` | root, 0644 |
| Настройки с ключами | `/etc/hardening-agent/<экземпляр>.env` | root:hardening-agent, 0640 |
| Unit-файлы | `/etc/systemd/system/` | root, 0644 |

Служба запускается от непривилегированного `hardening-agent` с ужесточением systemd: файловая
система только для чтения (`ProtectSystem=strict`), без повышения привилегий и capabilities, без
доступа к устройствам, модулям ядра, часам. Агенту этого достаточно: он только читает.

Где не хватает прав, агент не притворяется:

- `ufw status` требует root — состояние берётся из `/etc/ufw/ufw.conf` и `/etc/default/ufw`;
- **Docker**: сокет доступен только группе `docker`, а она фактически равна root (через Docker
  можно смонтировать корень хоста). Поэтому по умолчанию агент в неё **не** добавляется, и проверки
  Docker получают «не проверено». Нужны проверки Docker — осознанно:
  `sudo usermod -aG docker hardening-agent`.

Проверено 2026-09-27: `systemd-analyze verify` для шаблона и экземпляра; прогон `collector.py` в
песочнице с теми же ограничениями (`systemd-run --user`) — манифесты, подпись, распознавание
`ubuntu-server` и `docker`, все 20 проб, ingest на тестовый сервер. Установка `install.sh` на
боевом хосте не выполнялась.

Тесты агента: `pytest agent/tests`.
