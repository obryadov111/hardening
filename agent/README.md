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

Ключ — на каждый объект заказчика: интерфейс, страница «Агенты» → «Новый ключ» (срок действия, отзыв,
время и адрес последнего обращения; показывается один раз, в БД — только хэш). Там же открытый ключ
подписи паков и готовый файл настроек. Без интерфейса — `python -m app.commands.create_agent_key`.

## Связь с сервером

Агент сам обращается к серверу, к нему никто не подключается: от объекта нужен только исходящий HTTPS
на 443. Установка на объекте и что согласовать со службой безопасности — `docs/agent-install.md`,
сервер — `docs/deploy-server.md`.

| Параметр (переменная) | Зачем |
|---|---|
| — | только `https://`; `http://` — лишь `localhost` или `--allow-http` (VPN, стенд) |
| `--ca-file` (`HARDENING_CA_FILE`) | свой корневой сертификат: TLS-инспекция или внутренний УЦ заказчика |
| `--pin-sha256` (`HARDENING_PIN_SHA256`) | закрепление ключа сервера `sha256//<base64>` (можно текущий и резервный); `--show-server-pin` печатает отпечаток |
| `--proxy` (`HARDENING_PROXY`) | корпоративный прокси; без него — `HTTPS_PROXY` из окружения |
| `--spool-dir` (`HARDENING_SPOOL_DIR`), `--no-spool` | очередь: сервер недоступен — прогон сохраняется (0600) и досылается при следующем запуске раньше нового, код выхода 75; до 50 прогонов и 30 дней |
| `--out <файл>` | изолированный сегмент: прогон в файл, подписанный ключом хоста (или площадки), — загрузка через интерфейс |
| `--enroll` | только зарегистрировать хост ключом площадки и выйти (установка через GPO, Ansible) |
| `--state-dir <каталог>` | каталог состояния: ключ хоста `host.json` (по умолчанию `/var/lib/hardening-agent`, на Windows `C:\ProgramData\HardeningAgent`) |

Неверный пин или непроверенный сертификат — остановка («Ошибка безопасности»), а не очередь: это не
«сервер недоступен». У каждого прогона `run_id` и `collected_at`: повторная отправка из очереди не создаёт
второй снимок, время снимка — время сбора.

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
2. Проверяет подпись Ed25519 открытым ключом сервера (`HARDENING_PACK_PUBLIC_KEY`; проверка на чистом
   Python, RFC 8032). Подписать открытым ключом нельзя — ключ с объекта не позволяет подделать паки для
   других. Старая схема — HMAC общим ключом `HARDENING_PACK_KEY` — на время перехода; с открытым ключом
   HMAC-подпись не принимается. Подделка — остановка с кодом ошибки.
3. По условиям `detect` определяет, какие паки подходят платформе. Не распознана — ничего не отправляется.
   Подходит несколько (например, ОС + Docker + Samba) — выполняются все, одним прогоном и одним
   запросом; `--pack <id>` ограничивает прогон одним паком.
4. Выполняет пробы подошедших паков (только чтение) и отправляет их `probe_results` в `POST /api/ingest`.
   Сравнение с нормой (`assert`) делает сервер.

```bash
export HARDENING_AGENT_API_KEY=<ключ площадки — при первом запуске агент регистрирует хост и сохраняет свой ключ>
export HARDENING_PACK_PUBLIC_KEY=<открытый ключ подписи паков — страница «Агенты»>
python3 collector.py --api-url https://hardening.example.com --environment prod --use-packs
```

Внешний сбор с сетевого устройства по SSH (с джамп-хоста; учётка на устройстве — только на чтение):

```bash
python3 collector.py --api-url https://hardening.example.com --environment net --use-packs \
  --ssh-host 10.0.0.1 --ssh-user audit --ssh-key ~/.ssh/audit_ed25519
```

Устройство должно быть в `known_hosts`: проверка ключа хоста включена и не отключается.

### UserGate NGFW

Учётка Admin на CLI UserGate не принимает ключ, а `ssh` с закрытым stdin возвращает пустой вывод.
Поэтому для UserGate агент ходит сам, с хоста в сети заказчика, и сам выбирает способ — пока один не ответит:

1. **XML-RPC** (`http://<устройство>:4040/rpc`, только методы из подписанного пака `usergate-ngfw`).
   Версия ПО берётся из ответа `v2.core.login` и уходит в сопоставление с БДУ.
2. **SSH exec**, порт 2200: одна команда на одно соединение, пароль через `SSH_ASKPASS`
   (в командную строку и в окружение ssh пароль не попадает). stdin не закрывается, пока не придёт вывод.
   Код возврата ssh всегда 255 — это не ошибка; ошибка команды — строка `Error:`.
   Exec выполняется в режиме configure, поэтому `show system version` там не работает.
3. **Интерактивный** `ssh -tt`: агент ждёт приглашение `Admin@узел>` / `#`, сам входит в `configure`,
   на `--more--` отвечает пробелом.

Пароль лежит только на хосте агента, отдельным файлом с правами `0600`. В файл цели его не пишут,
на сервер он не отправляется и в журнал не попадает.

```bash
install -d -m 0750 -o root -g hardening-agent /etc/hardening-agent
install -m 0600 -o hardening-agent -g hardening-agent /dev/null /etc/hardening-agent/usergate.pass
printf '%s\n' 'пароль-Admin' > /etc/hardening-agent/usergate.pass
chown hardening-agent:hardening-agent /etc/hardening-agent/usergate.pass
chmod 0600 /etc/hardening-agent/usergate.pass

# ключ хоста CLI (порт 2200) — в known_hosts пользователя, от которого запускается агент
ssh-keyscan -p 2200 10.77.0.20 >> /var/lib/hardening-agent/known_hosts

cp deploy/usergate.json.example /etc/hardening-agent/usergate.json
# в json: host, user, hostname, password_file, ssh_port, xmlrpc_port, known_hosts

export HARDENING_AGENT_API_KEY=<ключ площадки>
export HARDENING_PACK_PUBLIC_KEY=<открытый ключ подписи паков>
python3 collector.py --api-url https://hardening.example.com --environment net --use-packs \
  --pack usergate-ngfw --device-config /etc/hardening-agent/usergate.json
```

Проверка без отправки — тот же запуск с `--dry-run`. В stderr одна строка `UserGate <адрес>: способ доступа xmlrpc`
(или `ssh-exec` / `ssh-interactive`).

Если XML-RPC молчит: в зоне, откуда подключается агент, должен быть разрешён сервис XML-RPC
(на зоне Management он включён с завода, порт 4040). Если пустой вывод SSH — агент этой версии
stdin не закрывает раньше ответа; пустой вывод у старого `ssh -n` как раз из-за этого.
`show system version` в exec даёт `Error:` — версию тогда приносит XML-RPC или интерактивный сеанс.
Выгрузка команд в файлы (`--offline-dir`) по-прежнему работает и пароля не требует.

Команды `show` и методы XML-RPC — только чтение. Метод записи в паке агент не вызовет, даже если
он подписан: белый список зашит в `usergate.py`.

Проверка по выгрузке конфигурации — без доступа к устройству (нет SSH-доступа, устройство изолировано,
вендора нет на стенде). Вывод команд сохраняется в каталог, по файлу на команду; имя файла — команда,
в которой пробелы и `/` заменены на `_`: `show_running-config.txt`, `show_version.txt`,
`display_current-configuration.txt`, `export.txt`. Источник — бэкап (Oxidized, RANCID, TFTP) или выгрузка
администратора:

```bash
python3 collector.py --api-url https://hardening.example.com --environment net --use-packs \
  --offline-dir ./export-sw-core-01 --hostname sw-core-01
```

Применяются те же паки, что и по SSH, и те же пробы `cli_config`; ничего не выполняется, файлы только читаются
(символические ссылки не открываются, пустой файл — отказ пробы, секреты в свидетельстве маскируются). Если
выгрузки команды detect нет (обычно сохраняют только running-config), пак задаётся явно: `--pack cisco-ios`;
если выгрузка есть и не совпадает с паком — данные не отправляются. Фильтры вывода (`| include …`) по выгрузке
не поддерживаются: их выполняет само устройство.

В снимок уходит источник данных — имена файлов, SHA-256 и время изменения, а также признак «пак задан
оператором». В интерфейсе снимок помечен «по выгрузке», в PDF/Excel — строка «Источник данных»: проверено
состояние на момент выгрузки, а не живое устройство.

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

## Windows (паки `windows-server`, `windows-client`, `windows-dc`)

На Windows-хостах нет Python, поэтому агент собирается в один файл `hardening-agent.exe` (PyInstaller) —
тот же `collector.py` + `probes.py`, только стандартная библиотека (реестр — модуль `winreg`). Готовый
файл собирает каждый прогон workflow **Windows packs** в GitHub Actions (артефакт `hardening-agent-exe`);
заказчику он раздаётся с сервера — `https://audit.<домен>/downloads/hardening-agent.exe`, публикует
`deploy/publish_agent.sh`, ссылка, SHA-256 и готовые команды — на странице «Агенты». Собрать самому:

```powershell
pip install pyinstaller==6.11.1
pyinstaller --onefile --name hardening-agent --paths agent --hidden-import probes --hidden-import usergate agent/collector.py
```

Запуск — только в режиме паков, **от имени администратора или SYSTEM**: `secedit` (политика паролей и
блокировки) и `auditpol` (политика аудита) без этих прав недоступны — такие проверки получают
«не проверено», а не «соблюдено».

```powershell
$env:HARDENING_PACK_PUBLIC_KEY = '<открытый ключ подписи паков>'
.\hardening-agent.exe --api-url https://hardening.example.com --environment prod --api-key <ключ площадки> --enroll
.\hardening-agent.exe --api-url https://hardening.example.com --environment prod --use-packs
```

По расписанию — задача планировщика от SYSTEM. Ключ хоста — в `C:\ProgramData\HardeningAgent\host.json`
(доступ только SYSTEM и «Администраторы»); ключ площадки нужен только для регистрации и в переменные среды не
кладётся — переменные машины может прочитать любой пользователь ПК. `Register-ScheduledTask`, а не `schtasks /TR`: путь с
пробелом и аргументы передаются отдельно — вложенные кавычки PowerShell передаёт `schtasks` неправильно:

```powershell
$action = New-ScheduledTaskAction -Execute "C:\Program Files\Hardening\hardening-agent.exe" `
  -Argument "--api-url https://hardening.example.com --environment prod --use-packs"
Register-ScheduledTask -TaskName "Hardening agent" -Action $action -Trigger (New-ScheduledTaskTrigger -Daily -At 03:00 -RandomDelay (New-TimeSpan -Hours 1)) `
  -User SYSTEM -RunLevel Highest -Force | Out-Null
```

Что читает агент на Windows и почему не `net accounts` / `netsh` / `auditpol /get`: на русской Windows их
вывод русский, разбор ломается. Источники, не зависящие от языка:

| Проба | Источник | Права |
|---|---|---|
| `reg_value` | реестр, только `HKLM`; кусты `SAM` и `SECURITY` (хэши паролей, секреты LSA) запрещены | пользователь |
| `win_secpol` | `secedit /export` — ключи вида `MinimumPasswordLength` | администратор |
| `win_auditpol` | `auditpol /backup` — GUID подкатегорий и числа 0–3 | администратор |
| `service_state` | `sc query` (состояние — число и константа) и `Start` службы в реестре | пользователь |
| `win_ad` | контроллер домена: встроенный в агент сценарий PowerShell читает каталог по LDAP (ADSI), манифест выбирает только имя сведения из закрытого списка | SYSTEM на DC |

`secedit` и `auditpol` пишут результат во временный файл в новом временном каталоге агента — он читается
и сразу удаляется; системная конфигурация не меняется. Пустой экспорт — «не проверено», а не «не задано».

Проверено на **настоящих** Windows Server 2022 и 2025 (CI, `.github/workflows/windows-packs.yml`): все пробы
выполняются, распознавание верное, собранный `.exe` работает по подписанным манифестам и отказывает при
неверном ключе подписи. Windows 10/11 в CI нет — пак `windows-client` в статусе `draft`.

**Контроллер домена** (`windows-dc`, распознаётся по `ProductType = LanmanNt`) — дополняет `windows-server`:
подпись и привязка LDAP, защита Netlogon (ZeroLogon), DSRM, аудит каталога и Kerberos и состояние домена
(`win_ad`): возраст пароля `krbtgt`, привилегированные учётные записи, делегирование, AS-REP, бессрочные
и пустые пароли, `ms-DS-MachineAccountQuota`, анонимный LDAP, корзина AD, схема LAPS. Сценарий только
ищет по каталогу, группы определяет по SID (язык системы не важен) и выводит JSON в Base64; счётчики дают в
свидетельстве до 10 имён. Живого домена в CI нет — пак в статусе `draft`; в CI проверяется, что сценарий
запускается и вне домена честно отвечает «каталог недоступен».

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
