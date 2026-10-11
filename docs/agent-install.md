# Установка агента на объекте заказчика

## Что согласовать со службой безопасности заказчика

- **Сеть:** только исходящий HTTPS (`443/tcp`) к одному адресу — `audit.<домен>`. Входящих соединений нет,
  VPN не нужен. Если интернет только через прокси — адрес прокси.
- **Что делает агент:** только читает конфигурацию хоста по пакам, подписанным сервером (белый список команд,
  запрет чтения секретов: `/etc/shadow`, ключи SSH, кусты `SAM` и `SECURITY` реестра). Ничего не меняет.
- **Что уходит на сервер:** результаты проверок конфигурации, список установленного ПО, имя хоста, IP, ОС.
  Пароли, хэши, ключи и SNMP-community маскируются агентом и на сервер не попадают.
- **Права:** Linux — отдельный пользователь `hardening-agent` без входа, служба с ужесточением systemd;
  Windows — задача планировщика от SYSTEM (политика безопасности и аудита доступны только администратору).

## Что выдаёт аудитор

1. Ключ агента для этого объекта — интерфейс, «Агенты» → «Новый ключ». Там же готовый файл настроек.
2. Открытый ключ подписи паков — там же.
3. Отпечаток ключа сервера (`HARDENING_PIN_SHA256`) — его печатает `deploy/enable_https.sh` на сервере
   или агент: `python3 collector.py --api-url https://audit.<домен> --environment x --show-server-pin`.

## Linux (systemd)

```bash
git clone … && cd hardening/agent        # или скопировать каталог agent/
sudo deploy/install.sh                   # экземпляр local — этот хост
sudo nano /etc/hardening-agent/local.env # вставить файл настроек из интерфейса
sudo systemctl start hardening-agent@local.service && journalctl -u hardening-agent@local -n 30
sudo systemctl enable --now hardening-agent@local.timer   # ежедневно
```

Нужен системный Python 3 — только стандартная библиотека, без pip.

## Windows

`hardening-agent.exe` — артефакт `hardening-agent-exe` workflow **Windows packs** (Python на хосте не нужен).

```powershell
mkdir "C:\Program Files\Hardening"; copy hardening-agent.exe "C:\Program Files\Hardening\"
setx /M HARDENING_AGENT_API_KEY "<ключ агента>"
setx /M HARDENING_PACK_PUBLIC_KEY "<открытый ключ>"
setx /M HARDENING_PIN_SHA256 "sha256//<отпечаток>"
# при прокси: setx /M HARDENING_PROXY "http://proxy.corp:3128"
schtasks /Create /TN "Hardening agent" /RU SYSTEM /SC DAILY /ST 03:00 /RL HIGHEST `
  /TR "\"C:\Program Files\Hardening\hardening-agent.exe\" --api-url https://audit.<домен> --environment prod --use-packs"
schtasks /Run /TN "Hardening agent"
```

Очередь неотправленных прогонов — `C:\ProgramData\HardeningAgent\spool`.

## Проверка связи

```bash
curl -sS https://audit.<домен>/health                       # {"status":"ok"}
python3 collector.py --api-url https://audit.<домен> --environment x --show-server-pin  # совпадает с выданным
```

Прогон появляется в интерфейсе в «Сканированиях», у ключа на странице «Агенты» — время и адрес последнего
обращения.

## Если что-то не так

| Сообщение агента | Причина |
|---|---|
| `нужен https://` | в `HARDENING_API_URL` указан `http://` (допустим только `localhost`) |
| `сертификат сервера не прошёл проверку` | в сети заказчика TLS-инспекция или свой УЦ — `HARDENING_CA_FILE` с корневым сертификатом; либо время на хосте неверное |
| `открытый ключ сервера не совпал с закреплённым` | ответил не наш сервер (перехват, подмена DNS) — **остановиться и выяснить**; либо сервер сменил ключ, а отпечаток не обновлён |
| `Сервер недоступен … сохранён в очередь` (код 75) | нет связи; прогон будет дослан при следующем запуске (очередь — до 50 прогонов и 30 дней) |
| `HTTP 401 — Недействительный ключ агента` | ключ отозван или истёк — выдать новый; очередь сохраняется до нового ключа |
| `Подпись манифеста … неверна` | паки подписаны не тем ключом, что `HARDENING_PACK_PUBLIC_KEY`, — проверить ключ; не обходить |

## Изолированный сегмент (без связи с сервером)

Агент сохраняет прогон в файл, подписанный ключом агента (`--out report.json`), с манифестами из файла
(`--manifests-file`). Файл переносится и загружается в интерфейсе: «Агенты» → «Отчёт агента из файла».
Подробнее — `docs/deploy-server.md`, раздел 6.
