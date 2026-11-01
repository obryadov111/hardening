# 6. Режимы работы агента

## Зачем нужно

Один и тот же `collector.py` обслуживает живой хост, устройство по SSH, UserGate, Континент 4, каталог с выгрузкой и изолированный сегмент без связи с сервером. Режим выбирают флаги, а не отдельная программа.

Основной режим — `--use-packs`. Без него на Linux ещё работает старый сбор «фактов» (`build_payload`: sshd, ufw, обновления, пароли, `ip_forward`, docker). Сервер сравнивает их с таблицей `hardening_rules` функцией `evaluate_asset`. На Windows этот режим завершается ошибкой. Новые проверки живут в паках.

## Как выбирается транспорт

`build_pack_payload` в `agent/collector.py`. Флаги `--offline-dir`, `--ssh-host` и `--device-config` нельзя сочетать.

| Условие | Класс | `name` | Какие паки подходят |
|---|---|---|---|
| ничего из трёх | `LocalTransport` | `local` | `transport: local` |
| `--ssh-host` | `SshTransport` | `ssh` | `transport: ssh` |
| `--device-config` без `kind` или не Континент | `UserGateTransport` | `ssh` | `transport: ssh` |
| `--device-config` с `kind=continent4` (также `kontinent-4`, `kontinent4`, `c4`) | `Continent4Transport` | `ssh` | `transport: ssh` |
| `--offline-dir` и в каталоге выгрузка Континента | `Continent4Transport.from_directory` | `offline-config` | паки ssh (`pack_transport`) |
| `--offline-dir` иначе | `OfflineConfigTransport` | `offline-config` | паки ssh |

`pack_transport` в `agent/probes.py`: у выгрузки атрибут `pack_transport="ssh"`, поэтому выгрузка читается теми же паками, что и живое устройство.

Дальше:

1. Манифесты с сервера (`GET /api/agent/manifests?transport=local|ssh`) или из `--manifests-file`.
2. `load_verified_manifests`. Неверная подпись — `SystemExit` «Ошибка безопасности». Ни одна проба не выполняется.
3. Если у транспорта есть `bind_manifests` (UserGate и Континент), ему передают белые списки методов и путей из подписанного манифеста.
4. `select_manifests`: транспорт совпал и совпали все правила `detect`. Для выгрузки пак, явно указанный `--pack`, принимается и без detect, если файла команды detect нет. Если файл есть и detect не совпал, явное имя пак не продавливает.
5. Ни один пак не подошёл — выход «Платформа не распознана», на сервер ничего не уходит. Агент не угадывает платформу.
6. Все совпавшие паки выполняются. Теги складываются. `asset_type` — первый непустой.
7. На локальном хосте дополнительно собираются список ПО и паспорт железа. На устройстве вместо ПО — прошивка из поля `firmware` пака.

## Что уходит на сервер

Тело собирает `build_pack_payload`, схему проверяет `IngestRequest` в `src/backend/app/schemas/ingest.py`.

```json
{
  "environment": "prod",
  "asset": {
    "hostname": "srv-01",
    "ip_address": "10.0.0.5",
    "os": "Ubuntu 24.04.4 LTS",
    "asset_type": "linux-server",
    "criticality": "medium"
  },
  "software": [
    {"name": "openssh-server", "version": "1:9.6p1-3ubuntu13.5", "vendor": null, "category": "os-package", "type": "package"}
  ],
  "inventory": {
    "mac_address": "52:54:00:12:34:56",
    "device_uuid": "…",
    "cpu_model": "…",
    "cpu_cores": 4,
    "memory_mb": 7962,
    "board_vendor": "…",
    "board_product": "…",
    "disks": [{"name": "nvme0n1", "model": "…", "size_gb": 512, "type": "nvme"}]
  },
  "platform_tags": ["linux-server", "debian-family", "ubuntu"],
  "packs": [
    {
      "id": "ubuntu-server",
      "version": "1.4.0",
      "probe_results": {
        "ssh.permit_root_login": {"found": true, "value": "no", "evidence": "PermitRootLogin no"}
      }
    }
  ],
  "scan_label": "плановый",
  "run_id": "uuid",
  "collected_at": "2026-11-01T03:12:40+00:00"
}
```

Ограничения схемы: не больше 10 паков, не больше 20 тегов, `evidence` и `error` до 500 символов, `value` — строка, число, bool или null, дисков не больше 64.

Для выгрузки добавляется `collection`: источник `offline-config`, список файлов с командой, именем, SHA-256 и временем изменения, флаг `declared_pack`. У живого ЦУС `describe()` возвращает пусто: это обычный опрос устройства, не файл.

`run_id` и `collected_at` дописывает `main`, не `build_pack_payload`.

## Онлайн, повторы и очередь

`ServerConnection` (`agent/collector.py`):

- Адрес только `https://`. `http://` разрешён для localhost или с `--allow-http`.
- TLS не ниже 1.2. Свой корень — `--ca-file`. Прокси — `--proxy`.
- `--pin-sha256 sha256//…` — пин SPKI. Разбор DER — `spki_pin`. Можно два пина через запятую (текущий и запасной). Несовпадение — остановка, прогон в очередь не кладётся.
- Повторы на 429, 502, 503, 504. Паузы `RETRY_DELAYS = (15, 45, 120, 240)` секунд, умноженные на случайное число от 1,0 до 1,5. Учитывается `Retry-After`, но не дольше 300 секунд.

Классы ошибок:

- `TransientError` — нет связи, 408, 429, 5xx. Прогон уходит в очередь.
- `RejectedError` — прочий 4xx, выход с кодом 1. Исключение: 409 на свой `run_id` значит «уже принят» и считается успехом. 401 при наличии ключа площадки запускает перерегистрацию.

Очередь — каталог `spool`. Файл `<collected_at>-<run_id>.json`, права 0600. `spool_trim`: не больше 50 файлов и не старше 30 дней. Перед новой отправкой `spool_flush` досылает старые по порядку. Успех или 409 удаляет файл. 401 и 403 останавливают досылку, очередь остаётся. Прочий 4xx переименовывает файл в `.rejected`. Если текущий прогон только что сохранён в очередь, код выхода 75.

## Файл для изолированного сегмента

`--out отчёт.json` не открывает сеть. `sign_report` пишет:

```json
{
  "format": "hardening-agent-report",
  "version": 1,
  "payload": {},
  "signature": "HMAC-SHA256"
}
```

Ключ HMAC — SHA-256 от ключа агента, записанный как ASCII (`report_signing_key`). Сообщение — канонический JSON payload.

Загрузка: страница «Агенты», `POST /api/organizations/{org}/agent-reports` (`upload_agent_report` в `api/routes/agent_keys.py`). Нужен администратор организации. Сервер перебирает хэши ключей площадки и ключей хостов и сравнивает HMAC через `hmac.compare_digest`. Если подписал ключ хоста, hostname в отчёте должен совпасть. `collected_at` должен быть раньше отзыва и раньше конца срока ключа. В `collection` дописываются `transfer: file`, имя ключа, кто и когда загрузил, SHA-256 файла. Источник партии — `agent-report-file`.

Онлайн-запрос такой подписи не имеет.

## Полезные флаги

| Флаг | Зачем |
|---|---|
| `--api-url`, `--api-key` | Сервер и ключ площадки. После регистрации ключ читается из `host.json` |
| `--enroll` | Только регистрация |
| `--use-packs` | Режим паков |
| `--pack-public-key` | Открытый ключ Ed25519. Если задан, HMAC-подпись манифеста не принимается |
| `--pack-key` | Старый общий HMAC. Игнорируется, когда задан открытый ключ |
| `--pack` | Оставить один id |
| `--manifests-file` | Манифесты из файла, без сети. Так работает CI |
| `--dry-run` | Показать payload и не отправлять |
| `--out` | Файл вместо POST |
| `--ssh-host`, `--ssh-user`, `--ssh-port`, `--ssh-key` | Устройство по SSH |
| `--device-config` | JSON UserGate или Континент 4. Пароль в этот JSON не входит |
| `--offline-dir`, `--hostname` | Выгрузка |
| `--collect-identity` | ПДн в паспорт. По умолчанию выключено |
| `--no-spool` | Не сохранять прогон при обрыве |
| `--show-server-pin` | Напечатать пин и выйти |
| `--state-dir`, `--spool-dir` | Где лежат ключ и очередь |

Полный разбор флагов — `parse_args` в `agent/collector.py`.

## Где в коде

| Что | Где |
|---|---|
| Выбор режима | `build_pack_payload`, `open_device_transport`, `main` |
| Сеть и очередь | `ServerConnection`, `send_ingest`, `spool_save`, `spool_flush` |
| Подпись файла | `sign_report` |
| Приём файла | `upload_agent_report` в `api/routes/agent_keys.py` |
| Схема тела | `IngestRequest` в `schemas/ingest.py` |

## Ограничения

- Старый режим фактов на Windows запрещён и новых правил в паки не переносит.
- Очередь не бесконечная: 50 файлов и 30 дней. Сервер всё равно отвергнет `collected_at` старше 31 дня.
- Неверный пин сертификата в очередь не попадает: иначе агент носил бы отчёт, снятый при подозрении на подмену.
- `--device-config`, SSH и выгрузка взаимоисключающие. Два устройства — два экземпляра службы.

## Вопросы на защите

**Агент сам ставит оценку?** Нет. Он присылает `probe_results`. Оценку пишет `evaluate_pack` на сервере.

**Чем онлайн отличается от файла `--out`?** Онлайн — HTTPS и ключ в заголовке, без подписи тела. Файл подписан HMAC от ключа агента, потому что его несут на флешке и загружает человек.

**Что если сервер ответил 503?** Агент ждёт 15–240 секунд с разбросом и повторяет. Не вышло — кладёт JSON в `spool` и выходит с кодом 75. Следующий запуск дошлёт очередь раньше нового прогона.

**Почему платформа «не распознана», хотя файлы лежат?** `detect` не совпал, а `--pack` не указан. Агент в этом случае ничего не отправляет.
