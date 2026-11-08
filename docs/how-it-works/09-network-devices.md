# 9. Сетевые устройства и российские СЗИ

## Зачем нужно

На межсетевой экран и коммутатор нельзя поставить службу так же, как на Ubuntu. Агент стоит на обычном Linux в сети заказчика и читает устройство. Сервер при этом тот же: манифест, пробы `cli_*`, `evaluate_pack`, прошивка как запись ПО для БДУ.

Актуальные ssh-паки на 1 ноября 2026: `cisco-ios`, `eltex-esr`, `eltex-mes`, `qtech-qsw`, `snr-switch`, `vipnet-coordinator`, `s-terra-gate`, `infowatch-arma-ngfw`, `dionis-nx`, `pt-ngfw` (только inventory), `usergate-ngfw`, `kontinent-4`. Опросные: `kontinent-4-local`, `ideco-ngfw`, `pt-ngfw-settings`. Паков Huawei и MikroTik в каталоге нет.

Подробный перечень проверок по вендорам — в `docs/network-devices.md`. Здесь — откуда берётся текст и что с ним делают.

## Общий путь

1. Экземпляр агента `hardening-agent@устройство` с `--use-packs`.
2. Манифесты `transport=ssh`.
3. Транспорт отдаёт текст команд.
4. `detect` выбирает один сетевой пак. Тест `test_device_output_is_recognised_by_exactly_one_pack` гоняет образцы всех ssh-паков и требует, чтобы вывод подошёл ровно одному.
5. Пробы заполняют `probe_results`.
6. `collect_firmware` добавляет продукт и версию в `software` с категорией `firmware`.
7. `inventory` для устройства пустой: паспорт железа хоста сюда не подмешивается.
8. Сервер сравнивает `assert` и считает тот же процент, что и для сервера Linux.

Три канала текста:

| Канал | Как запускается | Что видит отчёт |
|---|---|---|
| SSH ключом | `--ssh-host`, `--ssh-user`, `--ssh-key` | живое устройство, `collection` пустой |
| Файл цели | `--device-config` JSON | живое устройство. Для Континента `describe()` пустой |
| Выгрузка | `--offline-dir`, `--offline-file` или страница «Проверка по выгрузке» | `collection.source = offline-config` |

Выгрузка через интерфейс: `POST /api/organizations/{org}/offline-scans`, функция `upload_offline_scan`. Администратор организации. До 10 файлов по 5 МБ (`MAX_FILES`, `MAX_FILE_BYTES` в `services/offline_scan.py`) либо одно поле `bundle` того же размера. Команда файла в многофайловом режиме должна встречаться в каком-нибудь ssh-паке, иначе `OfflineScanError`. Сервер грузит `agent/probes.py` и `agent/offline_split.py` и для обычных команд вызывает `OfflineConfigTransport`. Если рядом лежит `continent4.py`, JSON ЦУС сначала пробует `Continent4Transport.from_uploads`. Образ бэкенда копирует `probes.py`, `offline_split.py` и `continent4.py`. `usergate.py` в образ не входит: живой XML-RPC делает агент на хосте заказчика. Дальше обычный `ingest_payload` с источником `offline-upload`. Тип актива — из пака, иначе у загрузки подставляется `network-device` в маршруте, если пак его не задал.

Один файл режет `split_bytes` в `agent/offline_split.py` (без зависимостей, тот же код у `--offline-file`):

| Что принесли | Как режется |
|---|---|
| Журнал `host# show version`, `user@host:~$`, эхо `Admin@узел#` | приглашение — граница команды. `sh run`, `sh ver`, лишние пробелы и `\| no-more` сопоставляются с командой пака. `terminal length 0` пропускается. `--More--`, backspace и ANSI стираются |
| Oxidized `! Command:` или закомментированный `show version` (`! Cisco IOS…`) и RANCID `!RANCID-CONTENT-TYPE:` | маркеры, не приглашение. Тело RANCID — конфигурация |
| Только `show running-config` | пак по отпечатку текста, если он однозначный: `version 15.2` и `end` без ГОСТ — Cisco IOS; `crypto isakmp` и `gost` — С-Терра; `#!/usr/bin/clish` — Eltex ESR; `passwords complexity enable` — Eltex MES; `service ssh` — Dionis; `set system login` — ARMA. Qtech и SNR по конфигурации неразличимы: нужна галочка пака |
| zip, tar, tar.gz | файлы с именами `offline_file_name` (`show_running-config.txt`). Путь с `..`, абсолютный путь и symlink отвергаются. Не больше 30 записей и 20 МБ распаковки |
| JSON `{команда: текст}` или JSON ЦУС (`export` / bundle `{export, cgw}`) | команды либо `Continent4Transport` |

Пустая выгрузка, двоичный файл и превышение размера — ответ 422 по-русски. `POST …/offline-scans/preview` показывает пак, найденные команды и пропуски, снимок не пишет. Пропущенная команда даёт проверкам «не проверено». Режим «файл на команду» в интерфейсе свёрнут, API полей `commands` и `files` не изменился.

## UserGate NGFW

Код — `agent/usergate.py`, класс `UserGateTransport`. Пак `usergate-ngfw` 1.1.0, 12 проверок, `transport: ssh`, зрелость `draft`.

Комментарий в YAML: формат сверен с лабораторным UserGate NGFW 7.4.1.341220R, заводские умолчания лежат в `pack_tests` и `agent/tests/fixtures/usergate`. Поле `verified_on` не заполнено. Пока его нет, модель не даст назвать пак `baseline`. Живой прогон агента на стенде автор в файле ещё не зафиксировал как подтверждение.

Почему не обычный `ssh host "команда"`. Учётка Admin по ключу не пускает. Одна команда `ssh` с закрытым stdin на CLI 7.4 возвращает пустой вывод. Поэтому отдельный транспорт, пароль остаётся в файле на хосте агента (права как у секрета) и в аргументы процесса `ssh` не попадает.

Порядок по умолчанию (`_DEFAULT_ORDER`):

1. **XML-RPC**, порт 4040. Методы только из пересечения белого списка агента `USERGATE_READONLY_METHODS` и списка `xmlrpc_methods` подписанного манифеста. Сейчас в паке: `v2.core.login`, `v2.core.logout`, `v2.core.administrator.config.get`, `v1.netmanager.zones.list`, `v1.firewall.rules.list`. В коде агента белый список шире на один пункт (`v2.core.license.info`, `v1.dos.profiles.list`): пак их не объявил, агент их не вызовет. Методы с `add`, `update`, `delete`, `set` и похожими сегментами отвергаются регуляркой и на сервере, и в агенте.
2. **SSH exec**, порт 2200. Одна команда на соединение, stdin не закрывают, пока не придёт вывод. Пароль через механизм askpass, не argv. В этом режиме сессия сразу в `configure`, и `show system version` там отвечает ошибкой.
3. **Интерактивный SSH** `ssh -tt`: приглашение, листание `--more--`. Версию читают до входа в configure.

Способ, который не смог отдать команду, не отменяет остальные. Версия берётся из ответа `v2.core.login` или из `show system version`. В отчёт уходит продукт `usergate next-generation firewall (ngfw)` — так он назван в БДУ. Пароль и `auth_token` в свидетельстве вырезаются (`scrub`).

Выгрузка тех же команд по-прежнему работает: файлы `show_settings_administrators_general.txt`, `show_network_zone_Untrusted.txt`, `show_system_version.txt`, один журнал CLI или архив этих файлов. Ответы XML-RPC агент в один файл не складывает — на странице выгрузки это сказано отдельно.

Примеры сравнений пака:

- `usergate_ngfw.admin_strong_password` — `eq on`
- `usergate_ngfw.admin_password_min_length` — `gte 8`
- `usergate_ngfw.admin_lockout_attempts` — `between` от 1 до 5
- `usergate_ngfw.untrusted_management_restricted` — `absent`: в зоне Untrusted не должно быть включённого Admin Console, CLI, XML-RPC или SNMP с адресом Any

Зона Untrusted — заводское имя. Если внешняя зона названа иначе, `require` не сойдётся и проверка будет «не проверено», а не «соблюдено».

Пример цели — `agent/deploy/usergate.json.example`.

## Континент 4

Код — `agent/continent4.py`, класс `Continent4Transport`. Пак `kontinent-4` 1.1.0, 6 проверок, `transport: ssh`. Комментарий: поля сверены с лабораторным ЦУС и узлом 4.2.1-653, пара выгрузок лежит в `agent/tests/fixtures/continent4`. `verified_on` пуст, уровень `draft`.

ЦУС слушает порт 444 и принимает TLS 1.2 с шифрами ГОСТ (Kuznyechik). Агент остаётся на стандартной библиотеке и перебирает, кто умеет такой TLS:

1. `ssl` текущего процесса, если движок ГОСТ уже загружен через `OPENSSL_CONF` до импорта.
2. Отдельный процесс Python с `OPENSSL_CONF` на `gost.so`.
3. `curl` с тем же `OPENSSL_CONF`.
4. `openssl s_client`.

На хосте нужен OpenSSL 3 и пакет вроде `libengine-gost-openssl`. Пароль читается из файла 0600 и в argv не попадает.

Пин `pin_sha256` в конфиге устройства — это SHA-256 всего сертификата ЦУС в DER, не SPKI. Если он задан, сверка идёт сразу после рукопожатия. Пока отпечаток не совпал, пароль и байты HTTP не отправляются. Несовпадение останавливает опрос (код 2), следующий способ не пробуется. `curl` так сверить не может (`--pinnedpubkey` хеширует SPKI), поэтому при заданном пине curl пропускается.

Живой опрос — три GET и только они (`C4_READONLY_PATHS` совпадает с `c4_paths` пака):

- `/api-v1-objects/config`
- `/api-v1-objects/config/active/cgw`
- `/api-v1-server/config/active/export-config-for-cgw/{hwserial}?view=full`

POST, PUT, DELETE, lock, fork, commit, install-policy и set-password агент не вызывает, даже если путь оказался бы в манифесте. Тело ответа чистится от полей паролей, community и ключей. Наружу пробы видят уже текст команд `show continent …`, который собирает сам агент из JSON. Поэтому пак выглядит как обычный `cli_config`, хотя по проводу ходил HTTP.

Учётка в комментарии пака — роль «Аудитор» комплекса: привилегии просмотра и структуры. На 4.2.1-653 этих прав хватает на три GET, запись отвечает 403. IP хоста агента должен быть в доступе к ЦУС.

Та же выгрузка JSON (`c4_config_exporter` или локальное меню) читается офлайн: `--offline-dir`, один JSON (export или bundle `{export, cgw}`), архив каталога и загрузка через интерфейс. `directory_has_export` узнаёт каталог.

Проверки 1.1.0:

- длина пароля `gte 8`
- блокировка `eq on`
- хотя бы одна персональная учётка (`cli_blocks`, `gte 1`)
- SSH к локальному меню `in` «выключен» или «включён, адреса ограничены»
- SNMP `in` «выключен» или «v3 с SHA и AES»
- внешний syslog `eq yes`

Версия для БДУ — `update_version` узла, продукт `комплекс безопасности «континент». версия 4`. Хвост после дефиса (`4.2.1-653`) при разборе версии пакета отрезается как ревизия сборки, сравнивается `4.2.1`.

Чего в API нет: пароль BIOS, пароль загрузчика, тайм-аут локального меню. Они в паке `kontinent-4-local` (опрос, 3 вопроса). Пример цели — `agent/deploy/continent4.json.example`.

## Остальные вендоры коротко

| Пак | Как читается | Прошивка в БДУ |
|---|---|---|
| `cisco-ios` | SSH или `show running-config` / `show version` | поля прошивки в актуальном паке нет, в каталоге методики продукт `cisco ios` для пункта УСИ.1 всё же перечислен |
| `eltex-esr`, `eltex-mes` | SSH или выгрузка, `firmware` из `show system` | да, шаблоны `esr-*`, `mes…` |
| `qtech-qsw`, `snr-switch` | SSH или выгрузка | да |
| `vipnet-coordinator` | команды `iplir` / `version`, отдельная ветка белого списка | да |
| `s-terra-gate`, `infowatch-arma-ngfw`, `dionis-nx` | SSH или выгрузка | у ARMA и Dionis по их `firmware`; у С-Терра поля `firmware` в актуальном файле нет |
| `pt-ngfw` | SSH, 0 проверок, только версия | продукт для УСИ.1 |
| `ideco-ngfw`, `pt-ngfw-settings` | только опрос | версия — ответ аудитора |

`s-terra-gate` 1.0.0 в выдаче скрипта подсчёта шёл без блока firmware. Если версии в `software` нет, БДУ по этой прошивке не с чем сопоставлять.

## Где в коде

| Что | Где |
|---|---|
| SSH и файлы | `SshTransport`, `OfflineConfigTransport` в `agent/probes.py` |
| UserGate | `UserGateTransport` в `agent/usergate.py` |
| Континент | `Continent4Transport` в `agent/continent4.py` |
| Выбор транспорта | `open_device_transport` в `agent/collector.py` |
| Загрузка выгрузки на сервере | `run_offline` в `services/offline_scan.py` |
| Белые списки в модели пака | `USERGATE_XMLRPC_READONLY`, `C4_READONLY_PATHS` в `services/packs/models.py` |

## Ограничения

- Ни один сетевой пак не в статусе `baseline`. Лабораторные стенды UserGate 7.4.1 и Континент 4.2.1 использованы для формата и фикстур. Это написано в шапке YAML. Подтверждения `verified_on` там нет.
- Обычный SSH не годится для интерактивного CLI UserGate. Для него нужен `--device-config`.
- Без ГОСТ-движка на хосте агента ЦУС Континента не открывается. Сервер «Харденинга» к ЦУС не ходит.
- Huawei, MikroTik и другие вендоры без файла в `app/packs/` не распознаются. Агент завершится «платформа не распознана».
- Опрос менее надёжен, чем чтение конфигурации. Снимок это показывает.

## Вопросы на защите

**UserGate проверяет сервер или агент?** Агент на Linux в сети заказчика. Сервер только получает уже собранные `probe_results`.

**Какие каналы у UserGate?** Сначала XML-RPC 4040, потом SSH exec на 2200, потом интерактивный SSH. Плюс выгрузка тех же команд файлами.

**Как Континент проходит ГОСТ TLS, если агент на стандартной библиотеке?** Перебор: системный ssl с движком, отдельный Python, curl, openssl s_client. Все с `OPENSSL_CONF` на `gost.so`. Пароль до совпадения пина сертификата не отправляется.

**Почему у Континента два пака?** `kontinent-4` читает политику ЦУС. `kontinent-4-local` спрашивает BIOS, пароль загрузчика и тайм-аут меню: в API этого нет.

**Это уже baseline?** Нет. Зрелость обоих — `draft`, потому что `verified_on` пустой.
