# 34. Файлы для администратора: что загружать и откуда брать

Глава для того, кто готовит выгрузку, а не только для комиссии. Описание — код `main` `1a5997d`. Открытый [PR 23](33-proposed-pr23.md) убирает страницу «Проверка по опросу» и не меняет загрузку выгрузки на `/offline-scan`. [PR 21](32-proposed-changes.md) сюда не входит: дневной сбор Windows в `main` не описан как уже включённый.

Сервер сам на железо не ходит. Автоматически отчёт появляется только если на площадке уже стоит агент и он сам открывает HTTPS к API. Отдельного «сервер опросил Континент по расписанию» нет.

Четыре разных действия, их нельзя называть одним словом «автоматизация»:

| Действие | Кто делает | Что получается |
|---|---|---|
| Загрузка файла на сайт | Администратор организации, страница «Проверка по выгрузке» или тот же `POST` | Снимок с источником выгрузки |
| Агент сам собрал и сам отправил | `collector.py` по таймеру, `POST /api/ingest` | Снимок без ручного файла |
| Агент записал файл отчёта | `--out`, человек потом загружает его на «Агенты» | Это JSON отчёта агента, не конфигурация устройства |
| Генерация vendor-export | Продукт вендора или три GET агента к ЦУС | JSON, который ещё нужно отдать агенту или на сайт. Харденинг сам такой JSON из ничего не создаёт |

## Континент 4: какой файл класть на сайт

Надёжный файл с железа — JSON ответа ЦУС, не резервная копия шлюза и не журнал команд самого шлюза. Разборщик при этом умеет читать и синтетический журнал, если в нём уже стоят виртуальные строки `show continent …`. Это не одно и то же.

Пак `kontinent-4` 1.1.0 читает конфигурацию узла безопасности так, как её отдаёт ЦУС. Пак `kontinent-4-local` — три вопроса человеку (BIOS, пароль загрузчика, тайм-аут локального меню). На `main` эти вопросы вводятся на странице «Проверка по опросу». После PR 23 страница исчезнет, ручки опроса останутся, но готового экрана не будет. Шлюз по SSH и его собственный CLI этот код не разбирает.

Проверено 22 ноября 2026 на образце `docs/how-it-works/samples/continent-bundle-min.json` (выдуманные номера, без паролей):

```text
python3 -c "import sys; sys.path.insert(0,'agent'); import offline_split; raw=open('docs/how-it-works/samples/continent-bundle-min.json','rb').read(); s=offline_split.split_bytes(raw, ['show continent version'], filename='continent-bundle-min.json'); print(s.kind, s.mode, s.recognized_pack)"
```

Печать: `json json kontinent-4`. Классификатор `classify_document` в `agent/continent4.py` называет такой файл `bundle`.

### Что в файле обязательно

Кодировка UTF-8. Допускается BOM (`utf-8-sig`). Расширение на сайте не проверяется по белому списку сервера: поле файла принимает `.json`, но решает содержимое.

Подходит один из четырёх видов. Имена полей — как в `classify_document` и `_looks_continent`.

1. Объект с ключами `export` и/или `cgw`. `export` — объект или список выгрузки узла. `cgw` — объект или список узлов. Хотя бы одно из них объект или список. Так устроен образец.
2. Сама выгрузка узла: объект с массивом `objects`. В элементах есть `type` из набора `passwordpolicy`, `sshaccesscomponent`, `snmpcomponent`, `admin`, `cgw`. Плюс либо `"type": "full"`, либо поле `hwserial`.
3. Список узлов или объект `{"data": [ ... ]}`, где хотя бы у одного элемента есть и `hwserial`, и `update_version`. Одного такого списка мало для проверок: без выгрузки узла `documents_from_items` пишет «в выгрузке Континент 4 нет export-config-for-cgw».
4. Zip, tar или tar.gz, внутри один или несколько `.json` этих видов. Имя внутри архива может быть любым `.json`. Смешивать JSON ЦУС и файлы `show_….txt` нельзя: ошибка «в архиве смешаны JSON Континент 4 и файлы команд».

В выгрузке узла для проверок читаются объекты:

| `type` | Зачем |
|---|---|
| `passwordpolicy` | `min_length`, `wrong_try_count`, `wrong_try_block`, `blocked_days` |
| `admin` | `login`, `is_enabled`, `primary`, `is_autocreated`, `uuid` |
| `cgw` | имя и `hwserial`, если отдельного списка узлов нет |
| `sshaccesscomponent` | включён ли SSH к локальному меню |
| `snmpcomponent` | `is_enabled`, `protocol`, `auth_type`, `enc_type` |
| `logserverremoteuplink` или тип со словом `syslog` | `is_enabled` и `host` / `ip` / `address` |

Объекты с `is_deleted: true` отбрасываются. Версия для БДУ — поле `update_version` узла из `cgw`, не из выгрузки. В образце оно `4.2.1-1`. Без `cgw` строка версии в разобранном тексте не появляется.

Несколько узлов в `cgw` без совпадающего `hwserial` у выгрузки дают ошибку «на ЦУС несколько узлов … укажите hwserial». В файле цели агента это поле `hwserial`. В одном JSON для сайта серийный номер должен совпасть сам: выгрузка несёт `hwserial`, список узлов — тот же номер.

### Три слоя: что принимает код, что может снять оператор, что доказывает фикстура

1. Парсер технически принимает журнал сессии, если после приглашения `host#` стоят команды пака: `show continent version`, `password-policy`, `administrators`, `ssh`, `snmp`, `syslog`, и дальше текст, который `render_commands` строит из JSON. Хвост `| no-more` отбрасывается. Функция `test_session_archive_and_abbreviations_match_multifile` в `src/backend/tests/test_offline_bundle.py` для пака `kontinent-4` собирает такой журнал из блока `base.cli` фикстуры, архив `show_continent_….txt` и набор файлов по команде. Подписи проб совпали. 22 ноября 2026 вызов этой функции и `test_continent_json_bundle_and_archive_match_two_files` прошёл напрямую, без pytest: у pytest после теста падает закрытие PostgreSQL, которого в среде нет. Это не прогон железа.
2. Оператор достоверно получает JSON ЦУС: три GET агента, либо файл той же формы. Комментарий фикстуры `pack_tests/kontinent-4.yaml` прямо говорит, что текст `show continent …` — то, что агент строит из JSON, а лабораторная пара 4.2.1-653 гоняется в `agent/tests/test_continent4.py` по JSON, не по терминалу шлюза. Командной строки шлюза, которая печатает `show continent version`, в репозитории нет.
3. Синтетический журнал и фикстура `base.cli` не доказывают, что на железном CLI есть эти команды. Журнал `node> show config` на списке команд пака разборщик отверг: «в журнале сессии не найдено известных команд пака». Родной backup, который не является zip/tar с JSON или журналом этих команд, тоже не принимается: обрезка zip дала «архив повреждён или это не zip/tar».

История PR 17 верна как проверка разборщика: сессия, zip и JSON дали те же 6 проб, что и файл на команду. Она неверна, если читать её как «с шлюза сняли терминальную сессию». Сессия в тесте собрана функцией `_session` из уже готовых текстов команд.

### Что в схеме обязательно, а что только для полноты проб

Файл принимается, если это один из четырёх видов выше. Отдельный список `cgw` без `export` узнаётся, но `documents_from_items` отказывается: «в выгрузке Континент 4 нет export-config-for-cgw». Для снимка нужна выгрузка узла (`objects`).

Не каждый `type` обязателен. Нет объекта — файл не отвергается, проверка по нему становится «не проверено» или, для syslog, нарушением:

| Нет объекта | Что делает рендер | Статус проверки |
|---|---|---|
| `passwordpolicy` | строка `missing: yes`, нет `min_length` и `lockout` | `error` у длины и у блокировки |
| `admin` | `missing: yes` | `error` у персональных учёток |
| `sshaccesscomponent` | `missing: yes` | `error` у SSH |
| `snmpcomponent` | `missing: yes` | `error` у SNMP |
| внешний syslog | всегда печатает `remote: no` | `fail`, не `error` |
| `cgw` с `update_version` | шесть проверок живут и без него | в `software` не попадает версия прошивки |

Учётка `admin` без связи на роль даёт `value` 0 и статус `fail`: факт есть, персональных записей с непустой `role` нет. Это не «не проверено».

Образец `continent-bundle-min.json` прогнан через `run_offline_bundle` и `evaluate_pack` 22 ноября 2026. Пак `kontinent-4` 1.1.0, формат `json`, прошивка `4.2.1-1`. Статусы: длина пароля, блокировка, SSH, SNMP и syslog — `pass`; персональные учётки — `fail`, потому что у `auditor` нет непустой роли. Это не полный зачёт. Тот же текст, записанный журналом `sw-core-01# show continent …`, дал формат `session` и те же статусы. Выгрузка только с `passwordpolicy` дала два `pass`, три `error` и `fail` по syslog, прошивки нет.

### Чего загружать нельзя

- Двоичный backup шлюза и любой файл, который не JSON ЦУС, не архив таких JSON и не журнал уже нормализованных `show continent`.
- JSON отчёта агента `{"format":"hardening-agent-report",...}`. Ответ: «JSON не похож на выгрузку команд или на JSON Континент 4». Его место — страница «Агенты», поле `file` у `POST …/agent-reports`, не поле `bundle`.
- Файл больше 5 000 000 байт на сайте и в `split_bytes`. Каталог агента `--offline-dir` для одного JSON режет на 8 МиБ (`_MAX_BODY`). Файл между этими порогами агент из каталога прочитает, сайт — нет.

Лабораторные файлы с настоящими полями схемы, не для копирования заказчику, лежат в `agent/tests/fixtures/continent4/`: `export-for-cgw-4210001.json`, `cgw.json`, `config.json`. Тест кладёт выгрузку в каталог под именем `export-config-for-cgw.json` (`agent/tests/test_continent4.py`). Имя файла для классификатора не важно, важно что это `.json` и форма выше. `config.json` — список конфигураций ЦУС; для проверок он не используется.

### Откуда взять JSON, не выдумывая меню

В репозитории нет пошаговых кликов по веб-интерфейсу Кода Безопасности. Есть три способа, которые названы в коде.

1. Живой агент. Файл цели — поля `host`, `user`, `password_file`, необязательные `hostname`, `hwserial`, `port` (по умолчанию 444), `pin_sha256`, `timeout`, `tls`, `gost_engine`, `openssl_conf`. Пароль в JSON цели запрещён. Пример полей без подстановки чужого адреса: `agent/deploy/continent4.json.example`. Пароль — отдельный файл, режим `0600`, не ссылка. Запуск: `python3 agent/collector.py --use-packs --device-config <файл цели>`. Агент сам делает только три GET и сам шлёт `POST /api/ingest`. Это и есть автоматический сбор. Сервер Харденинга к ЦУС не подключается.
2. Те же три GET, если их делает не агент, а человек или свой скрипт с учётной записью просмотра: `/api-v1-objects/config`, `/api-v1-objects/config/active/cgw`, `/api-v1-server/config/active/export-config-for-cgw/{hwserial}?view=full`. Другие методы и `view=short` агент отвергает. Ответ export и ответ cgw можно положить в один объект `{"export": ..., "cgw": ...}` или двумя `.json` в каталог.
3. Комментарий `agent/continent4.py` называет источниками того же JSON утилиту `c4_config_exporter` и локальное меню. Командной строки экспортёра и кликов меню в репозитории нет. Если файл с экспортёра или меню подходит под схему выше, сайт и `--offline-dir` его примут. Если это другой backup, не примут.

ЦУС на порту 444 требует TLS 1.2 с шифрами ГОСТ (в коде: Kuznyechik, `GOST2012-KUZNYECHIK-KUZNYECHIKOMAC`). Агент перебирает `ssl` процесса, отдельный Python, `curl`, `openssl s_client` и ищет `OPENSSL_CONF` / `gost_engine`. Без движка ГОСТ живой опрос не откроется. Для уже сохранённого JSON ГОСТ не нужен: файл читается офлайн. `pin_sha256` — SHA-256 всего сертификата ЦУС в DER, не SPKI. Пока отпечаток не совпал, пароль и HTTP не отправляются.

### Как загрузить на сайт

Страница `/offline-scan`, кнопка «Проверить выгрузку». Право — администратор организации. Поля формы и имена частей `multipart`:

| На экране | Имя поля |
|---|---|
| Файл выгрузки | `bundle` |
| Имя устройства | `hostname` |
| IP-адрес | `ip_address` |
| Окружение | `environment`, по умолчанию `network` |
| Критичность | `criticality`: `low`, `medium`, `high`, `critical` |
| Когда снята выгрузка | `exported_at`, ISO-время; будущее отвергается |
| Метка скана | `scan_label` |
| Прогон | `scan_run_id`, пусто — автоокно |
| Пак, только если файл сам не узнан | `pack` |

Предпросмотр без снимка: `POST /api/organizations/{org}/offline-scans/preview`, поля `bundle` и необязательный `pack`. Запись: `POST /api/organizations/{org}/offline-scans`. Оба требуют администратора. Другого API «запусти проверку Континента» нет: повторить можно только этот `POST` или поставленный агент.

После успешного разбора виртуальные команды `show continent version`, `password-policy`, `administrators`, `ssh`, `snmp`, `syslog` появляются уже на сервере. Их не нужно набивать руками. На образце `render_commands` дал, среди прочего, `min_length: 12`, `lockout: on`, `state: выключен` для SSH, `remote: yes` для syslog, `update_version: 4.2.1-1`. Это иллюстрация образца, не результат стенда.

Каталог для агента без отправки: файлы `*.json` в одном каталоге, `--offline-dir` и `--hostname`. Символические ссылки не читаются.

## Остальные сетевые паки: какой текст принимает код

Общий разборщик — `agent/offline_split.py`. Он не исполняет команды. Один файл до 5 000 000 байт. Архив: не больше 30 записей, каждый член до 5 000 000, распаковка до 20 000 000, архив внутри архива отвергается. Имя файла команды: `offline_file_name`, пробелы и прочие символы вне `A-Za-z0-9.-` становятся `_`, затем `.txt`. Пример: `show running-config` → `show_running-config.txt`.

Форматы, которые код реально отличает. Для каждого ssh-пака из списка `PACKS` в `test_offline_bundle.py` журнал, zip и сокращения команд сверяются с набором файлов одной функцией `test_session_archive_and_abbreviations_match_multifile`. Приглашение в тесте выдумано (`sw-core-01#`). Совпадение доказывает разборщик и фикстуру `base.cli`, не то, что терминал устройства выглядит так же. У Континента команды в фикстуре — уже нормализованный текст ЦУС.

| Формат | Как узнаёт | Для каких паков |
|---|---|---|
| Журнал сессии | Строка начинается с приглашения `host#`, `host>`, `user@host:~$` или `[скобки]#`. Команда после приглашения. Хвост `\| …` отбрасывается. Сокращение Cisco (`sh ver`) раскрывается, если оно однозначно | Любой ssh-пак, чья команда есть в списке ниже и буквально есть в журнале |
| Oxidized | Строка `! Command:` | Если команда из списка |
| RANCID | Строка `!RANCID-CONTENT-TYPE:` | Тело кладётся в `show running-config`, если эта команда паку известна |
| Один текст конфигурации | Отпечаток в `_CONFIG_FINGERPRINTS` | Cisco, Eltex ESR (`#!/usr/bin/clish`), Eltex MES (`passwords complexity enable`), Dionis (`service ssh` и `hostname`), InfoWatch (`set system login password minimum-length` и `set service`), С-Терра (`version`, `crypto isakmp policy`, `gost`) |
| Один вывод detect | Регулярное выражение в `_DETECT_BLOBS` | `show version` / `show system` / `version` из таблицы ниже |
| Архив файлов | Имя члена равно `show_running-config.txt` или без `.txt` | Команды выбранных паков |
| JSON `{команда: текст}` | Все значения — строки | Ключ — команда или её однозначное сокращение |
| JSON ЦУС | Схема раздела Континент | Только `kontinent-4` |

Qtech и SNR по одному `show running-config` не различаются, если в тексте есть и `no telnet-server enable`, и `authentication securityip`. Сайт попросит подтвердить пак. Подсказка в коде: «конфигурация похожа на Qtech или SNR».

UserGate: журнал CLI, архив `show_….txt` или JSON `{команда: текст}`. Ответы XML-RPC в один файл страница не разбирает. Это написано в `_SINGLE_FILE_HINTS`. Живой сбор — `--device-config`, поля `host`, `user`, `password_file`, `hostname`, `ssh_port`, `xmlrpc_port`, `known_hosts` (`agent/deploy/usergate.json.example`). Пароль снова только в отдельном файле.

Команды актуальных ssh-паков (скрипт по YAML 22 ноября 2026, detect, firmware и checks):

| Пак | Команды, которые должны оказаться в файле или в сессии |
|---|---|
| `cisco-ios` 1.3.0 | `show version`, `show running-config` |
| `eltex-esr` 1.0.0 | `show system`, `show running-config` |
| `eltex-mes` 1.0.0 | `show system`, `show version`, `show running-config` |
| `qtech-qsw` 1.0.0 | `show version`, `show running-config` |
| `snr-switch` 1.0.0 | `show version`, `show running-config` |
| `dionis-nx` 1.0.0 | `show version`, `show running-config` |
| `s-terra-gate` 1.0.0 | `show version`, `show running-config` |
| `infowatch-arma-ngfw` 1.0.0 | `show version`, `show configuration commands`, `show configuration` |
| `vipnet-coordinator` 1.0.0 | `version`, `inet show snmp community`, `iplir option get antispoofing`, `iplir option get block-other-protocols`, `machine show loghost`, `machine show session-timeout` |
| `usergate-ngfw` 1.1.0 | `show system version`, `show settings administrators general`, `show network zone`, `show network zone Untrusted`, `show network zone Management`, `show network-policy firewall`, `show logs logs-export` |
| `pt-ngfw` 1.0.0 | только `show version` (инвентаризация, проверок нет) |
| `kontinent-4` 1.1.0 | в файле или в журнале — те же шесть виртуальных `show continent …`. Живой терминал шлюза их не печатает; их строит `render_commands` из JSON ЦУС |

Образец журнала Cisco `docs/how-it-works/samples/cisco-session-min.txt` тем же `split_bytes` дал `session`, пак `cisco-ios`, команды `show version` и `show running-config`. Это проверка разборщика, не прогон оборудования.

Режим «Файл на каждую команду» на той же странице: до 10 файлов, каждый до 5 МБ, поля `commands` и `files` в одном порядке. Имена на диске могут быть любыми: команда передаётся отдельным полем, не выводится из имени. Для Континента этот режим не нужен, если загружается один JSON.

Linux и Windows на эту страницу не загружаются. Их читает агент на самом хосте: файлы, реестр, `secedit`, `auditpol`. Готового «пришлите tar с /etc» для `ubuntu-server` код загрузки не содержит.

Опросные паки `ideco-ngfw`, `pt-ngfw-settings`, `kontinent-4-local` файла конфигурации не принимают. На `main` ответы вводятся на `/manual-scan`. После PR 23 экрана не будет.

## Другие загрузки и выгрузки

### Список компьютеров для охвата

Страница «Агенты», блок охвата. `POST /api/organizations/{org}/expected-hosts`, одно поле файла `file`. До 5 000 000 байт и 50 000 имён. Колонки имени: `name`, `hostname`, `computername`, `computer`, `host`, `dnshostname`, `имя`, `имя компьютера`, `хост`, `компьютер`. ОС: `operatingsystem`, `os`, `ос`, `операционная система`. Последний вход: `lastlogondate`, `lastlogontimestamp`, `lastlogon`, `последний вход`. Колонка `enabled` / `включен` / `включён` со значением false выкидывает строку. Разделитель угадывается среди запятой, точки с запятой и таба. Если заголовка нет, каждая непустая строка — имя.

Команда из комментария `coverage.py`, её не нужно подменять выдуманной:

```text
Get-ADComputer -Filter * -Properties OperatingSystem,LastLogonDate |
  Select-Object Name,DNSHostName,OperatingSystem,LastLogonDate,Enabled |
  Export-Csv computers.csv -NoTypeInformation -Encoding UTF8
```

Образец `docs/how-it-works/samples/expected-hosts-min.csv` функция `parse_host_list` разобрала так: остался `pc-001` с ОС `Windows 10`, `pc-002` отброшен как выключенный (`skipped_disabled` 1). Скачивание с сайта — кнопка «Скачать CSV», разделитель `;`, колонки «Хост», «ОС», «Состояние», «Последний отчёт», «Последний вход (AD)», в начале BOM.

### Файл отчёта агента

`collector.py --out` пишет объект `format: hardening-agent-report`, `version: 1`, `payload` (тот же JSON, что ушёл бы на `/api/ingest`), `signature` — HMAC-SHA256 канонического payload ключом SHA-256 ключа агента. Загрузка: «Агенты» → «Отчёт агента из файла», `POST /api/organizations/{org}/agent-reports`, поле `file`. Это не конфигурация устройства.

### Excel и PDF

Кнопки на прогоне. Колонки листа «Результаты»: Актив, Проверка, Название, Уровень, Статус, Факт, Ожидалось, Срок устранения, Порядок, Как исправить, Пак, Доказательство, Проверено (`snapshot_export.py`). Отдельного CSV всех проверок нет. Страница «Отчёты» файл не отдаёт.

## Что осталось пробелом

- Клики по меню ЦУС и точная команда `c4_config_exporter` в репозитории не записаны. Принимается только JSON описанной формы.
- Родной backup шлюза Континента не поддержан. Журнал поддерживается только если в нём уже есть виртуальные `show continent`, а не команды шлюза. Доказательство — `test_session_archive_and_abbreviations_match_multifile`, не съёмка с устройства.
- Нет серверного опроса устройств по расписанию. Автоматичен только уже установленный агент.
- XML-RPC UserGate на страницу выгрузки не кладётся.
- Выгрузка каталога `/etc` для Linux-паков не принимается.
- Страница опроса на `main` есть; после PR 23 её не будет, а замены в интерфейсе PR не добавляет.
- Браузер по этой главе не прогонялся. Прогнаны разборщик, `render_commands` и `parse_host_list` на трёх образцах.
