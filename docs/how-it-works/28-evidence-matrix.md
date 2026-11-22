# 28. Матрица платформ и доказательств

Сверка **22 ноября 2026**, коммит `1a5997df9bb0573b1265724828be061b6603be20`.

Метод строк пака: скрипт на PyYAML читает `src/backend/app/packs/*.yaml`. Актуальная версия — максимум кортежа `version` внутри одного поля `pack`. Число проверок — `len(checks)` этой версии. `verified_on` цитируется из того же файла. Фикстура — файл `src/backend/pack_tests/<pack>.yaml` (26 файлов, по одному на id). CI — матрица `.github/workflows/linux-packs.yml` и `windows-packs.yml` плюс статусы check-runs коммита (все 24 в выборке API — `success`, повторно не запускались).

Класс сбора, чтобы не назвать инвентаризацию «проверкой конфигурации»:

| Класс | Что делает система |
|---|---|
| Аудит конфигурации | Проба читает факт, `evaluate_pack` сравнивает с `assert` |
| Только инвентаризация | `maturity: inventory`, `checks` пуст: узнавание и версия для БДУ |
| Опрос | `transport: manual`, отвечает человек, сервер всё равно сравнивает |
| Выгрузка | Те же ssh-пробы по файлам, без живого устройства (`OfflineConfigTransport`, `--offline-file`) |

Контейнер GitHub — не установленная ОС и не виртуальная машина заказчика. `baseline` в модели `Pack` требует непустой `verified_on`. Пустое поле оставляет `draft`, даже если лабораторный формат сверяли.

## Матрица

Права и предпосылки — по типу транспорта, не по отдельному стенду. `local`: агент на хосте, чтение файлов и белый список команд; Windows secpol/auditpol обычно нужны права администратора. `ssh`: учётная запись только на чтение, `BatchMode`, команда проходит `is_readonly_cli`. `manual`: прав на устройство у агента нет, отвечает администратор организации в интерфейсе.

| Пак и версия | Проверок | Класс | Сбор | Фикстура | CI на `1a5997d` | Живой стенд, подтверждённый этой сверкой | Ограничение |
|---|---|---|---|---|---|---|---|
| `ubuntu-server` 1.4.0 | 25 | аудит | local, файлы и команды | да | контейнеры ubuntu 20.04/22.04/24.04, `success` | нет. В YAML `verified_on`: Ubuntu 24.04.4 LTS — запись автора, машина 22 ноября не смотрелась | службы в контейнере могут быть `error` (`logging.auditd_active` в allow-списке) |
| `debian-server` 1.1.0 | 25 | аудит | local | да | контейнеры debian 11/12/13 | нет | `draft`, нет `verified_on` |
| `astra-linux` 1.2.0 | 25 | аудит | local | да | контейнер Astra ubi18 | нет | образ реестра, не установка SE на железе |
| `alt-linux` 1.1.0 | 14 | аудит | local | да | контейнеры alt p10 и p11 | нет | `draft` |
| `rhel-family` 1.1.0 | 19 | аудит | local | да | Rocky 8/9, Alma 9, Oracle 9, CentOS Stream 9, РЕД ОС ubi7 и ubi8 | нет | нет systemd: firewalld, auditd, telnet в allow-error |
| `windows-server` 1.0.0 | 40 | аудит | local, реестр, secedit, auditpol | да | раннеры windows-2022 и windows-2025, job `live`, `success` | нет отдельного стенда заказчика. `verified_on` называет эти раннеры | раннер — рядовой сервер, не контроллер домена |
| `windows-client` 1.0.0 | 39 | аудит | local | да | нет отдельного job: на раннере сервера пак не должен распознаться | нет | `draft`, образцы |
| `windows-dc` 1.0.0 | 26 | аудит | local, в том числе `win_ad` | да | на раннере сервера распознавание было бы провалом job | нет | LDAP-пробы на не-DC не становятся baseline |
| `docker` 1.2.0 | 11 | аудит | local, `cmd_foreach` | да | отдельного образа Docker в матрице нет | нет. YAML `verified_on`: Docker Engine 29.3.1 на Ubuntu 24.04.4 LTS | запись в файле, хост 22 ноября не проверялся |
| `postgresql` 1.1.0 | 9 | аудит файлов | local, файлы конфига | да | нет | нет | комментарий пака: SQL-проверки ФСТЭК не реализованы |
| `samba` 1.0.0 | 1 | аудит файла | local | да | нет | нет | одна проверка, не полный разбор Samba |
| `cisco-ios` 1.3.0 | 12 | аудит | ssh или выгрузка | да | нет устройства в CI | нет | `draft` |
| `eltex-esr` 1.0.0 | 16 | аудит | ssh или выгрузка | да | нет | нет | `draft` |
| `eltex-mes` 1.0.0 | 10 | аудит | ssh или выгрузка | да | нет | нет. Комментарий YAML: фикстура включает конфигурацию MES2324 из открытого репозитория; «на живом коммутаторе пак не запускался» | не называть это стендом |
| `qtech-qsw` 1.0.0 | 10 | аудит | ssh или выгрузка | да | нет | нет | `draft` |
| `snr-switch` 1.0.0 | 10 | аудит | ssh или выгрузка | да | нет | нет | `draft` |
| `vipnet-coordinator` 1.0.0 | 6 | аудит | ssh или выгрузка | да | нет | нет | `draft` |
| `s-terra-gate` 1.0.0 | 7 | аудит | ssh или выгрузка | да | нет | нет | `draft` |
| `infowatch-arma-ngfw` 1.0.0 | 7 | аудит | ssh или выгрузка | да | нет | нет | `draft` |
| `dionis-nx` 1.0.0 | 9 | аудит | ssh или выгрузка | да | нет | нет | `draft` |
| `usergate-ngfw` 1.1.0 | 12 | аудит | XML-RPC и SSH либо выгрузка | да | нет устройства в CI. Тесты агента на фикстурах входят в локальный прогон 22 ноября | нет. Лаборатория UGOS 7.4.1.341220R — история PR 17, не повтор 22 ноября. `verified_on` пуст | уровень `draft` |
| `kontinent-4` 1.1.0 | 6 | аудит | API ЦУС, текст как CLI, либо JSON-выгрузка | да | нет устройства в CI | нет. Лаборатория 4.2.1-653 — история PR 17. `verified_on` пуст | `draft`. BIOS и пароль загрузчика сюда не входят |
| `kontinent-4-local` 1.0.0 | 3 | опрос | manual | да | нет | нет | не чтение конфигурации |
| `ideco-ngfw` 1.0.0 | 6 | опрос | manual | да | нет | нет | не чтение конфигурации |
| `pt-ngfw-settings` 1.0.0 | 5 | опрос | manual | да | нет | нет | не чтение конфигурации |
| `pt-ngfw` 1.0.0 | 0 | инвентаризация | ssh, detect и прошивка | да | нет | нет | комментарий пака: CLI не показывает настройки, API без стенда был бы догадкой |

Сумма проверок актуальных версий: 353. Транспорт: 11 `local`, 12 `ssh`, 3 `manual`. Зрелость: 3 `baseline` (`ubuntu-server`, `docker`, `windows-server`), 1 `inventory`, остальные `draft`.

## Четыре проверки разных типов

Примеры взяты из YAML, не из выдуманного отчёта. Ожидаемый `pass`/`fail` на образце лежит в `pack_tests/`, а не в этой таблице.

### Файл на хосте: `ssh.permit_root_login`

Файл `src/backend/app/packs/ubuntu-server-1.4.0.yaml`. Проба `file_kv`, путь `/etc/ssh/sshd_config`, ключ `PermitRootLogin`, `follow_include: true`, `default: prohibit-password`. Утверждение `eq` / `no`. Ссылки методики `ОПС.1.10` и `СУД.1.1` должны дословно совпасть с `SOURCE` в `fstec/catalog.py`.

Цепочка: `probe_file_kv` → поле `probe_results["ssh.permit_root_login"]` → `evaluate_pack` → `check_assertion`. Нет файла и нет default, который проба смогла подставить, — `found: false` и статус `error`, не `fail`. Комментарий в паке прямо пишет, почему default не `no`: у OpenSSH по умолчанию `prohibit-password`.

### Политика Windows: `win.password_min_length`

Файл `windows-server-1.0.0.yaml`. Проба `win_secpol`, ключ `MinimumPasswordLength`. Оператор `gte`, значение 14. На Linux-агенте живой `secedit` не вызывается: соответствующий тест пропускается. На раннере CI job `live` вызывает `pack live --pack windows-server`.

### Устройство, команда только на чтение: `usergate_ngfw.admin_strong_password`

Файл `usergate-ngfw-1.1.0.yaml`. Проба `cli_config`, команда `show settings administrators general`, `assert` `eq` / `on`. Исполнитель — `UserGateTransport` или `OfflineConfigTransport`, не произвольный shell. Серверная модель отдельно запрещает не-readonly CLI (`CLI_READONLY_RE` в `services/packs/models.py`).

### Опрос: `ideco_ngfw.web_external_access`

Файл `ideco-ngfw-1.0.0.yaml`. Проба `manual`, вопрос про опцию веб-интерфейса, `assert` `eq` / `yes`. Агент этот тип не исполняет: в словаре `PROBES` его нет. Ответ сохраняет маршрут ручного скана, сравнение делает тот же `evaluate_pack`. Это не аудит файла.

### Инвентаризация без оценки: `pt-ngfw`

Файл `pt-ngfw-1.0.0.yaml`, `checks: []`. Процент по пустому списку проверок не считается: `compute_compliance_score` возвращает `None`, если нет ни `pass`, ни учитываемого `fail`.

### Континент, факт из API, форма как CLI: `kontinent4.password_min_length`

Файл `kontinent-4-1.1.0.yaml`. Проба `cli_config`, команда `show continent password-policy`, оператор `gte` / 8. На живом ЦУС транспорт рендерит ответ API в текст, который эта проба разбирает. В выгрузке JSON тот же разбор идёт из файла. Оба пути оценивает один `assert`.

## Операторы и типы проб

В коде кортеж `OPERATORS` в `services/packs/assertions.py`: `eq`, `ne`, `in`, `not_in`, `lt`, `lte`, `gt`, `gte`, `between`, `regex`, `exists`, `absent`, `mode_within` — 13 имён.

В актуальных проверках встретились 11. Не встретились `lt` и `gt`. Счётчик по полю `assert.op`: `eq` 150, `exists` 61, `absent` 37, `in` 27, `gte` 21, `mode_within` 12, `lte` 12, `regex` 11, `ne` 11, `between` 9, `not_in` 2.

Типы проб на верхнем уровне проверки: `cli_config` 94, `file_kv` 47, `reg_value` 34, `file_regex` 33, `service_state` 26, `win_secpol` 20, `win_auditpol` 17, `first_of` 16, `win_ad` 15, `manual` 14, `file_stat` 12, `cli_blocks` 11, `cmd_foreach` 9, `cmd_regex` 5. `pkg_version` есть в `PROBES` и в актуальных паках не используется.

Критичность в актуальных проверках: `medium` 154, `high` 117, `low` 64, `critical` 18. Сумма 353. Срок на экране берётся из `REMEDIATION_BY_SEVERITY` в `src/utils/remediation.js` и только для статуса `fail`. Комментарий файла: уровень — оценка автора пака, не рассчитанный показатель V.

## Ключевые каталоги

| Путь | Назначение | Кто вызывает |
|---|---|---|
| `agent/collector.py` | CLI, enrollment, очередь, сборка payload | systemd, GPO, человек |
| `agent/probes.py` | типы проб, подпись манифеста, выбор пака | `collector.py` при `--use-packs` |
| `agent/usergate.py`, `agent/continent4.py` | транспорты устройств | `collector.py` по `--device-config` |
| `agent/offline_split.py` | один файл выгрузки → команды | `--offline-file` |
| `src/backend/app/main.py` | приложение FastAPI | uvicorn |
| `src/backend/app/api/routes/ingest.py` | `ingest_payload` | `POST /api/ingest` и загрузки из UI |
| `src/backend/app/services/packs/evaluate.py` | `evaluate_pack` | приём |
| `src/backend/app/services/packs/assertions.py` | `check_assertion` | `evaluate_pack` |
| `src/backend/app/services/hardening_engine.py` | `compute_compliance_score`, `compute_coverage` | приём и отчёты |
| `src/backend/app/packs/*.yaml` | нормы | `load_registry` |
| `src/backend/app/services/fstec/catalog.py` | 70 пунктов модели | `GET .../fstec-coverage` |
| `src/backend/app/services/bdu/criticality.py` | формула V | страница уязвимостей |
| `src/pages/*.jsx` | маршруты интерфейса | `src/App.jsx` |
| `deploy/`, `agent/deploy/` | nginx, публикация, служба | оператор, не при каждом запросе |
| `.github/workflows/` | CI по путям | GitHub Actions |

Полная пофайловая карта ноября — [глава 26](26-module-map.md). Она не переписывалась построчно 22 ноября.
