# 23. Тесты и CI

## Зачем нужно

Цифра в дипломе должна совпадать с командой, которую можно повторить на том же коммите. Ниже три слоя, и их нельзя смешивать.

1. **Эта сверка, 22 ноября 2026**, дерево `main` коммит `1a5997df9bb0573b1265724828be061b6603be20`. Команды выполнены здесь. PostgreSQL в среде не было, браузер не открывался, продакшен не трогался.
2. **CI GitHub на этом же коммите.** Статусы прочитаны через API 22 ноября 2026, прогоны заново не запускались. Это доказательство, что на push коммита проверки были зелёные, а не что они зелёные на любой будущей машине.
3. **Исторические сообщения** (лаборатория UserGate и Континента, раскатка GPO, ночные отчёты). В репозитории и в этой сверке они не воспроизводились. Они вынесены в [главу 24](24-history-limits.md) и не входят в таблицу «выполнено».

## Что посчитано и что выполнено 22 ноября 2026

| Команда | Результат | Что это доказывает | Чего не доказывает |
|---|---|---|---|
| `pytest tests --collect-only -q` в `src/backend` при `DATABASE_URL`, `JWT_SECRET_KEY`, `TOTP_SECRET_ENCRYPTION_KEY`, `PACK_SIGNING_KEY` | `670 tests collected` | Столько кейсов импортируется | Что они проходят. Сбор не открывает PostgreSQL, но и не выполняет assertions |
| `pytest agent/tests --collect-only -q` | `334 tests collected` | Столько кейсов агента | — |
| `pytest agent/tests -q` | `332 passed, 2 skipped` за ~24 с | Агентские тесты на CPython 3.12 этой среды проходят | Windows: два теста пропущены, см. ниже. Не доказывает живой стенд |
| `python -m app.commands.pack validate` в `src/backend` | `Ошибок: 0, предупреждений: 8` | Схема, ссылки, имя файла, регрессии между версиями | Что пак верен на устройстве |
| `python -m app.commands.pack test` | 26 файлов `pack_tests/*.yaml`, все сценарии сошлись (от 2/2 у Ideco до 23/23 у `rhel-family`) | Фикстура гоняет пробы агента и `evaluate_pack` | Живое устройство |
| `TZ=Asia/Yekaterinburg node --test src/utils/utils.test.js src/utils/gpoPackage.test.js` | `15` pass, `0` fail | Утилиты дат, оценки, ролей, пакета GPO | Страницы React. Без `TZ` три теста дат падают: ожидание написано для Екатеринбурга (UTC+5), среда по умолчанию была UTC |
| `npx playwright test -c e2e/playwright.config.js --list` | `Total: 135 tests in 9 files` | Столько тестов видит сборщик, включая циклы по ролям и страницам | Что браузер их проходит. Браузер в этой сверке не запускался |
| `ruff check` по `src/backend/app` и `src/backend/tests` | `All checks passed` | Стиль этих каталогов на момент сверки | Агент и скрипты shell |

Пропущенные тесты агента, оба с явной причиной в коде:

- `agent/tests/test_windows_probes.py`: «настоящий secedit/auditpol есть только на Windows»
- там же: «настоящий PowerShell есть только на Windows»

Предупреждения `pack validate` (не ошибки): удалены проверки при переходе `cisco-ios` 1.0.0→1.1.0 (`enable_secret_used`, `vty_ssh_only`), `kontinent-4` 1.0.0→1.1.0 (`bios_password_changed`, `inactivity_timeout`, `loader_password_changed`), `ubuntu-server` 1.1.0→1.2.0 (`filesharing.smb_no_guest_access`); у `firewall.ufw_enabled` и `ssh.permit_root_login` критичность `critical` сменилась на `high`.

Старый текст этой главы называл 629, 300 и 134 на 1 ноября 2026. На коммите `1a5997d` сборщик печатает **670**, **334** и **135**. Разница — тесты, добавленные после той даты (прогоны, один файл выгрузки, GPO, Континент). Называть 629 как текущее число нельзя.

Юнит-тесты интерфейса раньше считали только 7 функций в `utils.test.js`. Файл `gpoPackage.test.js` добавляет 8. Вместе скрипт `npm run test:unit` (`src/**/*.test.js`) даёт 15.

## CI на коммите main

`GET /repos/obryadov111/hardening/commits/1a5997df9bb0573b1265724828be061b6603be20/check-runs` 22 ноября 2026: `total_count` 24, все `conclusion=success`. Имена: матрица Linux (16 образов из таблицы ниже), `live (windows-2022)`, `live (windows-2025)`, `exe`, `pytest`, `playwright`, `lint-and-build`, `python36-rocky8`, `shellcheck`. Запуски датированы 2026-11-08. Повторно они здесь не гонялись.

Workflow не стартует на правке только `docs/`: у каждого файла в `.github/workflows/` фильтр `paths`. Зелёный бейдж после этой документации сам не появится.

| Файл | Когда | Что делает |
|---|---|---|
| `backend-tests.yml` | `src/backend/**` | ruff и pytest на PostgreSQL 15 |
| `agent-tests.yml` | `agent/**` | pytest на Python 3.12 и системным Python 3.6 в контейнере Rocky Linux 8 |
| `frontend-ci.yml` | `src/**` кроме бэкенда | ESLint, `npm run test:unit`, сборка |
| `e2e.yml` | `src/**`, `agent/**`, `e2e/**` | Playwright и Chromium против API и одноразовой базы. Ошибка в консоли или ответ 5xx роняют тест |
| `shell.yml` | `*.sh` | shellcheck скриптов `deploy/` и `agent/deploy/install.sh` |
| `linux-packs.yml` | агент и паки ОС | агент внутри контейнера, результат оценивает `pack evaluate` |
| `windows-packs.yml` | агент, паки Windows, `deploy/windows/gpo/**` | прогон на раннере, сборка exe, регистрация по подписанным манифестам, сценарий GPO |
| `windows-release.yml` | теги `agent-*` и `v*`, не каждый push | собирает `hardening-agent.exe` и прикладывает к GitHub Release. В git файла нет |

Образы `linux-packs.yml`, 16 строк. Это контейнеры официальных образов, не виртуальные машины и не установленные серверы:

Ubuntu 20.04, 22.04, 24.04; Debian 11, 12, 13; Astra SE 1.8 (`registry.astralinux.ru/library/astra/ubi18:latest`); Альт p10 и p11; Rocky 8 и 9; Alma 9; Oracle Linux 9; CentOS Stream 9; РЕД ОС 7.3 и 8 (`registry.red-soft.ru/ubi7` и `ubi8`).

Пак в контейнере: Ubuntu → `ubuntu-server`, Debian → `debian-server`, Astra → `astra-linux`, Альт → `alt-linux`, остальные → `rhel-family`.

В контейнере нет рабочего systemd. Проверки служб там «не проверено». Workflow разрешает это флагами `--allow-missing-command systemctl`, `--allow-missing-command modprobe`, `--allow-error-matching "not been booted with systemd"` и списками `--allow-error` (например `logging.auditd_active`). Это не подмена ожидаемого `pass`.

Windows: отдельные прогоны `windows-2022` и `windows-2025` для пака `windows-server`. Раннер — рядовой сервер, не контроллер домена: job падает, если распознаны `windows-client` или `windows-dc` либо не распознан `windows-server`. Поэтому `windows-dc` и `windows-client` из этого job baseline не становятся. Сборка exe — job на `windows-2022`.

`pack test` требует, чтобы каждая проверка актуального пака была показана и в `pass`, и в `fail`. Это проверяет тест `test_every_check_is_shown_both_failing_and_passing`.

Сквозной стык агента и сервера без браузера — `src/backend/tests/test_agent_interop.py`. Он входит в 670 собранных кейсов бэкенда и в этой сверке не исполнялся.

Нагрузка страниц — `tools/loadtest/ui_load.py`. В этой сверке он не запускался. Генератора шторма приёма в каталоге нет. Массовый охват тысяч хостов отсюда не следует.

## Где в коде

Каталоги: `src/backend/tests/`, `agent/tests/`, `e2e/tests/`, `src/utils/utils.test.js`, `src/utils/gpoPackage.test.js`, `.github/workflows/`.

## Ограничения

- Pytest бэкенда и Playwright здесь не исполнялись: нет PostgreSQL и не поднимался браузер.
- Контейнерный прогон Linux не доказывает службы, модули ядра и «боевую» установку дистрибутива.
- Сетевые паки в `linux-packs` не гоняются: устройств в CI нет. Их держат фикстуры и `agent/tests/test_usergate.py`, `test_continent4.py`, `test_offline_split.py`.
- Два пропуска агента на Linux ожидаемы и не заменяют Windows-прогон. Windows-прогон есть в CI коммита, локально он не повторялся.

## Вопросы на защите

**На каких ОС агент запускался в CI этого коммита?** Шестнадцать контейнерных образов Linux и Windows Server 2022 и 2025 (раннеры GitHub, не стенд заказчика). Плюс тесты агента на Python 3.6 в образе Rocky 8. Статусы прочитаны из GitHub, не перезапускались 22 ноября.

**Почему в контейнере часть проверок «не проверено»?** Нет systemd. Workflow это разрешает флагом, а не записывает `pass`.

**Сколько тестов называть?** На коммите `1a5997d`, подсчёт 22 ноября 2026: бэкенд — 670 собранных кейсов (прогон не делался), агент — 334 собранных и 332 прошедших плюс 2 пропуска, список Playwright — 135 (браузер не запускался), утилиты интерфейса — 15 прошедших. Рядом стоит сказать метод: `pytest --collect-only` и `playwright test --list`, а не число файлов.
