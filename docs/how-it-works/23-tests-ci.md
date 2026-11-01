# 23. Тесты и CI

## Зачем нужно

Цифры в дипломе должны совпадать с репозиторием. Подсчёт **1 ноября 2026** сделан командами, не оценкой на глаз:

- `pytest tests --collect-only -q` в `src/backend` напечатал `629 tests collected`. База не открывалась: сбор только импортирует тесты.
- `pytest agent/tests --collect-only -q` напечатал `300 tests collected`.
- `npx playwright test --list` напечатал `Total: 134 tests in 9 files`.

Разбор AST дал те же 629 и 300. Утилиты интерфейса — 7 функций `test()` в `src/utils/utils.test.js`.

| Набор | Как считали | Число |
|---|---|---|
| Бэкенд `src/backend/tests/` | `pytest --collect-only -q` | **629** |
| Агент `agent/tests/` | `pytest --collect-only -q` | **300** |
| Playwright `e2e/tests/*.spec.js` | `npx playwright test --list` | **134** |
| `src/utils/utils.test.js` | функции `test()` node:test | **7** |
| Фикстуры паков | файлы `src/backend/pack_tests/*.yaml` | **26** |
| Миграции | файлы в `alembic/versions` | **19** |

Старые тексты называли около 125 сквозных тестов и 603 теста бэкенда. Сейчас сборщик печатает 134 и 629. Разница с 603 — тесты UserGate, Континента и parametrize по всем пакам, которые появились после той оценки.

## Что проверяет каждый workflow

Все workflow в `.github/workflows/` срабатывают по своим путям, не на любой push. Правка только `docs/` их не запускает.

| Файл | Когда | Что делает |
|---|---|---|
| `backend-tests.yml` | `src/backend/**` | ruff и pytest на PostgreSQL 15 |
| `agent-tests.yml` | `agent/**` | pytest на Python 3.12 и ещё раз системным Python 3.6 в контейнере Rocky Linux 8 |
| `frontend-ci.yml` | `src/**` кроме бэкенда | ESLint, `npm run test:unit`, сборка |
| `e2e.yml` | `src/**`, `agent/**`, `e2e/**` | Playwright и Chromium против настоящего API и одноразовой базы. Ошибка в консоли или ответ 5xx роняют тест |
| `shell.yml` | любые `*.sh` | shellcheck скриптов `deploy/` и `agent/deploy/install.sh` |
| `linux-packs.yml` | агент и паки ОС | агент внутри контейнера, результат оценивает `pack evaluate` |
| `windows-packs.yml` | агент и паки Windows | живой прогон на раннере, сборка exe, регистрация по подписанным манифестам, сценарий GPO |

Образы Linux в матрице `linux-packs.yml`, 16 строк:

Ubuntu 20.04, 22.04, 24.04; Debian 11, 12, 13; Astra SE 1.8; Альт p10 и p11; Rocky 8 и 9; Alma 9; Oracle Linux 9; CentOS Stream 9; РЕД ОС 7.3 и 8.

Пак в контейнере: Ubuntu → `ubuntu-server`, Debian → `debian-server`, Astra → `astra-linux`, Альт → `alt-linux`, остальные → `rhel-family`.

В контейнере нет рабочего systemd. Проверки служб там «не проверено». Workflow разрешает это флагами `--allow-missing-command` и списками id вроде `logging.auditd_active`, а не подменой ожидаемого `pass`.

Windows: отдельные прогоны `windows-2022` и `windows-2025` для пака `windows-server`. Раннер — рядовой сервер (`ProductType=ServerNT`), не контроллер домена, поэтому `windows-dc` там не становится baseline. Сборка exe — job на `windows-2022`.

`pack test` гоняет фикстуры: каждая проверка актуального пака должна быть показана и в `pass`, и в `fail`. Это требование команды автора, его проверяет тест `test_every_check_is_shown_both_failing_and_passing`.

Сквозной стык агента и сервера без браузера — `src/backend/tests/test_agent_interop.py`: подписанный манифест, настоящий агент, `POST /ingest`, оценка.

Нагрузка страниц — `tools/loadtest/ui_load.py`. Генератора шторма приёма в этом каталоге нет.

## Где в коде

Каталоги: `src/backend/tests/`, `agent/tests/`, `e2e/tests/`, `src/utils/utils.test.js`, `.github/workflows/`.

## Ограничения

- CI на документацию не настроен. Зелёный бейдж после правки только markdown сам не появится.
- Число 629 подтверждено `pytest --collect-only`, не только разбором AST. Это число собранных кейсов, а не число файлов.
- Сетевые паки в linux-packs не гоняются: там нет устройств. Их держат фикстуры `pack_tests` и тесты `agent/tests/test_usergate.py`, `test_continent4.py`.

## Вопросы на защите

**На каких ОС агент реально запускался в CI?** Шестнадцать образов Linux из матрицы и Windows Server 2022 и 2025. Плюс тесты агента на Python 3.6 Rocky 8.

**Почему в контейнере часть проверок «не проверено»?** Нет systemd. Это ожидаемо и разрешено workflow, а не спрятано.

**Сколько тестов называть?** Бэкенд — 629 кейсов при подсчёте 1 ноября 2026, агент — 300, сквозные — 134, утилиты интерфейса — 7. Рядом стоит сказать, что это подсчёт по коду, и при желании показать вывод pytest.
