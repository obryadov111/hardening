# 🛡️ Харденинг — контроль защищённости конфигураций ИТ-инфраструктуры

**Харденинг** собирает конфигурацию разнородных хостов и сетевых устройств, сравнивает её с
требованиями безопасности и методиками ФСТЭК России и показывает соответствие, его изменение во
времени и что нужно исправить.

```text
агент / выгрузка ──► сервер (FastAPI) ──► PostgreSQL ──► веб-интерфейс (React)
 читает конфигурацию   оценивает по          снимки,         оценка, сравнение,
 по контент-пакам      требованиям паков     история         ФСТЭК, БДУ, отчёты
```

> Это не сетевой сканер и не пентест: система читает настройки изнутри хоста (или из выгрузки
> конфигурации) и проверяет, правильно ли они заданы. Дополнительно версии установленного ПО
> сопоставляются с Банком данных угроз ФСТЭК.

📖 **Как это работает** — справочник для защиты: откуда данные, что с чем сравнивается, как
получается оценка: [`docs/how-it-works.md`](docs/how-it-works.md) и каталог
[`docs/how-it-works/`](docs/how-it-works/README.md).

📖 **Полное описание проекта** — [`docs/project-description.md`](docs/project-description.md).

🌐 **Сетевое оборудование и средства защиты** — [`docs/network-devices.md`](docs/network-devices.md).

---

## Возможности

- **Контент-паки вместо кода.** Платформа описывается YAML-файлом: как её распознать, что прочитать,
  с чем сравнить, критичность, рекомендация, ссылки на пункты методики ФСТЭК. Новая платформа —
  новые данные, агент обновлять не нужно.
- **Агент только читает, сервер оценивает.** Четыре файла на Python без зависимостей (`collector.py`,
  `probes.py`, `usergate.py`, `continent4.py`; Linux, Python 3.6+) или один `.exe` (Windows).
  Подписанные манифесты, белые списки команд, запрет чтения секретов, служба systemd с ФС только на чтение.
- **Сбор:** на самом хосте; устройство по SSH с джамп-хоста (только команды на чтение); UserGate
  (XML-RPC, затем SSH) и Континент 4 (API ЦУС по ГОСТ TLS) тем же установленным агентом; **по выгрузке
  конфигурации** — агентом (`--offline-dir`) или загрузкой файлов в интерфейсе; опрос там, где настройки
  в файле не лежат.
- **Честная оценка.** Соответствие = соблюдено / (соблюдено + нарушено); «не проверено» не
  засчитывается ни в плюс, ни в минус и показывается отдельно как покрытие.
- **Снимки и сравнение** любых двух сканов: исправлено, ухудшилось, появилось, риск принят.
- **Принятый риск** с обоснованием и сроком: нарушение остаётся видимым, но не входит в оценку.
- **Уязвимости ПО по БДУ ФСТЭК** с уровнем критичности V по методике ФСТЭК от 30.06.2025 и
  подтверждением по данным Ubuntu (OVAL Canonical).
- **Покрытие методики ФСТЭК** от 25.11.2025 по 70 пунктам: что соблюдено, нарушено, не применялось,
  вне модели и почему.
- **Сроки устранения** по критичности (24 часа / 7 дней / 4 недели / 4 месяца).
- **Отчёты PDF и Excel** по любому снимку.
- **Несколько организаций** с изоляцией данных, роли, суперадмин, 2FA (TOTP), защита от подбора.
- **Работа через интернет:** агент — только исходящий HTTPS с закреплённым ключом сервера, подписанные
  паки, очередь при обрыве связи; сайт открыт сотрудникам из любой сети с обязательной 2FA, лимитами,
  fail2ban и CSP; агент для Linux и Windows скачивается со страницы «Агенты» (`docs/deploy-server.md`,
  `docs/agent-install.md`).

## Платформы

Подсчёт актуальных версий **1 ноября 2026**: 26 паков, 353 проверки (ещё 17 файлов — прошлые версии
тех же паков). Полная таблица с транспортом и тем, где пак подтверждён, —
[`docs/how-it-works/07-packs.md`](docs/how-it-works/07-packs.md).

| Пак | Платформа и сбор | Проверок | Уровень |
|---|---|---|---|
| `ubuntu-server` 1.4.0 | Ubuntu 20.04 / 22.04 / 24.04, агент на хосте | 25 | **baseline** — Ubuntu 24.04.4 |
| `debian-server` 1.1.0 | Debian 11 / 12 / 13 | 25 | draft — контейнеры в CI |
| `astra-linux` 1.2.0 | Astra Linux SE 1.8 | 25 | draft — контейнер в CI |
| `alt-linux` 1.1.0 | Альт p10 / p11 | 14 | draft — контейнеры в CI |
| `rhel-family` 1.1.0 | РЕД ОС 7.3 / 8, Rocky, Alma, Oracle, CentOS Stream | 19 | draft — контейнеры в CI |
| `windows-server` 1.0.0 | Windows Server 2022 / 2025 | 40 | **baseline** — настоящие серверы в CI |
| `windows-client` 1.0.0 | Windows 10 / 11 | 39 | draft — образцы |
| `windows-dc` 1.0.0 | контроллер домена | 26 | draft |
| `docker` 1.2.0 | Docker Engine | 11 | **baseline** — хост проекта |
| `postgresql` 1.1.0 | файлы PostgreSQL | 9 | draft — образцы |
| `samba` 1.0.0 | Samba | 1 | draft — образцы |
| `cisco-ios` 1.3.0 | Cisco IOS / IOS XE, SSH или выгрузка | 12 | draft — образцы |
| `eltex-esr` 1.0.0 | Eltex ESR, SSH или выгрузка | 16 | draft |
| `eltex-mes` 1.0.0 | Eltex MES, SSH или выгрузка | 10 | draft |
| `qtech-qsw` 1.0.0 | Qtech QSW, SSH или выгрузка | 10 | draft |
| `snr-switch` 1.0.0 | SNR, SSH или выгрузка | 10 | draft |
| `vipnet-coordinator` 1.0.0 | ViPNet Coordinator, SSH или выгрузка | 6 | draft |
| `s-terra-gate` 1.0.0 | С-Терра Шлюз, SSH или выгрузка | 7 | draft |
| `usergate-ngfw` 1.1.0 | UserGate NGFW, XML-RPC и SSH или выгрузка | 12 | draft — формат сверен с лабораторным 7.4.1 |
| `infowatch-arma-ngfw` 1.0.0 | InfoWatch ARMA, SSH или выгрузка | 7 | draft |
| `dionis-nx` 1.0.0 | Dionis-NX, SSH или выгрузка | 9 | draft |
| `pt-ngfw` 1.0.0 | PT NGFW, SSH, только версия | 0 | inventory |
| `pt-ngfw-settings` 1.0.0 | PT NGFW, опрос | 5 | draft |
| `kontinent-4` 1.1.0 | Континент 4, API ЦУС или выгрузка JSON | 6 | draft — формат сверен с лабораторным 4.2.1 |
| `kontinent-4-local` 1.0.0 | Континент 4, опрос BIOS и локального меню | 3 | draft |
| `ideco-ngfw` 1.0.0 | Ideco NGFW, опрос | 6 | draft |

`baseline` требует заполненного `verified_on`. Лабораторные стенды UserGate и Континента дали формат
проверок и фикстуры; в YAML уровень оставлен `draft`, потому что `verified_on` пуст. В CI агент
запускается в 16 Linux-образах и на Windows Server 2022 и 2025.

## Архитектура

| Часть | Стек | Где |
|---|---|---|
| Интерфейс | React 19, Vite, TailwindCSS, React Router, Recharts | `src/` |
| Сервер | FastAPI, SQLAlchemy 2, Alembic, PostgreSQL 15 | `src/backend/` |
| Агент | Python, только стандартная библиотека; Windows — PyInstaller | `agent/` |
| Развёртывание | Docker, nginx без root, systemd, GitHub Actions | `deploy/`, `agent/deploy/`, `.github/workflows/` |

```mermaid
flowchart LR
    B[Браузер] -->|":443 HTTPS"| N["frontend nginx"]
    RA[Удалённый агент] -->|":443 /api"| N
    N --> BE["backend FastAPI"]
    LA[Агент на сервере] -->|"127.0.0.1:8000"| BE
    BE --> DB[("PostgreSQL")]
```

Порт 80 после включения HTTPS только перенаправляет на 443 (`deploy/enable_https.sh`). До включения
домена nginx слушает 80 без TLS. Агент на не-localhost по HTTP не ходит без явного `--allow-http`.

```text
agent/                  агент: collector.py, probes.py, usergate.py, continent4.py, служба (deploy/), тесты
src/                    интерфейс: pages/, components/, api/, utils/
src/backend/app/        сервер: api/routes/, models/, services/, packs/ (YAML), commands/
src/backend/alembic/    миграции схемы
src/backend/pack_tests/ фикстуры паков «нарушение / соблюдение»
deploy/                 nginx.conf, скрипты выкатки, обновление БДУ
docs/                   полное описание проекта, архитектура паков
```

## Запуск для разработки

```bash
# сервер
cd src/backend
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
cp .env.example .env           # DATABASE_URL, JWT_SECRET_KEY, TOTP_SECRET_ENCRYPTION_KEY, PACK_SIGNING_KEY
.venv/bin/alembic upgrade head
.venv/bin/python -m app.commands.create_admin        # первый суперадмин
.venv/bin/uvicorn app.main:app --reload

# интерфейс (Vite проксирует /api на localhost:8000)
npm install && npm run dev
```

Ключ агента для организации: `python -m app.commands.create_agent_key` (показывается один раз).

## Агент

```bash
# служба на Linux-хосте
sudo ./agent/deploy/install.sh                          # /opt/hardening-agent, пользователь hardening-agent
sudo nano /etc/hardening-agent/local.env                # адрес сервера, ключ агента, ключ подписи паков
sudo systemctl start hardening-agent@local              # пробный прогон
sudo systemctl enable --now hardening-agent@local.timer # ежедневно

# сетевое устройство по SSH (с джамп-хоста, учётка только на чтение)
python3 agent/collector.py --api-url https://… --environment net --use-packs \
  --ssh-host 10.0.0.1 --ssh-user audit --ssh-key ~/.ssh/audit_ed25519

# UserGate или Континент 4: JSON цели, пароль лежит отдельно и в аргументы не попадает
python3 agent/collector.py --api-url https://… --environment net --use-packs \
  --device-config /etc/hardening-agent/usergate.json

# по выгрузке конфигурации: каталог файлов или один журнал/архив/JSON
python3 agent/collector.py --api-url https://… --environment net --use-packs \
  --offline-dir ./export-sw-core-01 --hostname sw-core-01
python3 agent/collector.py --api-url https://… --environment net --use-packs \
  --offline-file ./session.log --hostname sw-core-01
```

Подробно — [`agent/README.md`](agent/README.md), включая Windows.
Раскатка на компьютеры домена через GPO — [`docs/gpo-rollout.md`](docs/gpo-rollout.md):
исключение Kaspersky, Континент 4, NETLOGON, пакет со страницы «Агенты».

## Тесты

```bash
# сервер — только на одноразовой БД (тесты очищают таблицы), не на боевой
cd src/backend && DATABASE_URL=postgresql+psycopg://postgres:postgres@localhost:5433/app_test_db .venv/bin/pytest tests
pytest agent/tests                                                    # агент
cd src/backend && python -m app.commands.pack validate && python -m app.commands.pack test   # паки
npm run lint && npm run test:unit && npm run build                    # интерфейс: линтер, утилиты, сборка

# сквозные тесты интерфейса (Playwright): бэкенд и Vite поднимаются сами, БД — своя одноразовая,
# не та, что у pytest (засев стирает её): каждая страница, кнопка и роль.
# Подсчёт 1 ноября 2026: 134 теста (70 вызовов test(), часть раскрывается циклами ролей и страниц)
E2E_DATABASE_URL=postgresql+psycopg://postgres:postgres@localhost:5433/app_e2e_db npm run test:e2e
```

Подсчёт тестов на 1 ноября 2026: `pytest --collect-only` дал 629 кейсов бэкенда и 300 кейсов агента,
`npx playwright test --list` — 134 сквозных, в `utils.test.js` — 7. Подробности —
[`docs/how-it-works/23-tests-ci.md`](docs/how-it-works/23-tests-ci.md).

Нагрузка: `tools/loadtest/ui_load.py` — засев N хостов (ПО как на хосте, настоящие пробы агента) и замер
API каждой страницы; приём отчётов от 1000 хостов — заметка «Агент на 1000+ хостов» в репозитории диплома.

CI на каждый push: тесты сервера (ruff, pytest) и агента, линтер, юнит-тесты и сборка интерфейса, сквозные
тесты в Chromium, shellcheck скриптов, агент внутри 16 Linux-систем и на настоящих Windows Server 2022 / 2025.

## Развёртывание

```bash
# перед выкаткой: дамп БД и метки на текущие образы для отката
docker exec diploma_db pg_dump -Fc -U postgres app_db > ~/backups/app_db-pre-<изменение>.dump
docker tag hardening-backend:latest hardening-backend:pre-<изменение>

# сервер: образ (пробы агента — отдельным контекстом), миграции одноразовым контейнером, перезапуск
docker build --build-context agent=./agent -t hardening-backend:latest ./src/backend
docker run --rm --network diplom-hardening_default --env-file ./src/backend/.env hardening-backend:latest alembic upgrade head
./deploy/restart_backend.sh

# интерфейс: nginx без root. После enable_https.sh снаружи 443, порт 80 только перенаправляет
./deploy/restart_frontend.sh

# копия БДУ ФСТЭК и данных Ubuntu (OVAL)
./deploy/update_bdu.sh
```

Сервер слушает только `127.0.0.1:8000`, снаружи — через nginx. Все контейнеры с лимитами ресурсов и
`no-new-privileges`.

## Пример: реальный сервер «до → после»

Агент на сервере проекта (Ubuntu 24.04 + Docker):

| Скан | Что сделано | Оценка |
|---|---|---|
| 1 | исходное состояние | 21 % |
| 2 | SSH, ufw, auditd | 57 % |
| 3 | агенту дан доступ к Docker | 71 % |
| 4 | парольная политика, faillock | 90 % |
| позже | no-new-privileges, изоляция контейнеров, запрет USB-накопителей, удалён xrdp; принят риск по `ip_forward` и порту фронтенда | **97 %** |

Осталось одно нарушение — вход по паролю в SSH (до настройки ключей).

## Дипломная работа

> **Систематизация и автоматизация харденинга информационной инфраструктуры**

Проект показывает контроль конфигураций для разных платформ, включая российские ОС и сетевое
оборудование; привязку проверок к методикам ФСТЭК России; проверку на реальной инфраструктуре — от
сбора данных до отчёта и сравнения «до / после».
