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

📖 **Полное описание проекта** — как работает каждая функция, интеграция и технический момент:
[`docs/project-description.md`](docs/project-description.md).

---

## Возможности

- **Контент-паки вместо кода.** Платформа описывается YAML-файлом: как её распознать, что прочитать,
  с чем сравнить, критичность, рекомендация, ссылки на пункты методики ФСТЭК. Новая платформа —
  новые данные, агент обновлять не нужно.
- **Агент только читает, сервер оценивает.** Два файла на Python без зависимостей (Linux, Python 3.6+)
  или один `.exe` (Windows). Подписанные манифесты, белые списки команд, запрет чтения секретов,
  служба systemd с ФС только на чтение.
- **Три способа сбора:** на самом хосте; сетевое устройство по SSH с джамп-хоста (только команды на
  чтение); **по выгрузке конфигурации** — агентом (`--offline-dir`) или загрузкой файлов в интерфейсе,
  для устройств без доступа и вендоров без стенда.
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

## Платформы

| Пак | Платформы | Проверок | Уровень |
|---|---|---|---|
| `ubuntu-server` | Ubuntu 20.04 / 22.04 / 24.04 | 25 | **baseline** — реальный хост |
| `debian-server` | Debian 11 / 12 / 13 | 25 | draft — контейнеры в CI |
| `astra-linux` | Astra Linux SE 1.8 | 25 | draft — контейнер в CI |
| `alt-linux` | Альт p10 / p11 | 14 | draft — контейнеры в CI |
| `rhel-family` | РЕД ОС 7.3 / 8, Rocky, Alma, Oracle Linux, CentOS Stream, RHEL | 19 | draft — контейнеры в CI |
| `windows-server` | Windows Server 2022 / 2025 | 40 | **baseline** — настоящие серверы в CI |
| `windows-client` | Windows 10 / 11 | 39 | draft — образцы |
| `docker` | Docker Engine | 11 | **baseline** — реальный хост |
| `postgresql` | PostgreSQL | 9 | draft — образцы |
| `cisco-ios` | Cisco IOS / IOS XE (SSH или выгрузка) | 12 | draft — образцы |
| `samba` | Samba | 1 | draft — образцы |

11 паков, 220 проверок, 18 систем в CI. `baseline` — подтверждено на реальной системе, `draft` —
в контейнерах или на образцах вывода.

## Архитектура

| Часть | Стек | Где |
|---|---|---|
| Интерфейс | React 19, Vite, TailwindCSS, React Router, Recharts | `src/` |
| Сервер | FastAPI, SQLAlchemy 2, Alembic, PostgreSQL 15 | `src/backend/` |
| Агент | Python, только стандартная библиотека; Windows — PyInstaller | `agent/` |
| Развёртывание | Docker, nginx без root, systemd, GitHub Actions | `deploy/`, `agent/deploy/`, `.github/workflows/` |

```mermaid
flowchart LR
    B[Браузер] -->|":80"| N["frontend<br/>nginx: статика + /api"]
    RA[Удалённый агент] -->|":80 /api"| N
    N --> BE["backend<br/>FastAPI + пробы агента"]
    LA[Агент на сервере] -->|"127.0.0.1:8000"| BE
    BE --> DB[("PostgreSQL")]
```

```text
agent/                  агент: collector.py, probes.py, служба systemd (deploy/), тесты
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

# по выгрузке конфигурации (show_running-config.txt, show_version.txt … в каталоге)
python3 agent/collector.py --api-url https://… --environment net --use-packs \
  --offline-dir ./export-sw-core-01 --hostname sw-core-01
```

Подробно — [`agent/README.md`](agent/README.md), включая Windows.

## Тесты

```bash
# сервер — только на одноразовой БД (тесты очищают таблицы), не на боевой
cd src/backend && DATABASE_URL=postgresql+psycopg://postgres:postgres@localhost:5433/app_test_db .venv/bin/pytest tests
pytest agent/tests                                                    # агент
cd src/backend && python -m app.commands.pack validate && python -m app.commands.pack test   # паки
npm run lint && npm run build                                         # интерфейс
```

CI на каждый push: тесты сервера и агента, сборка интерфейса, агент внутри 16 Linux-систем и на
настоящих Windows Server 2022 / 2025.

## Развёртывание

```bash
# перед выкаткой: дамп БД и метки на текущие образы для отката
docker exec diploma_db pg_dump -Fc -U postgres app_db > ~/backups/app_db-pre-<изменение>.dump
docker tag hardening-backend:latest hardening-backend:pre-<изменение>

# сервер: образ (пробы агента — отдельным контекстом), миграции одноразовым контейнером, перезапуск
docker build --build-context agent=./agent -t hardening-backend:latest ./src/backend
docker run --rm --network diplom-hardening_default --env-file ./src/backend/.env hardening-backend:latest alembic upgrade head
./deploy/restart_backend.sh

# интерфейс: nginx без root на порту 80
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
