# 🛡️ Харденинг — система контроля харденинга ИТ-инфраструктуры

**Харденинг** — система, которая автоматически собирает конфигурацию разнородных хостов, сравнивает её с требованиями безопасности и показывает соответствие и его изменение во времени.

```text
агент на хосте ──► сервер (FastAPI) ──► PostgreSQL ──► веб-интерфейс (React)
  собирает факты     сравнивает с         снимки,        оценка, сравнение
  по контент-пакам   требованиями пака    история        сканов, отчёты
```

> ⚠️ Это не сканер уязвимостей: система проверяет, правильно ли **настроены** системы
> (SSH, пароли, межсетевой экран, аудит, контейнеры, СУБД и т. д.), и соответствуют ли
> настройки политикам безопасности и методикам ФСТЭК России.

---

## 🧩 Возможности

- **Контент-паки вместо кода.** Проверки для платформы описываются декларативно в YAML (`src/backend/app/packs/`): как распознать платформу, какой факт собрать, с чем сравнить, критичность и рекомендация. Новая платформа добавляется данными, агент обновлять не нужно.
- **Агент только собирает, сервер оценивает.** Агент — два файла на Python без зависимостей (Python 3.6+). Он получает с сервера подписанные паки, сам определяет платформу и отправляет «сырые» результаты проб. Сравнение с требованиями выполняет сервер.
- **Разные ОС в одном агенте:** Ubuntu, Debian, RHEL-семейство (Rocky, Alma, Oracle, CentOS Stream, РЕД ОС), Astra Linux, Альт, Windows Server и Windows 10/11, а также Docker, PostgreSQL, Samba, Cisco IOS.
- **Оценка соответствия и покрытие.** Compliance score = соблюдено / (соблюдено + нарушено). Проверки, которые не удалось выполнить, показываются отдельно и не завышают оценку.
- **Снимки и сравнение сканов.** Каждый прогон агента — снимок. Любые два снимка можно сравнить: что исправлено, что ухудшилось, что появилось.
- **Принятый риск.** Администратор может исключить нарушение из оценки с обоснованием и сроком. Факт `fail` при этом сохраняется, решение остаётся в истории.
- **Сроки устранения по методикам ФСТЭК** (25.11.2025, 30.06.2025) в зависимости от критичности.
- **Отчёты PDF и Excel** по любому снимку.
- **Несколько организаций** с изоляцией данных и ролями (администратор, наблюдатель), суперадмин, 2FA (TOTP), защита входа от подбора.

### Паки

| Пак | Уровень | Подтверждение |
|---|---|---|
| `ubuntu-server` | baseline | реальный хост (Ubuntu 20.04 / 22.04 / 24.04) |
| `docker` | baseline | реальный хост |
| `windows-server` | baseline | Windows Server 2022 и 2025 (CI) |
| `debian-server`, `alt-linux`, `astra-linux`, `rhel-family` | draft | агент в контейнерах этих ОС (CI) |
| `windows-client`, `postgresql`, `samba`, `cisco-ios` | draft | образцы вывода |

`baseline` — проверено на реальной системе, `draft` — на образцах или в контейнерах. Формат пака и правила авторства описаны в [`src/backend/app/packs/README.md`](src/backend/app/packs/README.md), архитектура — в [`docs/agent-packs/`](docs/agent-packs/).

---

## 🧱 Архитектура и стек

| Часть | Стек | Где в репозитории |
|---|---|---|
| Веб-интерфейс | React 19, Vite, TailwindCSS, React Router | `src/` |
| Сервер | FastAPI, SQLAlchemy 2, Alembic, PostgreSQL | `src/backend/` |
| Агент | Python 3.6+, только стандартная библиотека | `agent/` |
| Развёртывание | Docker, nginx (без root), systemd | `deploy/`, `Dockerfile.frontend`, `agent/deploy/` |

```mermaid
flowchart LR
    B[Браузер] -->|":80"| N["frontend<br/>nginx: статика + /api"]
    RA[Удалённый агент] -->|":80 /api"| N
    N --> BE["backend<br/>FastAPI"]
    LA[Агент на сервере] -->|"127.0.0.1:8000"| BE
    BE --> DB[("PostgreSQL")]
```

### Структура репозитория

```text
agent/
 ├── collector.py, probes.py   # агент: сбор фактов по пакам, отправка на сервер
 ├── deploy/                   # служба systemd: unit, таймер, install.sh, образец настроек
 └── tests/
src/
 ├── api/                      # клиенты к API
 ├── components/, pages/       # интерфейс
 ├── utils/                    # сроки устранения, оценка, даты
 └── backend/
      ├── app/
      │    ├── api/routes/     # HTTP-маршруты
      │    ├── models/         # таблицы БД
      │    ├── services/       # движок оценки, паки, принятый риск, отчёты
      │    ├── packs/          # контент-паки (YAML)
      │    └── commands/       # команды: create_admin, create_agent_key, pack
      ├── alembic/             # миграции схемы
      ├── pack_tests/          # фикстуры паков (нарушение / соблюдение)
      └── tests/
deploy/                        # nginx.conf, restart_backend.sh, restart_frontend.sh
docs/agent-packs/              # архитектура паков, платформы, дорожная карта
```

---

## 🚀 Запуск для разработки

```bash
# сервер
cd src/backend
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
cp .env.example .env            # DATABASE_URL, JWT_SECRET_KEY, TOTP_SECRET_ENCRYPTION_KEY, ...
.venv/bin/alembic upgrade head
.venv/bin/uvicorn app.main:app --reload

# интерфейс (Vite проксирует /api на localhost:8000)
npm install
npm run dev
```

Первый администратор: `python -m app.commands.create_admin`. Ключ агента для организации: `python -m app.commands.create_agent_key`.

### Тесты

```bash
# сервер — только на отдельной, одноразовой БД (тесты очищают таблицы)
cd src/backend && DATABASE_URL=postgresql+psycopg://postgres:postgres@localhost:5433/app_test_db .venv/bin/pytest tests
# агент
pytest agent/tests
# паки: схема и сценарии нарушения / соблюдения
cd src/backend && python -m app.commands.pack validate && python -m app.commands.pack test
# интерфейс
npm run lint && npm run build
```

CI (GitHub Actions) прогоняет всё это на каждый push, а паки — ещё и в контейнерах Linux-дистрибутивов и на Windows Server.

---

## 📦 Развёртывание на сервере

Сервер и интерфейс работают в отдельных контейнерах. nginx интерфейса отдаёт сборку и проксирует `/api` в сервер. Сам сервер слушает только `127.0.0.1:8000`.

```bash
# сервер: сначала миграции одноразовым контейнером из нового образа, затем перезапуск
docker build -t hardening-backend:latest ./src/backend
docker run --rm --network diplom-hardening_default --env-file ./src/backend/.env hardening-backend:latest alembic upgrade head
./deploy/restart_backend.sh

# интерфейс: nginx без root на порту 80 (FRONTEND_PUBLISH=127.0.0.1:80 — только с этого хоста)
./deploy/restart_frontend.sh
```

Перед выкаткой: дамп БД и метка на текущий образ (`docker tag hardening-backend:latest hardening-backend:pre-<изменение>`) для отката.

### Агент на хосте

```bash
sudo ./agent/deploy/install.sh                      # копирует агента в /opt/hardening-agent
sudo nano /etc/hardening-agent/local.env            # адрес сервера, ключ агента, ключ подписи паков
sudo systemctl start hardening-agent@local          # пробный прогон
sudo systemctl enable --now hardening-agent@local.timer   # ежедневно
```

Агент только читает: файловая система службы доступна лишь на чтение, команды берутся из белого списка, секреты не читаются. Подробно — [`agent/README.md`](agent/README.md).

---

## 📌 Пример: реальный хост «до → после»

Агент на боевом сервере проекта (Ubuntu 24.04, Docker), паки `ubuntu-server` и `docker`, 21 проверка:

| Скан | Что изменилось | Соблюдено | Нарушено | Оценка |
|---|---|---|---|---|
| 1 | исходное состояние | 3 | 11 (+7 не проверено) | 21% |
| 2 | SSH, ufw, auditd | 8 | 6 (+7 не проверено) | 57% |
| 3 | агенту дан доступ к Docker | 15 | 6 | 71% |
| 4 | парольная политика, faillock | 19 | 2 | **90%** |

Оставшиеся два нарушения: вход по паролю в SSH (до настройки ключей) и `ip_forward` (нужен Docker и VPN). Это кандидаты на «принятый риск».

---

## 🎓 Дипломная работа

> **Систематизация и автоматизация харденинга информационной инфраструктуры**

Проект показывает:
- практическую реализацию контроля конфигураций для разных платформ, включая российские ОС;
- привязку проверок к методикам ФСТЭК России;
- проверку на реальной инфраструктуре: от сбора фактов до отчёта и сравнения «до/после».
