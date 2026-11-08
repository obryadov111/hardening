# 18. Перечень API

Префикс всех ручек — `/api` (`API_PREFIX`). Плюс `GET /health` без префикса (`main.py`): проверка, что процесс жив, без данных аудита.

Обозначения прав:

- **публично** — без токена
- **токен** — обычный JWT `type=access`, 2FA подключена, если она обязательна
- **участник** — `require_org_access`: admin, auditor или viewer этой организации; суперадмин проходит везде
- **админ орг.** — `require_org_admin`
- **суперадмин** — `require_superadmin`
- **агент** — заголовок `X-Agent-Api-Key`

`auditor` и `viewer` в этой таблице не разделены: код их не разделяет.

## Вход

| Метод | Путь | Кто | Что делает |
|---|---|---|---|
| POST | `/api/auth/login` | публично | пароль, либо токен доступа, либо `pre_2fa` |
| POST | `/api/auth/verify-2fa` | публично, нужен temp token | код → токен доступа |
| GET | `/api/auth/me` | токен, даже без смены пароля и без 2FA | кто я и надо ли донастроить вход |
| POST | `/api/auth/change-password` | токен, даже с временным паролем | новый пароль и новый токен |
| GET | `/api/auth/2fa` | токен на этапе подключения 2FA | состояние |
| POST | `/api/auth/2fa/setup` | то же | секрет и QR |
| POST | `/api/auth/2fa/confirm` | то же | включить после верного кода |
| POST | `/api/auth/2fa/disable` | токен | выключить, нужны пароль и код |

## Люди и организации

| Метод | Путь | Кто | Что делает |
|---|---|---|---|
| GET | `/api/organizations` | токен | свои организации |
| GET | `/api/organizations/{org}/my-role` | участник | роль и флаги |
| GET | `/api/organizations/{org}/users` | админ орг. | участники |
| POST | `/api/organizations/{org}/users` | админ орг. | добавить участника |
| PATCH | `/api/organizations/{org}/users/{id}` | админ орг. | сменить роль |
| DELETE | `/api/organizations/{org}/users/{id}` | админ орг. | убрать участника |
| POST | `/api/admin/organizations` | суперадмин | создать организацию |
| GET | `/api/admin/users` | суперадмин | все учётки |
| POST | `/api/admin/users` | суперадмин | создать учётку |
| POST | `/api/admin/users/{id}/reset-password` | суперадмин | временный пароль |
| POST | `/api/admin/users/{id}/reset-2fa` | суперадмин | сбросить 2FA |
| POST | `/api/admin/users/{id}/block` | суперадмин | заблокировать |
| POST | `/api/admin/users/{id}/activate` | суперадмин | разблокировать, в том числе после подбора |

## Чтение данных

Все ручки ниже — участник организации либо владелец актива через проверку в `data.py` / `exports.py`.

| Метод | Путь | Что делает |
|---|---|---|
| GET | `/api/organizations/{org}/dashboard` | сводка |
| GET | `/api/organizations/{org}/assets` | активы |
| GET | `/api/assets` | до 50 активов по всем доступным организациям |
| GET | `/api/assets/{id}` | карточка |
| GET | `/api/assets/{id}/inventory` | паспорт |
| GET | `/api/assets/{id}/software` | ПО актива |
| GET | `/api/assets/{id}/hardening` | проверки актива |
| GET | `/api/organizations/{org}/software` | поиск ПО |
| GET | `/api/software` | ПО без фильтра организации, урезанный список |
| GET | `/api/organizations/{org}/environments` | окружения |
| GET | `/api/organizations/{org}/hardening` | проверки с фильтрами и страницами |
| GET | `/api/organizations/{org}/snapshots` | снимки (как раньше, по одному на приём) |
| GET | `/api/organizations/{org}/scan-runs` | прогоны, query `status`, `limit`, `offset` |
| GET | `/api/organizations/{org}/scan-schedule` | `daily` или `weekly` |
| GET | `/api/scan-runs/{id}` | шапка прогона и сводные суммы |
| GET | `/api/scan-runs/{id}/hosts` | хосты прогона, query `q`, `status`, `environment_id`, страницы |
| GET | `/api/scan-runs/{id}/findings` | нарушения по правилам и число хостов |
| GET | `/api/scan-runs/compare` | два прогона, query `before_run_id`, `after_run_id` |
| GET | `/api/exports/scan-runs/{id}/download` | Excel или PDF прогона |
| GET | `/api/scan-snapshots` | снимки по доступным организациям |
| GET | `/api/organizations/{org}/reports` | история процента организации |
| GET | `/api/organizations/{org}/vulnerabilities` | находки, здесь же ленивый пересчёт |
| GET | `/api/organizations/{org}/fstec-coverage` | пункты методики |
| GET | `/api/organizations/{org}/coverage` | охват, query `days` |
| GET | `/api/snapshots/compare` | два снимка, query `before_snapshot_id` и `after_snapshot_id` |
| GET | `/api/exports/snapshots/{id}/download` | `format=excel` или `pdf` |
| GET | `/api/organizations/{org}/policies` | список политик |
| GET | `/api/organizations/{org}/risk-exceptions` | список рисков |
| GET | `/api/organizations/{org}/manual-scans/packs` | вопросы анкет |
| GET | `/api/organizations/{org}/offline-scans/packs` | какие ssh-паки ждут выгрузку |
| GET | `/api/organizations/{org}/agent-keys` | список ключей площадки, сами ключи не возвращаются |

## Изменения участником-админом

| Метод | Путь | Что делает |
|---|---|---|
| POST | `/api/organizations/{org}/policies` | создать карточку |
| PATCH | `/api/organizations/{org}/policies/{id}` | изменить |
| DELETE | `/api/organizations/{org}/policies/{id}` | удалить |
| POST | `/api/organizations/{org}/risk-exceptions` | принять риск |
| DELETE | `/api/organizations/{org}/risk-exceptions/{id}` | отозвать |
| POST | `/api/organizations/{org}/agent-keys` | создать ключ площадки, секрет в ответе один раз |
| POST | `/api/organizations/{org}/agent-keys/{id}/revoke` | отозвать ключ площадки |
| POST | `/api/organizations/{org}/agent-hosts/{id}/revoke` | отозвать хост |
| DELETE | `/api/organizations/{org}/agent-hosts/{id}` | удалить регистрацию и освободить имя |
| POST | `/api/organizations/{org}/agent-reports` | загрузить файл `--out` |
| POST | `/api/organizations/{org}/expected-hosts` | заменить список охвата |
| DELETE | `/api/organizations/{org}/expected-hosts` | очистить список |
| POST | `/api/organizations/{org}/offline-scans/preview` | разобрать один файл, снимок не создавать |
| POST | `/api/organizations/{org}/offline-scans` | выгрузка: `commands`+`files` или одно поле `bundle`; необязательное поле `scan_run_id` |
| POST | `/api/organizations/{org}/manual-scans` | ответы анкеты; необязательное поле `scan_run_id` |
| POST | `/api/organizations/{org}/scan-runs` | открыть прогон вручную |
| POST | `/api/scan-runs/{id}/close` | закрыть прогон |
| PUT | `/api/organizations/{org}/scan-schedule` | `daily` или `weekly` |

## Агент

| Метод | Путь | Кто | Что делает |
|---|---|---|---|
| GET | `/api/agent/manifests` | агент | подписанные манифесты, query `transport=local\|ssh` |
| POST | `/api/agent/enroll` | ключ площадки | выдать ключ хоста |
| POST | `/api/ingest` | ключ хоста или старый `direct_use` | принять прогон |

Команды вне HTTP, их вызывает администратор сервера, не браузер:

| Команда | Зачем |
|---|---|
| `python -m app.commands.create_admin` | первый суперадмин |
| `python -m app.commands.create_agent_key` | ключ площадки без интерфейса |
| `python -m app.commands.pack_signing_key` | seed Ed25519 |
| `python -m app.commands.pack validate\|test\|live\|manifests\|evaluate` | автор паков |
| `python -m app.commands.bdu import\|oval` | загрузка БДУ и OVAL |
| `python -m app.commands.seed_demo_data` | демонстрационные данные |

## Ограничения

- OpenAPI живёт на `/docs` процесса uvicorn. Снаружи его может закрывать nginx. Список выше снят с декораторов роутеров, а не с чужого описания.
- Часть чтения (`GET /api/assets`, `GET /api/software`, `GET /api/scan-snapshots`) существует параллельно с вариантом «внутри организации» и ограничивает объём. Для тысяч хостов используются варианты с `{org}` и пагинацией.

## Вопросы на защите

**Сколько примерно ручек?** Декораторы роутеров плюс `/health` — около шестидесяти. Точный список — таблица выше, она собрана по `src/backend/app/api/routes`.

**Может ли наблюдатель принять риск?** Нет. POST исключений требует `require_org_admin`.

**Какой ручкой агент сдаёт работу?** `POST /api/ingest`. Манифесты — `GET /api/agent/manifests`. Регистрация — `POST /api/agent/enroll`.
