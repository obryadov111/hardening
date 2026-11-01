# 1. Вход, JWT, роли и 2FA

## Зачем нужно

Люди работают в браузере. Данные организаций нельзя отдавать по одному паролю, если сайт открыт из интернета. Поэтому вход — это пароль, затем одноразовый код, затем токен, который сервер проверяет на каждом запросе.

Самостоятельной регистрации нет. Учётку создаёт суперадминистратор. Об этом прямо написано на странице входа.

## Как работает по шагам

1. `POST /api/auth/login` ищет пользователя по email в нижнем регистре (`login` в `src/backend/app/api/routes/auth.py`).
2. До проверки пароля `ensure_not_locked` смотрит `users.locked_until`. Если блокировка ещё идёт, ответ 429 и пароль не проверяется (`login_guard.py`).
3. Неверный пароль увеличивает `failed_login_attempts` атомарным `UPDATE`. После 5 подряд (`LOGIN_MAX_FAILED_ATTEMPTS`) счётчик обнуляется и ставится `locked_until` на 15 минут (`LOGIN_LOCKOUT_MINUTES`).
4. Если email не найден, пароль всё равно прогоняется через bcrypt по заготовленному хэшу (`_DUMMY_HASH`). Иначе по времени ответа можно было бы узнать, какие адреса есть в базе.
5. Неактивный или не `active` пользователь получает 403.
6. Если 2FA включена, сервер не выдаёт доступ. Он возвращает короткий JWT `type=pre_2fa` на 5 минут (`PRE_2FA_TOKEN_EXPIRE_MINUTES`). Счётчик неудач при этом не сбрасывается: иначе, зная пароль, можно было бы бесконечно подбирать код, чередуя его с верным паролем.
7. `POST /api/auth/verify-2fa` принимает код приложения или резервный код (`check_second_factor` в `api/routes/twofa.py`). Верный код сбрасывает счётчик и выдаёт обычный токен.
8. Обычный токен создаёт `create_access_token` (`core/security.py`): HS256, `sub` = id пользователя, `type=access`, `exp` через 8 часов (`ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 8`), `iat` с долями секунды.
9. Браузер кладёт токен в `localStorage` под ключом `hardening_access_token` (`src/api/client.js`, `setStoredAccessToken`) и шлёт заголовок `Authorization: Bearer`.
10. `get_current_user_allow_password_change` (`api/deps.py`) отклоняет токен без `type=access`, токен старше `password_changed_at` и заблокированного пользователя.
11. Если `REQUIRE_2FA=true` (значение по умолчанию) и 2FA не включена, почти все ручки отвечают 403 «Нужно подключить двухфакторную защиту». Открыты смена пароля и подключение 2FA.
12. Временный пароль (`must_change_password`) закрывает API, пока его не сменят. Смена пароля (`POST /api/auth/change-password`) пишет новый bcrypt, обновляет `password_changed_at` и возвращает новый токен. Старые токены умирают из-за сравнения `iat`.

Пароль: bcrypt, 12 раундов, учитываются первые 72 байта. Новый пароль — от 12 до 128 символов, не равен email, не из одних пробелов (`password_problem`). Это проверка только для паролей, которые задают через API. Старые хэши не пересматриваются.

2FA — TOTP (pyotp, RFC 6238). Секрет в `user_2fa.secret_encrypted` зашифрован Fernet. Ключ Fernet — SHA-256 от `TOTP_SECRET_ENCRYPTION_KEY`, не сам секрет в открытом виде. Восемь резервных кодов хранятся как SHA-256. Принятый код запоминается в `last_used_at` (начало 30-секундного окна), повтор того же кода не проходит.

Подключение: `GET /api/auth/2fa`, `POST /api/auth/2fa/setup` (QR), `POST /api/auth/2fa/confirm`. Отключение — пароль и код (`POST /api/auth/2fa/disable`). Суперадмин может сбросить 2FA чужому пользователю (`POST /api/admin/users/{id}/reset-2fa`): запись `user_2fa` удаляется, и при обязательной 2FA человеку снова нужно её подключить.

## Откуда берутся данные

| Данные | Откуда |
|---|---|
| Email и пароль | Форма входа, их ввёл человек |
| Учётка | Суперадмин, `POST /api/admin/users`, или команда `python -m app.commands.create_admin` |
| Секрет TOTP | Сервер генерирует при setup, телефон показывает код |
| Токен | Сервер, после пароля и, если нужно, кода |

Сравнения здесь нет в смысле харденинга. Сравниваются: пароль с bcrypt-хэшем, код TOTP с секретом, `iat` токена с `password_changed_at`, роль с требуемым доступом.

## Где хранится

- `users` — email, `password_hash`, `is_superadmin`, `account_status` (`pending|active|blocked`), `must_change_password`, `failed_login_attempts`, `locked_until`, `password_changed_at`.
- `user_2fa` — секрет, флаги, хэши резервных кодов, `last_used_at`.
- `user_organizations` — роль в конкретной организации: `admin`, `auditor` или `viewer`.
- Токен на сервере не хранится. Отзыв — только через срок жизни и через `password_changed_at`.

Поля `users.role_id` и `users.organization_id` — от старой схемы, текущий код их не использует. Роль берётся из `user_organizations`.

## Роли

`get_user_role_in_org` (`api/deps.py`): суперадмин везде считается `admin`. Иначе читается строка членства. Нет строки — доступа к организации нет (403, а если организации нет — 404).

`require_org_access` пускает любую из трёх ролей. `require_org_admin` пускает только `admin` (и суперадмина).

`GET /api/organizations/{id}/my-role` отдаёт флаги. Смотреть дашборд, активы и отчёты могут все три роли. `manage_users` и `manage_policies` — только `admin`.

Что закрыто не-админу по коду ручек: ключи агента, загрузка выгрузки, опрос, список ожидаемых хостов, участники организации, политики (изменение), принятие риска. Чтение проверок, снимков, уязвимостей и методики открыто и аудитору, и наблюдателю.

**Роли `auditor` и `viewer` в коде не различаются.** Обе проходят `require_org_access` и не проходят `require_org_admin`. Интерфейс показывает разные подписи («Аудитор» и «Наблюдатель», `src/utils/roles.js`), но отдельные права для аудитора не реализованы.

Суперадмин дополнительно: `POST /api/admin/organizations`, список пользователей, сброс пароля, сброс 2FA, блок и разблокировка (`api/routes/admin_users.py`, `admin_organizations.py`). Разблокировка снимает и `locked_until`.

## Где в коде

| Что | Где |
|---|---|
| Вход и смена пароля | `login`, `verify_2fa`, `change_password` в `api/routes/auth.py` |
| Разбор токена | `get_current_user_allow_password_change` в `api/deps.py` |
| Хэш и JWT | `hash_password`, `create_access_token` в `core/security.py` |
| Подбор | `check_password`, `register_failure` в `services/login_guard.py` |
| 2FA | `api/routes/twofa.py`, `services/twofa_service.py` |
| Роли | `get_user_role_in_org`, `require_org_admin` в `api/deps.py`; `api/routes/members.py` |
| Токен в браузере | `setStoredAccessToken` в `src/api/client.js` |
| Страницы | `src/pages/Login.jsx`, `TwoFactor.jsx`, `ChangePassword.jsx`, `AdminUsers.jsx`, `OrganizationUsers.jsx` |

## Ограничения

- Регистрации «с улицы» нет.
- `auditor` и `viewer` сейчас одинаковы по правам.
- JWT лежит в `localStorage`. Это доступно скрипту страницы. На сервере есть заголовки CSP у nginx, но отдельного хранилища токена в httpOnly-cookie нет.
- Серверных сессий нет: украденный токен действует до `exp` или до смены пароля.
- Лимита неудачных входов по IP в коде приложения нет. Комментарий в `login_guard.py` объясняет почему: за nginx все клиенты выглядели бы одним адресом. Лимит запросов к входу есть в nginx (`limit_req zone=login`, 10 запросов в минуту на IP, `deploy/nginx/limits.conf`).
- Блокировку можно навести на чужой email серией ошибок. Она временная, суперадмин может снять её раньше.

## Вопросы на защите

**Откуда берётся пользователь?** Его создаёт суперадмин. Саморегистрации в коде нет.

**Где хранится пароль?** Только bcrypt-хэш в `users.password_hash`. Проверка — `verify_password`.

**Чем аудитор отличается от наблюдателя?** Подписью в интерфейсе. На сервере обе роли только читают. Менять могут администратор организации и суперадмин.

**Почему после смены пароля старый токен не работает?** В токене есть `iat`. Сервер сравнивает его с `users.password_changed_at` в `get_current_user_allow_password_change`.

**Что будет, если украсть пароль, но не телефон?** При включённой 2FA пароль даёт только `pre_2fa` на 5 минут. Данные организации этим токеном не открываются: `get_current_user` принимает только `type=access`.
