# 8. Пробы: что именно читает агент

## Зачем нужно

Проба — закрытый способ прочитать один факт. Автор пака выбирает тип и параметры. Агент не выполняет произвольный shell. Если проба не смогла прочитать факт, результат `found: false`. Сервер ставит `error` («Не проверено»), а не нарушение.

Диспетчер — `run_probe` в `agent/probes.py`. Словарь `PROBES` содержит 14 типов. Пятнадцатый тип, `manual`, в этот словарь не входит: его обрабатывает сервер в опросе.

Подсчёт по актуальным пакам на 1 ноября 2026 (верхний уровень проверки, без вложенных в `first_of`):

| Тип | Проверок | Где выполняется |
|---|---|---|
| `cli_config` | 94 | SSH, UserGate, Континент, выгрузка |
| `file_kv` | 47 | локальный хост |
| `reg_value` | 34 | Windows |
| `file_regex` | 33 | локальный хост |
| `service_state` | 26 | systemd или служба Windows |
| `win_secpol` | 20 | Windows, secedit |
| `win_auditpol` | 17 | Windows, auditpol |
| `first_of` | 16 | первый сработавший вложенный источник |
| `win_ad` | 15 | контроллер домена |
| `manual` | 14 | сервер, страница опроса |
| `file_stat` | 12 | права файла, без чтения содержимого |
| `cli_blocks` | 11 | блоки конфигурации устройства |
| `cmd_foreach` | 9 | список и проверка каждого элемента, в паках это Docker |
| `cmd_regex` | 5 | одна команда из белого списка |
| `pkg_version` | 0 | тип есть в агенте, в актуальных паках не используется |

Внутри `first_of` ещё 20 `reg_value`, 6 `file_kv` и 6 `cmd_regex`. Это запасные источники того же факта, не отдельные проверки.

Результат любой пробы: `{found, value, evidence}` и при отказе `error`. Свидетельство проходит `redact`: после слов password, secret, community, token, hash, psk, pre-shared-key, private-key, plaintext-password, encrypted-password остаток строки заменяется на `***` и обрезается. Журнал прогона в stderr — JSON на каждую проверку: пак, id, тип, `found`, секунды. Значение туда не пишется.

## Файлы

`file_kv` (`probe_file_kv`). Ключ и значение из файла. Разделитель пробел или `=`. Можно взять первое или последнее вхождение, игнорировать регистр ключа, подставить `default`, если строки нет. `follow_include` раскрывает `Include` (так устроен `sshd_config`): глубина до 5, не больше 50 файлов, каталог не шире каталога исходного файла. Встреча `Match` останавливает чтение, как у sshd.

`file_regex` (`probe_file_regex`). Первая группа регулярного выражения или всё совпадение.

`file_stat` (`probe_file_stat`). Поле `mode`, `owner`, `group`, `uid` или `gid`. Содержимое не читается, поэтому так можно говорить о `/etc/shadow`, не забирая хэши. Сравнение прав — оператор `mode_within`, не «число меньше».

Файл больше `MAX_FILE_BYTES` (2 000 000) целиком не читается. Путь должен быть абсолютным, без `..`. Символическая ссылка проверяется и сама, и после `realpath`.

`DENIED_PATH_PATTERNS` запрещает и путь, и realpath, и результат glob:

- `/etc/shadow`, `/etc/gshadow`, `/etc/security/opasswd`
- ключи хоста SSH, `/root/.ssh/`, `/home/*/.ssh/`, `id_rsa` и соседние имена
- `*.pem`, `*.key`, `*.p12`, `*.pfx`
- `/proc/*/environ`

## Команды и sysctl

`cmd_regex` (`probe_cmd_regex`). Локальная команда — список аргументов, не строка shell. Исполняемый файл ищется в `SAFE_PATH`. На Windows это System32. Окружение процесса — только `PATH` и `LANG=C`. Таймаут `COMMAND_TIMEOUT` = 15 секунд.

Белый список `LOCAL_COMMAND_POLICY`:

| Программа | Что разрешено |
|---|---|
| `systemctl` | `is-active`, `is-enabled`, `is-failed` и имя юнита |
| `ufw` | `status` или `status verbose` |
| `dpkg-query` | `-W -f=…` и имя пакета |
| `rpm` | `-q --qf …` и имя пакета |
| `sysctl` | `-n` и имя ключа вида `net.ipv4.ip_forward` |
| `getenforce` | без аргументов |
| `aa-status` | `--enabled` |
| `timedatectl` | `show` с необязательным `-p` и `--value` |
| `ss` | набор флагов `-tulnp` |
| `modprobe` | только `-n -v` (показать, что модуль запрещён, не загружать) |
| `sc` | `query` и имя службы |
| `docker` | `ps -q`; `inspect` с фиксированным набором полей; `network inspect bridge` для флага icc |

Всё остальное — отказ пробы. `docker run`, `exec`, `rm` в список не входят.

`cmd_foreach` (`probe_cmd_foreach`). Сначала команда-список (`docker ps -q`), затем команда на каждый элемент, элемент дописывается последним аргументом. Значение — число элементов, чей вывод совпал с шаблоном. Пустой список — 0. Ошибка команды — это `error`, а не ноль. Потолок `max_items` — 200, в модели по умолчанию 100.

`service_state` (`probe_service_state`). На Linux — `systemctl`. Известные состояния и `not-found` отличаются от «команда недоступна». На Windows — значение `Start` в реестре (2 — автозапуск, 4 — отключена) плюс `sc query`.

`pkg_version` (`probe_pkg_version`) читает версию одного пакета через dpkg или rpm. В актуальных паках тип не используется: список всего ПО собирается отдельно, функцией `collect_software`, для БДУ, а не как проверка пака.

Отдельной пробы «прочитать PostgreSQL по SQL» нет. Пак `postgresql` смотрит файлы `postgresql.conf` и `pg_hba.conf` типами `file_kv`, `file_regex` и `file_stat`. Другие СУБД отдельных паков не имеют. В каталоге методики для MySQL и MariaDB есть только пункт уязвимостей ПО, без проверок конфигурации.

## Реестр, политики, аудит, домен

Реестр: `probe_reg_value` и `read_registry`. Только HKLM. Кусты `HKLM\SAM` и `HKLM\SECURITY` запрещены (`REG_DENIED`) ещё до обращения к системе, это проверяется и на Linux в тестах. DWORD приходит числом, MULTI_SZ — строкой через запятую.

`win_secpol` (`probe_win_secpol`). `secedit /export` во временный файл, разбор `parse_secedit`, каталог удаляется. Результат кэшируется на время прогона.

`win_auditpol` (`probe_win_auditpol`). `auditpol /backup`, разбор `parse_auditpol_backup`. Значение подкатегории по GUID: 0 нет аудита, 1 успех, 2 отказ, 3 успех и отказ. Пример из пака: `win.audit_logon` ждёт `eq 3` для GUID входа.

`win_ad` (`probe_win_ad`). Один из 15 фактов встроенного сценария `AD_FACTS_SCRIPT`. Сценарий не приходит из манифеста: это константа в `probes.py`. Запуск — PowerShell с закодированной командой, таймаут дольше обычной команды. Вывод — JSON в base64. Факты:

1. `krbtgt_password_age_days`
2. `privileged_users_count`
3. `schema_admins_count`
4. `privileged_spn_users_count`
5. `unconstrained_delegation_count`
6. `asrep_roastable_count`
7. `password_never_expires_count`
8. `password_not_required_count`
9. `reversible_encryption_users_count`
10. `des_only_users_count`
11. `machine_account_quota`
12. `domain_functional_level`
13. `recycle_bin_enabled`
14. `anonymous_ldap_allowed`
15. `laps_schema_present`

Имена учётных записей в значение не кладутся целиком: счётчики возвращают число и не больше 10 имён для свидетельства. Пак `windows-dc` как раз из этих фактов. На рядовом сервере `detect` пака (`ProductType=LanmanNt`) не совпадёт, и факты AD не читаются. На контроллере совпадают оба пака: `windows-dc` и `windows-server`.

`first_of` (`probe_first_of`). От двух до пяти вложенных проб, один уровень. Берётся первая, которая нашла значение. Так одна проверка переживает разный путь файла в Debian и в RHEL.

## Сеть: общий разбор текста

`cli_config` (`probe_cli_config`) и `cli_blocks` (`probe_cli_blocks`) читают текст команды. Откуда текст — решает транспорт: SSH, файл выгрузки, UserGate или Континент. Сама проба этого не знает.

Команда обязана пройти `is_readonly_cli` и ту же регулярку на сервере (`CLI_READONLY_RE`): длина до 200 символов, без кавычек, переводов строк и подстановок. Разрешено:

- `show …`, `display …`
- `/export` и команды RouterOS `… print`
- группы ViPNet: `inet|iplir|machine|failover|mftp|ups show`, `iplir option get`, `version`

После `|` допускаются только фильтры `include`, `exclude`, `begin`, `section`, `count`, `match`, `except`.

`cli_config`: регулярное выражение `match`, необязательные `section`, `require` (признак, что это вообще тот вывод; нет признака — проба не выполнилась, а не «значения нет»), `default`, `multiline`. Строка, начинающаяся с `%`, считается ошибкой устройства.

`cli_blocks`: режет вывод на блоки по отступам. Считает блоки, у которых есть все строки `has` и нет строк `lacks`, при желании только внутри родителя `within`. Значение — число. Его сравнивают с `gte 1` или `eq 0`.

SSH (`SshTransport`): каждая команда — отдельный `ssh` без shell, `BatchMode=yes`, `StrictHostKeyChecking=yes`, таймаут соединения 10 секунд, таймаут команды 30 секунд. Код 255 — ошибка ssh, не пустая конфигурация. Устройство должно быть в `known_hosts` пользователя агента. Пароль по SSH не передаётся: только ключ.

Выгрузка (`OfflineConfigTransport`): имя файла — команда, пробелы и слэши заменены на `_`, расширение `.txt` (`offline_file_name`). Пример: `show running-config` → `show_running-config.txt`. Не symlink, не пустой, до 5 МБ, кодировка utf-8-sig или cp1251. В описание прогона попадают SHA-256 и время файла.

UserGate и Континент подставляют в эти же пробы свой текст. Их каналы — следующая глава.

## Список ПО и железо

Это не проверки пака.

`collect_software`: на Debian-семействе `dpkg-query` с именем, версией и source; иначе `rpm`. На Windows — ветки Uninstall, 64-бит и WOW6432Node, без `SystemComponent=1`.

`collect_hardware`: Linux читает sysfs и proc без root (machine-id, DMI, диски nvme/ssd/hdd). Windows — один сценарий CIM. Имя пользователя, домен и группы — только при `--collect-identity`.

Прошивка устройства — `collect_firmware`: проба версии из поля `firmware`, имя продукта из константы или из `product_probe`. Запись ПО: имя в нижнем регистре, версия, производитель, категория `firmware`.

## Где в коде

| Что | Функция |
|---|---|
| Диспетчер | `run_probe`, словарь `PROBES` |
| Файлы | `probe_file_kv`, `probe_file_regex`, `probe_file_stat` |
| Команды | `probe_cmd_regex`, `probe_cmd_foreach`, `LocalTransport._execute` |
| Windows | `probe_reg_value`, `probe_win_secpol`, `probe_win_auditpol`, `probe_win_ad` |
| Текст устройства | `probe_cli_config`, `probe_cli_blocks`, `is_readonly_cli` |
| Запреты | `DENIED_PATH_PATTERNS`, `LOCAL_COMMAND_POLICY`, `REG_DENIED`, `redact` |
| Модель на сервере | классы проб в `services/packs/models.py` |

Сервер при загрузке пака повторяет ограничения: абсолютный путь, команда из того же белого списка, для ssh только `cli_config`, `cli_blocks` и `cmd_regex`. Пак с лишней командой не загрузится. Агент всё равно проверяет ещё раз и не доверяет манифесту вслепую.

## Ограничения

- Нет пробы «выполнить SQL», «сходить в чужой HTTP» или «прочитать произвольный PowerShell из пака». AD — единственный PowerShell, и он зашит в код.
- `pkg_version` в каталоге паков сейчас не используется.
- В контейнере CI нет systemd. Проверки служб там честно становятся «не проверено», и workflow это разрешает флагом, а не подменой ожидаемого значения.
- Ядро Linux в список ПО попадает, но с БДУ не сопоставляется. Это решение модуля БДУ, не пробы.

## Вопросы на защите

**Откуда берётся значение «PermitRootLogin no»?** Проба `file_kv` читает `/etc/ssh/sshd_config` и Include. Сравнение `eq no` делает сервер.

**Почему агент не читает `/etc/shadow`?** Содержимое запрещено `DENIED_PATH_PATTERNS`. Права файла читает `file_stat`, не открывая хэши.

**Может ли пак попросить `docker run`?** Нет. И модель пака, и `LOCAL_COMMAND_POLICY` такой аргумент отвергают.

**Сколько фактов AD?** Пятнадцать, список `Fact` в `AD_FACTS_SCRIPT`. Пак не может добавить шестнадцатый без новой сборки агента.
