# 27. След одной проверки

Все фрагменты ниже скопированы из репозитория: пак, фикстура или тест. Это не выдуманный хост. Где тест использует укороченный пак, а не боевой `ubuntu-server`, это сказано прямо.

## А. SSH: запрет входа root

Боевой пак `ubuntu-server` 1.4.0, проверка `ssh.permit_root_login`.

### 1. Норма в YAML

```yaml
- id: ssh.permit_root_login
  title: Запрет входа по SSH под root
  probe: { type: file_kv, path: /etc/ssh/sshd_config, key: PermitRootLogin, follow_include: true, default: prohibit-password }
  assert: { op: eq, value: "no" }
  severity: high
  remediation: В sshd_config установить PermitRootLogin no и перезапустить sshd.
  refs:
    - { source: "Методика анализа защищённости информационных систем, ФСТЭК России, 25.11.2025", id: "ОПС.1.10" }
    - { source: "Методика анализа защищённости информационных систем, ФСТЭК России, 25.11.2025", id: "СУД.1.1" }
```

Файл: `src/backend/app/packs/ubuntu-server-1.4.0.yaml`. Комментарий в том же файле: у OpenSSH значение по умолчанию — `prohibit-password`, не `no`. Поэтому в пробе стоит `default: prohibit-password`. Если строки в файле нет, сравнение всё равно идёт, и с `eq no` оно не проходит. Раньше старый агент подставлял `no` и получал ложный pass.

`severity: high` — оценка автора пака. Формула V здесь не считается.

В манифест агенту уйдут только `id` и `probe`. Поля `assert`, `severity`, `remediation`, `refs` вырезает `build_manifest`.

### 2. Что читает агент

Тип пробы `file_kv`, функция `probe_file_kv` в `agent/probes.py`. Она открывает `/etc/ssh/sshd_config`. `follow_include: true` раскрывает `Include` (глубина до 5, не больше 50 файлов) и останавливается на `Match`, как sshd. Ключ `PermitRootLogin`. Если строки нет — значение `prohibit-password`.

Фикстура «слабый хост» в `src/backend/pack_tests/ubuntu-server.yaml` подставляет файл:

```yaml
/etc/ssh/sshd_config: |
  PermitRootLogin yes
```

Ожидание этой фикстуры: `ssh.permit_root_login: fail`. Рядом есть кейс, где строки нет, и ожидание тоже `fail` (сработал default). Кейс, где файл не читается, ожидает `error`.

`pack test` гоняет настоящую `probe_file_kv` по этим файлам и настоящий `evaluate_pack`.

### 3. Фрагмент отчёта

Тест приёма `pack_payload` в `src/backend/tests/test_ingest_packs.py` шлёт уже готовый результат пробы. Паке там не боевой на 25 проверок, а тестовый `ubuntu-test` из `BASE_PACK` (`tests/test_packs.py`): те же id, но у root оператор `in: [no, prohibit-password]` и severity `critical`. Для следа приёма важен JSON:

```json
"probe_results": {
  "ssh.permit_root_login": {"found": true, "value": "yes", "evidence": "PermitRootLogin yes"},
  "ssh.max_auth_tries": {"found": true, "value": "3", "evidence": "MaxAuthTries 3"}
}
```

`found: true` значит «строку прочитали». Нормы в JSON нет.

### 4. Приём и сравнение

`ingest_payload` находит пак по id и версии. `evaluate_pack` для проверки с `found: true` вызывает `check_assertion`.

Для боевого пака: `eq`, ожидается `no`, фактическое `yes`. `normalize_value` приводит к нижнему регистру. Строки не равны → `fail`. `describe_assertion` запишет ожидание `= no`.

Для тестового `ubuntu-test` тот же `yes` тоже `fail`, потому что его нет в списке `no`, `prohibit-password`. Вторая проверка тестового пака, `MaxAuthTries` 3 при `lte 4`, даёт `pass`.

Тест `test_ingest_packs` проверяет ответ:

```
checks = {total: 2, passed: 1, failed: 1, errors: 0}
```

и строки в базе: `hardening_checks` содержит `ssh.permit_root_login` со статусом `fail` и `ssh.max_auth_tries` со статусом `pass`. Сырьё в `agent_collections` хранит `value == "yes"`. В `scan_check_results` у этой проверки лежат title, severity и remediation на момент прогона.

Процент тестового прогона: 1 / (1 + 1) = 50. Один `fail` боевого пака на 25 проверок сам по себе эти 50 не даёт: знаменатель там другой. Исторические 97,06 — отдельный прогон сервера проекта (33 pass и 1 fail при двух принятых рисках), не эта фикстура.

### 5. Методика и экран

У боевой проверки два пункта: `ОПС.1.10` и `СУД.1.1`. `organization_coverage` помечает пункт `violated`, если среди активов есть `fail` без риска. Срок для `high` — «до 7 дней», обязательно, п. 3.4.4 (`REMEDIATION_BY_SEVERITY`). На странице «Харденинг» фильтр «Нарушено» показывает эту строку. Подпись «Не проверено» была бы только при `error`.

## Б. Континент 4: длина пароля

Пак `kontinent-4` 1.1.0, проверка `kontinent4.password_min_length`. Сервер на ЦУС не ходит. Ходит агент.

### 1. Цель

`agent/deploy/continent4.json.example`:

```json
{
  "kind": "continent4",
  "host": "10.77.0.30",
  "port": 444,
  "user": "hardening-ro",
  "password_file": "/etc/hardening-agent/continent4.pass",
  "pin_sha256": ""
}
```

`open_device_transport` видит `kind=continent4` и строит `Continent4Transport`. Пароль читает `read_password` из файла, в аргументы процессов он не попадает. Канал — ГОСТ TLS, три GET из `C4_READONLY_PATHS`. Если задан `pin_sha256`, пароль не уходит, пока отпечаток сертификата не совпал.

### 2. Текст, который видит проба

Агент не отдаёт JSON паку. `render_password` собирает текст команды `show continent password-policy`. Если политик несколько, в `min_length` попадает минимум. Фикстура `src/backend/pack_tests/kontinent-4.yaml` хранит уже этот текст, снятый с лабораторного 4.2.1-653:

```yaml
show continent password-policy: |
  object: passwordpolicy
  min_length: 12
  wrong_try_count: 5
  wrong_try_block: 900
  blocked_days: 0
  lockout: on
```

Проба в паке:

```yaml
probe:
  type: cli_config
  cmd: show continent password-policy
  require: '(?m)^min_length:'
  match: '^min_length:\s*(\d+)'
assert: { op: gte, value: 8 }
severity: medium
```

`probe_cli_config` требует, чтобы в тексте была строка `min_length:`, и забирает число в группу. Здесь value = `12`.

### 3. Сравнение

`check_assertion` для `gte`: оба значения числа, 12 ≥ 8 → `pass`. Фикстура так и помечена: `kontinent4.password_min_length: pass`.

Второй кейс того же файла подставляет `min_length: 4` и `lockout: off`. Ожидание длины — `fail`. Это тот же оператор, другое фактическое число.

`describe_assertion` для ожидания пишет `>= 8`. Срок для `medium` — «до 4 недель», после экспертной оценки. Пункт методики в паке — `УСИ.4`.

Прошивка из той же фикстуры: продукт `комплекс безопасности «континент». версия 4`, версия `4.2.1-653`. В сопоставлении с БДУ хвост `-653` отрезается как ревизия, сравнивается `4.2.1`.

Уровень пака `draft`: в YAML нет `verified_on`, хотя текст фикстуры взят с лабораторного ЦУС.

## В. Находка БДУ: OpenSSH 9.6p1

Цифры — тест `test_api_lists_potential_vulnerabilities_with_criticality` и XML `SAMPLE_XML` в `src/backend/tests/test_bdu.py`. Это маленькая копия выгрузки, не боевые 90 тысяч записей. Алгоритм тот же, что у `import_bdu` и `refresh_findings`.

### 1. Что лежит на активе

Тест пишет в `software` хоста `web-01` (`asset_type` `linux-server`):

| Пакет | Версия |
|---|---|
| `openssh-server` | `1:9.6p1-3ubuntu13.19` |
| `openssh-client` | `1:9.6p1-3ubuntu13.19` |
| `linux-image-6.8.0-142-generic` | `6.8.0-142.142` |
| `bash` | `5.2.21-2ubuntu4` |

### 2. Имя и версия

`product_for_package`: оба пакета OpenSSH попадают в алиас `openssh`. Ядро попадает в `NOT_COMPARED` и в находки не идёт. `upstream_version("1:9.6p1-3ubuntu13.19")` даёт `9.6p1`: эпоха `1:` и ревизия `-3ubuntu13.19` отрезаны. Клиент и сервер одной версии склеиваются в одну строку пакетов.

### 3. Запись БДУ

Из `SAMPLE_XML`:

```xml
<identifier>BDU:2024-04914</identifier>
<name>Уязвимость OpenSSH, позволяющая нарушителю выполнить произвольный код</name>
<version>от 8.6 до 9.8</version>
<cvss3><vector score="8,1">...</vector></cvss3>
<exploit_status>Существует</exploit_status>
```

`parse_bdu_version("от 8.6 до 9.8")` — диапазон с включённым низом и невключённым верхом. `9.6p1` внутри, `9.8` и `8.5` снаружи (это отдельный тест `parse_bdu_version`). Запись «до 7.4» (`BDU:2019-00001`) этот хост не цепляет. Строка «24.04 LTS» при импорте пропускается: это не диапазон версии.

### 4. V

Хост один, тип `linux-server`, тега `internet-facing` нет. Комментарий теста:

- Icvss = 8,1 (CVSS 3, не 10 из CVSS 2)
- K = 0,7, L = 1,0 (уязвимость на единственном активе), P = 0,6
- Iinfr = 0,5×0,7 + 0,2×1,0 + 0,3×0,6 = 0,73
- Iat = 0,3 («Существует»), Iimp = 0,5 (в названии «выполнить произвольный код»)
- V = 8,1 × 0,73 × 0,8 = 4,73

Тест требует `criticality.v == 4.73`, `level == "medium"`, `deadline == "до 4 недель"`. Пакеты в ответе: `openssh-client, openssh-server`, сравнимая версия `9.6p1`, CVE `CVE-2024-6387`. В `not_compared` есть причина про ядро.

Соседний тест `test_criticality_formula` на других входных числах (CVSS 9,8, тот же сервер) получает V = 5,72 и уровень `high`. Это другая карточка, не эта находка.

Процент харденинга от этой строки не меняется. Она живёт в `asset_vulnerabilities` и на странице «Уязвимости».

## Г. Тот же root после принятого риска

Тест `test_accepting_risk_updates_current_state_and_dashboard_at_once` в `src/backend/tests/test_risk_exceptions.py` использует тот же `pack_payload`: две проверки, root нарушен.

До принятия дашборд показывает `failedChecks == 1`.

Администратор шлёт POST с `check_key = ssh.permit_root_login` и причиной «Вход root нужен для аварийного доступа» (длиннее 10 символов).

После этого тест проверяет:

- статус строки по-прежнему `fail` (факт `yes` не переписан);
- в строке есть `risk_exception` с этой причиной, не на всю организацию;
- дашборд: passed 1, failed 0, accepted 1, не проверено 0, покрытие 100;
- `compliance_score` отчёта организации стал 100 без нового прогона агента.

Следующий приём (`test_next_scan_records_accepted_risk_in_snapshot`) пишет в `scan_snapshots` `failed = 0`, `accepted_risks = 1`, `compliance_score = 100`, а в `scan_check_results` статус всё ещё `fail` и `risk_exception_id` заполнен.

Процент стал 1 / 1 = 100, потому что единственный fail вынут из знаменателя. Нарушение на экране остаётся. Для боевого пака с `severity: high` срок у этой строки больше не показывается: `get_remediation` и `ResultRow.fix` для принятого риска возвращают пусто.
