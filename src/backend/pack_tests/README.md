# Образцы (фикстуры) паков

Прогон пака на образцах файлов и вывода команд — без живого хоста и без устройства:

```bash
cd src/backend
python -m app.commands.pack validate            # все паки в app/packs
python -m app.commands.pack test                # все фикстуры в pack_tests/
python -m app.commands.pack test pack_tests/docker.yaml
```

Под капотом работают **настоящие пробы агента** (`agent/probes.py`) и **настоящая оценка сервера**
(`evaluate_pack`). Подменён только транспорт: файлы, права и вывод команд берутся из фикстуры.
Команды при этом проходят белый список агента: фикстура не может «разрешить» команду, которую
агент на хосте не выполнит. Такая проверка в прогоне получит `error`.

Фикстуры лежат отдельно от `app/packs/`, потому что реестр загружает оттуда все `*.yaml` как паки.

## Формат

```yaml
pack: docker            # id пака
version: 1.1.0          # необязательно; по умолчанию последняя версия

base:                   # общее для всех сценариев (необязательно)
  files:    { /путь: "содержимое" }                    # file_kv, file_regex
  stats:    { /путь: "640" }                           # file_stat: mode, или { mode: "640", uid: 0, gid: 0 }
  commands: { "argv через пробел": "stdout" }          # cmd_regex, cmd_foreach, service_state
            # или { stdout: "...", stderr: "...", code: 1 }
  cli:      { "show running-config": "..." }           # cli_config и cmd_regex по ssh

cases:
  - name: что проверяем
    files/stats/commands/cli: ...   # поверх base
    drop: [/путь]                   # убрать файл из base (нет файла)
    drop_commands: ["команда"]      # убрать команду из base
    detect: true                    # необязательно: должен ли пак распознать платформу
    expect:                         # ожидаемые статусы: pass | fail | error
      docker.no_host_pid: fail
```

Для ssh-пака команда, которой нет в `cli`, отвечает `% Invalid input…`, как устройство без прав.

## Что требует CI (`tests/test_pack_authoring.py`)

- `validate` не находит ошибок ни в одном паке;
- у последней версии каждого пака есть фикстура, и все её сценарии проходят;
- каждая проверка хотя бы раз показана и в `pass`, и в `fail`. Одно `pass` ничего не говорит о
  том, что проверка умеет ловить нарушение.

Новая проверка без образцов нарушения и соблюдения в `main` не попадёт.
