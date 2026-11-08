# Комплект раскатки Windows через GPO

Сценарий, который выполняет компьютер: [`gpo-startup.ps1`](gpo-startup.ps1).

Его же проверяет CI (Windows PowerShell 5.1) и публикует `deploy/publish_agent.sh` как
`/downloads/gpo-startup.ps1`. Второй копии сценария в репозитории нет.

| Файл | Назначение |
|---|---|
| `gpo-startup.ps1` | Сценарий автозагрузки. Параметры — в шапке файла |
| `gpo-parameters.txt` | Шаблон одной строки параметров. Боевой пин и адрес на 8 ноября 2026; живые значения страница «Агенты» берёт из `version.json` |
| [`../../../docs/gpo-rollout.md`](../../../docs/gpo-rollout.md) | Пошаговая инструкция для домена |

`hardening-agent.exe` в git не хранится. Его собирает workflow `.github/workflows/windows-release.yml`
по тегу `agent-*` или `v*` и кладёт в GitHub Release. На сервере тот же файл отдаёт
`/downloads/hardening-agent.exe` после `deploy/publish_agent.sh`.
