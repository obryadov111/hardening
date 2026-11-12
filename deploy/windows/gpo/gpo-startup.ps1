<#
Агент «Харденинг» — сценарий запуска компьютера для групповой политики (GPO). Выполняется от SYSTEM.
Загрузку ПК не держит: сразу ставит постоянную задачу «Hardening agent bootstrap» и выходит.
Задача (SYSTEM, один экземпляр) повторяет установку и регистрацию каждые 15–30 минут, пока хост не
зарегистрируется. Секрет площадки в аргументы задачи не пишется и в журнал не попадает: файл site.key
в каталоге состояния, доступ только у SYSTEM и администраторов.

  GPO: Конфигурация компьютера → Политики → Конфигурация Windows → Сценарии → Автозагрузка → PowerShell:
  этот файл, параметры (одной строкой):
    -Server https://audit.example.ru -SiteKey yak_... -PackPublicKey ... -Pin sha256//ТЕКУЩИЙ,sha256//РЕЗЕРВНЫЙ -Share \\corp.local\NETLOGON\Hardening
  -Pin можно повторить или перечислить через запятую. Пустой список — только для ещё не зарегистрированного
  хоста берётся server_pin из version.json. Уже заданный список из-за version.json не подменяется:
  при TLS_PIN_MISMATCH доверие не ослабляется.
  -Schedule Weekly — прогон раз в неделю (понедельник) вместо ежедневного.
  -CollectIdentity — собирать сотрудника за ПК (ПДн; по умолчанию выключено).
  -InitialJitterMaxSeconds 900 — U(0, N) перед первой регистрацией и первым сбором (делает агент).
  -RetryBudgetSeconds 1800 — бюджет повторов одного запуска.
  -BootstrapEveryMinutes 15 и -BootstrapRandomDelayMinutes 15 — период повтора 15–30 минут.
  -CollectTime 07:30 и -CollectRandomDelayHours 2 — единственное место, где заданы время сбора и разброс.
  Сервер площадки ночью выключен (примерно 18:30–07:00, Екатеринбург), поэтому сбор днём.
  Задача «Hardening agent spool» в это же окно досылает очередь командой flush-spool:
  каждые 30 минут плюс случайные 0–30 минут, 10 часов, без нового полного сбора.

Журнал — C:\ProgramData\HardeningAgent\gpo-startup.log, строки stage=… code=….
Ключ площадки в параметрах GPO виден пользователям домена (SYSVOL) — короткий срок на время раскатки.
#>
param(
    [Parameter(Mandatory = $true)][string]$Server,
    [string]$SiteKey = "",
    [string]$PackPublicKey = "",
    [string[]]$Pin = @(),
    [string]$Share = "",
    [string]$Environment = "prod",
    [string]$Proxy = "",
    [ValidateSet("Daily", "Weekly")][string]$Schedule = "Daily",
    [switch]$CollectIdentity,
    [string]$InstallDir = "C:\Program Files\Hardening",
    [string]$StateDir = "C:\ProgramData\HardeningAgent",
    [switch]$AllowHttp,
    [switch]$Worker,
    [int]$InitialJitterMaxSeconds = 900,
    [int]$RetryBudgetSeconds = 1800,
    [int]$BootstrapEveryMinutes = 15,
    [int]$BootstrapRandomDelayMinutes = 15,
    # Время сбора и разброс. Триггеры читают эти параметры, отдельной константы времени в коде нет.
    [string]$CollectTime = "07:30",
    [ValidateRange(0, 12)][int]$CollectRandomDelayHours = 2,
    [switch]$Library
)
$ErrorActionPreference = "Stop"
$BootstrapTaskName = "Hardening agent bootstrap"
$CollectTaskName = "Hardening agent"
$SpoolTaskName = "Hardening agent spool"
# Досылка очереди. Интервал, случайная добавка и длина дневного окна задаются только здесь.
$SpoolEveryMinutes = 30
$SpoolRandomDelayMinutes = 30
$SpoolWindowHours = 10
$SpoolExecutionMinutes = 15
$script:Secret = $SiteKey
$script:Pins = @()
$script:Mutex = $null

function Write-Log([string]$message) {
    if (-not (Test-Path $StateDir)) { New-Item -ItemType Directory -Force -Path $StateDir | Out-Null }
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $message" | Out-File -FilePath (Join-Path $StateDir "gpo-startup.log") -Append -Encoding utf8
}

function Redact([string]$Text) {
    if (-not $Text) { return "" }
    $secret = $script:Secret
    if ($secret -and $secret.Length -ge 4) { return $Text.Replace($secret, "***") }
    return $Text
}

function Write-Stage([string]$Stage, [string]$Code, [string]$Detail) {
    $line = "stage={0} code={1}" -f $Stage, $Code
    if ($Detail) { $line = "{0} {1}" -f $line, (Redact $Detail) }
    Write-Log $line
}

function Format-TaskArg([string]$Value) {
    if ($null -eq $Value) { return '""' }
    if ($Value -match '[\s"]') { return '"' + ($Value.Replace('"', '`"')) + '"' }
    return $Value
}

function ConvertTo-PinList {
    param([string[]]$Raw)
    $seen = @{}
    $out = @()
    foreach ($item in @($Raw)) {
        if (-not $item) { continue }
        foreach ($part in ($item -split ',')) {
            $pin = $part.Trim()
            if ($pin -and -not $seen.ContainsKey($pin)) {
                $seen[$pin] = $true
                $out += $pin
            }
        }
    }
    return $out
}

function Protect-StateDir {
    if (-not (Test-Path $StateDir)) { New-Item -ItemType Directory -Force -Path $StateDir | Out-Null }
    & icacls $StateDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "не удалось ограничить доступ к $StateDir" }
}

function Save-SiteKey([string]$Value) {
    $path = Join-Path $StateDir "site.key"
    [IO.File]::WriteAllBytes($path, [Text.Encoding]::UTF8.GetBytes($Value))
    & icacls $path /inheritance:r /grant:r "*S-1-5-18:F" "*S-1-5-32-544:F" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "не удалось ограничить доступ к site.key" }
}

function Read-SiteKey {
    $path = Join-Path $StateDir "site.key"
    if (-not (Test-Path $path)) { return "" }
    return [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($path)).Trim()
}

function Remove-SiteKey {
    $path = Join-Path $StateDir "site.key"
    if (Test-Path $path) {
        Remove-Item $path -Force
        Write-Stage "secret" "REMOVED" "path=site.key"
    }
}

function Get-Sha256([string]$path) { (Get-FileHash -Algorithm SHA256 -Path $path).Hash.ToLowerInvariant() }

function Set-RuntimeEnv {
    [Environment]::SetEnvironmentVariable("HARDENING_INITIAL_JITTER_MAX", "$InitialJitterMaxSeconds", "Machine")
    [Environment]::SetEnvironmentVariable("HARDENING_RETRY_BUDGET_SECONDS", "$RetryBudgetSeconds", "Machine")
    $env:HARDENING_INITIAL_JITTER_MAX = "$InitialJitterMaxSeconds"
    $env:HARDENING_RETRY_BUDGET_SECONDS = "$RetryBudgetSeconds"
    if ($PackPublicKey) {
        $trimmed = $PackPublicKey.Trim()
        [Environment]::SetEnvironmentVariable("HARDENING_PACK_PUBLIC_KEY", $trimmed, "Machine")
        $env:HARDENING_PACK_PUBLIC_KEY = $trimmed
    }
    if ($Proxy) {
        [Environment]::SetEnvironmentVariable("HARDENING_PROXY", $Proxy, "Machine")
        $env:HARDENING_PROXY = $Proxy
    }
    # Пин из политики — в окружение задачи сбора. Пустой список здесь не затирает уже записанный пин
    # и не подставляет ключ, увиденный при TLS-inspection.
    if ($script:Pins.Count -gt 0) {
        $joined = $script:Pins -join ","
        [Environment]::SetEnvironmentVariable("HARDENING_PIN_SHA256", $joined, "Machine")
        $env:HARDENING_PIN_SHA256 = $joined
    }
}

function Get-BootstrapArguments {
    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($token in @(
            "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", (Format-TaskArg $PSCommandPath), "-Worker",
            "-Server", (Format-TaskArg $Server), "-Environment", (Format-TaskArg $Environment),
            "-Schedule", $Schedule, "-InstallDir", (Format-TaskArg $InstallDir), "-StateDir", (Format-TaskArg $StateDir),
            "-InitialJitterMaxSeconds", "$InitialJitterMaxSeconds", "-RetryBudgetSeconds", "$RetryBudgetSeconds",
            "-BootstrapEveryMinutes", "$BootstrapEveryMinutes", "-BootstrapRandomDelayMinutes", "$BootstrapRandomDelayMinutes",
            "-CollectTime", (Format-TaskArg $CollectTime), "-CollectRandomDelayHours", "$CollectRandomDelayHours"
        )) { [void]$parts.Add($token) }
    if ($Share) { [void]$parts.Add("-Share"); [void]$parts.Add((Format-TaskArg $Share)) }
    if ($Proxy) { [void]$parts.Add("-Proxy"); [void]$parts.Add((Format-TaskArg $Proxy)) }
    if ($PackPublicKey) { [void]$parts.Add("-PackPublicKey"); [void]$parts.Add((Format-TaskArg $PackPublicKey.Trim())) }
    foreach ($pin in (ConvertTo-PinList $Pin)) {
        [void]$parts.Add("-Pin")
        [void]$parts.Add((Format-TaskArg $pin))
    }
    if ($CollectIdentity) { [void]$parts.Add("-CollectIdentity") }
    if ($AllowHttp) { [void]$parts.Add("-AllowHttp") }
    # Ключ площадки в этот список не входит: он только в site.key
    return ($parts -join " ")
}

function Register-BootstrapTask {
    $argument = Get-BootstrapArguments
    if ($argument -match '(?i)(^|\s)-SiteKey(\s|$)') { throw "аргументы задачи содержат -SiteKey" }
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $argument
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
        -RepetitionInterval (New-TimeSpan -Minutes $BootstrapEveryMinutes) `
        -RepetitionDuration (New-TimeSpan -Days 1)
    if ($BootstrapRandomDelayMinutes -gt 0) {
        $trigger.RandomDelay = "PT{0}M" -f [int]$BootstrapRandomDelayMinutes
    }
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 90)
    Register-ScheduledTask -TaskName $BootstrapTaskName -Action $action -Trigger $trigger -Settings $settings `
        -User "SYSTEM" -RunLevel Highest -Force | Out-Null
    # Duration в сутки оборвал бы повтор. Пустой Duration в XML — повтор, пока задачу не снимут.
    $xml = Export-ScheduledTask -TaskName $BootstrapTaskName
    if ($xml -is [System.Array]) { $xml = $xml -join "`n" }
    $xml = $xml -replace '<StopAtDurationEnd>true</StopAtDurationEnd>', '<StopAtDurationEnd>false</StopAtDurationEnd>'
    $xml = $xml -replace '<Duration>.*?</Duration>', ''
    Register-ScheduledTask -TaskName $BootstrapTaskName -Xml $xml -Force | Out-Null
}

function ConvertTo-CollectClock([string]$Value) {
    if ($Value -notmatch '^(\d{1,2}):(\d{2})$') { throw "CollectTime должен быть ЧЧ:ММ, получено: $Value" }
    $hour = [int]$Matches[1]
    $minute = [int]$Matches[2]
    if ($hour -gt 23 -or $minute -gt 59) { throw "CollectTime вне суток: $Value" }
    return "{0:D2}:{1:D2}" -f $hour, $minute
}

function Get-TriggerClock([string]$Boundary) {
    if ($Boundary -match 'T(\d{1,2}):(\d{2})') {
        return "{0:D2}:{1:D2}" -f [int]$Matches[1], $Matches[2]
    }
    return ""
}

function ConvertTo-HourDelay([int]$Hours) {
    if ($Hours -le 0) { return "PT0S" }
    return "PT{0}H" -f $Hours
}

function ConvertTo-MinuteDelay([int]$Minutes) {
    if ($Minutes -le 0) { return "PT0S" }
    return "PT{0}M" -f $Minutes
}

function Test-IgnoreNew($Settings) {
    $instances = [string]$Settings.MultipleInstances
    return ($instances -eq "IgnoreNew" -or $instances -eq "2")
}

function Get-TaskXml([string]$Name) {
    $task = Get-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue
    if (-not $task) { return "" }
    $xml = Export-ScheduledTask -TaskName $Name
    if ($xml -is [System.Array]) { $xml = $xml -join "`n" }
    return [string]$xml
}

function Initialize-CollectClock {
    $script:CollectTime = ConvertTo-CollectClock $CollectTime
    if ($script:CollectRandomDelayHours -lt 0) { $script:CollectRandomDelayHours = 0 }
}

function Get-CollectArguments {
    $arguments = "--api-url $Server --environment $Environment --use-packs --state-dir `"$StateDir`""
    if ($AllowHttp -and $Server.StartsWith("http://")) { $arguments += " --allow-http" }
    if ($CollectIdentity) { $arguments += " --collect-identity" }
    return $arguments
}

function Get-SpoolArguments {
    # flush-spool не собирает факты и не запрашивает манифесты.
    $arguments = "flush-spool --api-url $Server --environment $Environment --state-dir `"$StateDir`""
    if ($AllowHttp -and $Server.StartsWith("http://")) { $arguments += " --allow-http" }
    return $arguments
}

function New-CollectTrigger {
    $delay = New-TimeSpan -Hours $CollectRandomDelayHours
    if ($Schedule -eq "Weekly") {
        return New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At $CollectTime -RandomDelay $delay
    }
    return New-ScheduledTaskTrigger -Daily -At $CollectTime -RandomDelay $delay
}

function Test-CollectTaskCurrent([string]$ExePath, [string]$Arguments) {
    $existing = Get-ScheduledTask -TaskName $CollectTaskName -ErrorAction SilentlyContinue
    if (-not $existing -or $existing.Actions.Count -lt 1 -or $existing.Triggers.Count -lt 1) { return $false }
    $triggerClass = if ($Schedule -eq "Weekly") { "MSFT_TaskWeeklyTrigger" } else { "MSFT_TaskDailyTrigger" }
    $trigger = $existing.Triggers[0]
    $available = $false
    try { $available = [bool]$existing.Settings.StartWhenAvailable } catch { $available = $false }
    return ($existing.Actions[0].Execute -eq $ExePath -and $existing.Actions[0].Arguments -eq $Arguments -and
        $trigger.CimClass.CimClassName -eq $triggerClass -and
        [string]$existing.Settings.ExecutionTimeLimit -eq "PT1H" -and
        [string]$trigger.RandomDelay -eq (ConvertTo-HourDelay $CollectRandomDelayHours) -and
        (Get-TriggerClock ([string]$trigger.StartBoundary)) -eq $CollectTime -and
        $available -and (Test-IgnoreNew $existing.Settings))
}

function Test-SpoolRepetition($Trigger) {
    $interval = ConvertTo-MinuteDelay $SpoolEveryMinutes
    $duration = "PT{0}H" -f [int]$SpoolWindowHours
    $rep = $Trigger.Repetition
    $gotInterval = ""
    $gotDuration = ""
    $stop = ""
    if ($rep) {
        $gotInterval = [string]$rep.Interval
        $gotDuration = [string]$rep.Duration
        $stop = [string]$rep.StopAtDurationEnd
    }
    $durationOk = ($gotDuration -eq $duration) -or ($gotDuration.StartsWith($duration))
    $stopOk = ($stop -eq "True") -or ($stop -eq "true")
    if ($gotInterval -eq $interval -and $durationOk -and $stopOk) { return $true }
    # CIM иногда не заполняет длительность, хотя в XML она записана.
    $xml = Get-TaskXml $SpoolTaskName
    return ($xml -match "<Interval>$interval</Interval>" -and $xml -match "<Duration>$duration</Duration>" -and
        $xml -match "<StopAtDurationEnd>true</StopAtDurationEnd>")
}

function Test-SpoolTaskCurrent([string]$ExePath, [string]$Arguments) {
    $existing = Get-ScheduledTask -TaskName $SpoolTaskName -ErrorAction SilentlyContinue
    if (-not $existing -or $existing.Actions.Count -lt 1 -or $existing.Triggers.Count -lt 1) { return $false }
    $trigger = $existing.Triggers[0]
    $available = $false
    try { $available = [bool]$existing.Settings.StartWhenAvailable } catch { $available = $false }
    return ($existing.Actions[0].Execute -eq $ExePath -and $existing.Actions[0].Arguments -eq $Arguments -and
        $trigger.CimClass.CimClassName -eq "MSFT_TaskDailyTrigger" -and
        [string]$existing.Settings.ExecutionTimeLimit -eq (ConvertTo-MinuteDelay $SpoolExecutionMinutes) -and
        [string]$trigger.RandomDelay -eq (ConvertTo-MinuteDelay $SpoolRandomDelayMinutes) -and
        (Get-TriggerClock ([string]$trigger.StartBoundary)) -eq $CollectTime -and
        $available -and (Test-IgnoreNew $existing.Settings) -and (Test-SpoolRepetition $trigger))
}

function Test-FlushSpoolSupported([string]$ExePath) {
    if (-not (Test-Path $ExePath)) { return $false }
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        & $ExePath flush-spool --help *> $null
        return ($LASTEXITCODE -eq 0)
    } finally {
        $ErrorActionPreference = $previous
    }
}

function Repair-SpoolTaskXml {
    $interval = ConvertTo-MinuteDelay $SpoolEveryMinutes
    $duration = "PT{0}H" -f [int]$SpoolWindowHours
    $delay = ConvertTo-MinuteDelay $SpoolRandomDelayMinutes
    $xml = Get-TaskXml $SpoolTaskName
    if (-not $xml) { return }
    try {
    if ($xml -notmatch '<Repetition>') {
        $block = "      <Repetition><Interval>$interval</Interval><Duration>$duration</Duration><StopAtDurationEnd>true</StopAtDurationEnd></Repetition>"
        $xml = $xml -replace '</CalendarTrigger>', ($block + '</CalendarTrigger>')
    } else {
        if ($xml -match '<Interval>') {
            $xml = $xml -replace '<Interval>.*?</Interval>', "<Interval>$interval</Interval>"
        } else {
            $xml = $xml -replace '<Repetition>', "<Repetition><Interval>$interval</Interval>"
        }
        if ($xml -match '<Duration>') {
            $xml = $xml -replace '<Duration>.*?</Duration>', "<Duration>$duration</Duration>"
        } else {
            $xml = $xml -replace '</Interval>', "</Interval><Duration>$duration</Duration>"
        }
        if ($xml -match '<StopAtDurationEnd>') {
            $xml = $xml -replace '<StopAtDurationEnd>.*?</StopAtDurationEnd>', '<StopAtDurationEnd>true</StopAtDurationEnd>'
        } else {
            $xml = $xml -replace '</Repetition>', '<StopAtDurationEnd>true</StopAtDurationEnd></Repetition>'
        }
    }
    if ($xml -notmatch '<RandomDelay>') {
        $xml = $xml -replace '</StartBoundary>', "</StartBoundary><RandomDelay>$delay</RandomDelay>"
    } else {
        $xml = $xml -replace '<RandomDelay>.*?</RandomDelay>', "<RandomDelay>$delay</RandomDelay>"
    }
    Register-ScheduledTask -TaskName $SpoolTaskName -Xml $xml -Force | Out-Null
    } catch {
        Write-Stage "schedule" "SPOOL_XML" (Redact $_.Exception.Message)
    }
}

function Register-CollectTask([string]$ExePath, [string]$Arguments) {
    $action = New-ScheduledTaskAction -Execute $ExePath -Argument $Arguments
    $trigger = New-CollectTrigger
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours 1)
    Register-ScheduledTask -TaskName $CollectTaskName -Action $action -Trigger $trigger -Settings $settings `
        -User "SYSTEM" -RunLevel Highest -Force | Out-Null
    $delay = ConvertTo-HourDelay $CollectRandomDelayHours
    Write-Stage "schedule" "TASK_UPDATED" ("задача планировщика «Hardening agent» создана (расписание {0}, время {1}, разброс {2})" -f $Schedule, $CollectTime, $delay)
}

function Register-SpoolTask([string]$ExePath, [string]$Arguments) {
    $action = New-ScheduledTaskAction -Execute $ExePath -Argument $Arguments
    # В Windows PowerShell 5.1 повтор есть только у -Once. Дневному триггеру его дописывает XML.
    $trigger = New-ScheduledTaskTrigger -Daily -At $CollectTime -RandomDelay (New-TimeSpan -Minutes $SpoolRandomDelayMinutes)
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes $SpoolExecutionMinutes)
    Register-ScheduledTask -TaskName $SpoolTaskName -Action $action -Trigger $trigger -Settings $settings `
        -User "SYSTEM" -RunLevel Highest -Force | Out-Null
    Repair-SpoolTaskXml
    Write-Stage "schedule" "SPOOL_UPDATED" ("задача «{0}»: flush-spool каждые {1} мин, окно {2} ч, с {3}" -f $SpoolTaskName, $SpoolEveryMinutes, $SpoolWindowHours, $CollectTime)
}

function Update-CollectTask([string]$ExePath) {
    Initialize-CollectClock
    $arguments = Get-CollectArguments
    $collectSame = Test-CollectTaskCurrent $ExePath $arguments
    if (-not $collectSame) { Register-CollectTask $ExePath $arguments }
    $spoolArguments = Get-SpoolArguments
    $spoolSame = Test-SpoolTaskCurrent $ExePath $spoolArguments
    if ($spoolSame) {
        if ($collectSame) {
            Write-Stage "schedule" "TASK_UNCHANGED" ("schedule={0} collect={1} delay={2}" -f $Schedule, $CollectTime, (ConvertTo-HourDelay $CollectRandomDelayHours))
        }
        return
    }
    if (-not (Test-FlushSpoolSupported $ExePath)) {
        $stale = Get-ScheduledTask -TaskName $SpoolTaskName -ErrorAction SilentlyContinue
        if ($stale) { Unregister-ScheduledTask -TaskName $SpoolTaskName -Confirm:$false }
        Write-Stage "schedule" "SPOOL_SKIPPED" "exe без команды flush-spool: дневной сбор уже обновлён, досылка появится вместе с новым exe"
        if ($collectSame) {
            Write-Stage "schedule" "TASK_UNCHANGED" ("schedule={0} collect={1} delay={2}" -f $Schedule, $CollectTime, (ConvertTo-HourDelay $CollectRandomDelayHours))
        }
        return
    }
    Register-SpoolTask $ExePath $spoolArguments
    if ($collectSame) {
        Write-Stage "schedule" "TASK_UNCHANGED" ("schedule={0} collect={1} delay={2}" -f $Schedule, $CollectTime, (ConvertTo-HourDelay $CollectRandomDelayHours))
    }
}

function Get-HttpStatus($ErrorRecord) {
    try {
        $response = $ErrorRecord.Exception.Response
        if (-not $response) { return $null }
        return [int]$response.StatusCode
    } catch { return $null }
}

function Invoke-FullJitterRetry {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Action,
        [int]$BudgetSeconds,
        [string]$Stage,
        [string]$FailureCode
    )
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $attempt = 0
    $zeros = 0
    while ($true) {
        try { return (& $Action) }
        catch {
            $message = Redact ([string]$_.Exception.Message)
            $status = Get-HttpStatus $_
            # 4xx кроме 408/429 — отказ по существу, не «нет связи». 429 и обрыв (status пустой) повторяются.
            if ($status -ge 400 -and $status -lt 500 -and $status -ne 408 -and $status -ne 429) {
                Write-Stage $Stage $FailureCode ("http={0} {1}" -f $status, $message)
                throw
            }
            $elapsed = $clock.Elapsed.TotalSeconds
            $cap = 15 * [Math]::Pow(2, $attempt)
            if ($cap -gt 900) { $cap = 900 }
            $pause = Get-Random -Minimum 0 -Maximum ([int]$cap + 1)
            $remaining = $BudgetSeconds - $elapsed
            if ($remaining -le 0 -or $pause -gt $remaining) {
                Write-Stage $Stage $FailureCode ("attempt={0} сервер недоступен: {1}" -f $attempt, $message)
                throw
            }
            if ($pause -le 0) {
                $zeros++
                if ($zeros -gt 8) {
                    Write-Stage $Stage $FailureCode ("attempt={0} сервер недоступен: {1}" -f $attempt, $message)
                    throw
                }
            } else { $zeros = 0 }
            Write-Stage $Stage "RETRY" ("code=None pause_s={0} attempt={1} error={2}" -f $pause, ($attempt + 1), $message)
            if ($pause -gt 0) { Start-Sleep -Seconds $pause }
            $attempt++
        }
    }
}

function Get-PublishedVersion {
    $web = @{ UseBasicParsing = $true; TimeoutSec = 60; Uri = "$Server/downloads/version.json" }
    if ($Proxy) { $web.Proxy = $Proxy }
    $script:DownloadWeb = $web
    return Invoke-FullJitterRetry -BudgetSeconds $RetryBudgetSeconds -Stage "version" -FailureCode "VERSION_UNAVAILABLE" -Action {
        Invoke-RestMethod @script:DownloadWeb
    }
}

function Save-AgentExe([string]$Uri, [string]$Destination) {
    $web = @{ UseBasicParsing = $true; TimeoutSec = 60; Uri = $Uri; OutFile = $Destination }
    if ($Proxy) { $web.Proxy = $Proxy }
    $script:DownloadWeb = $web
    Invoke-FullJitterRetry -BudgetSeconds $RetryBudgetSeconds -Stage "download" -FailureCode "DOWNLOAD_UNAVAILABLE" -Action {
        Invoke-WebRequest @script:DownloadWeb | Out-Null
    } | Out-Null
}

function Install-Agent([string]$ExePath, $Published) {
    $file = $Published.files | Where-Object { $_.platform -eq "windows" } | Select-Object -First 1
    if (-not $file) {
        Write-Stage "install" "AGENT_NOT_PUBLISHED" ""
        throw "на сервере не опубликован агент для Windows"
    }
    if ((Test-Path $ExePath) -and (Get-Sha256 $ExePath) -eq $file.sha256) {
        Write-Stage "install" "UP_TO_DATE" "sha256=$($file.sha256)"
        return
    }
    if ($Share) {
        $src = Join-Path $Share $file.name
        $actual = Get-Sha256 $src
        if ($actual -ne $file.sha256) {
            Write-Stage "install" "SHA256_MISMATCH" "actual=$actual expected=$($file.sha256)"
            throw "SHA-256 агента не совпал с опубликованным ($actual вместо $($file.sha256)) — файл не установлен"
        }
        New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
        Copy-Item -Path $src -Destination $ExePath -Force
        Write-Stage "install" "INSTALLED" "установлен агент версии $($file.version)"
        return
    }
    $tmp = Join-Path $env:TEMP "hardening-agent-$([guid]::NewGuid()).exe"
    Save-AgentExe -Uri "$Server/downloads/$($file.name)" -Destination $tmp
    $actual = Get-Sha256 $tmp
    if ($actual -ne $file.sha256) {
        Remove-Item $tmp -Force
        Write-Stage "install" "SHA256_MISMATCH" "actual=$actual expected=$($file.sha256)"
        throw "SHA-256 агента не совпал с опубликованным ($actual вместо $($file.sha256)) — файл не установлен"
    }
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    Move-Item -Path $tmp -Destination $ExePath -Force
    Write-Stage "install" "INSTALLED" "установлен агент версии $($file.version)"
}

function Get-PinLockPath { Join-Path $StateDir "pin-mismatch.lock" }

function Resolve-Pins($Published, [bool]$AlreadyEnrolled) {
    $policy = @(ConvertTo-PinList $Pin)
    if ($policy.Count -gt 0) {
        # Список из политики сильнее и version.json, и замка после mismatch: так вводят проверенный резервный пин.
        $script:Pins = $policy
        Write-Stage "pin" "FROM_POLICY" ("count={0}" -f $policy.Count)
        return
    }
    $lockPath = Get-PinLockPath
    if (Test-Path $lockPath) {
        $locked = @(ConvertTo-PinList (Get-Content -Path $lockPath -Raw -ErrorAction SilentlyContinue))
        $script:Pins = $locked
        # Повторно не читаем server_pin: тело version.json на сомнительном маршруте нельзя использовать, чтобы снять mismatch.
        Write-Stage "pin" "LOCKED_AFTER_MISMATCH" ("count={0}" -f $locked.Count)
        return
    }
    if (-not $AlreadyEnrolled -and $Published -and $Published.server_pin) {
        $script:Pins = @([string]$Published.server_pin)
        Write-Stage "pin" "FROM_PUBLISHED" "count=1"
        return
    }
    $script:Pins = @()
    if (-not $AlreadyEnrolled) { Write-Stage "pin" "EMPTY" "" }
}

function Lock-PinsAfterMismatch {
    if ($script:Pins.Count -lt 1) { return }
    Set-Content -Path (Get-PinLockPath) -Value ($script:Pins -join ",") -Encoding ascii
}

function Invoke-Enroll([string]$ExePath) {
    if (-not $script:Secret) {
        Write-Stage "enroll" "SITE_KEY_MISSING" ""
        return 1
    }
    # Пины и бюджет повторов — в переменных окружения: их читает агент, а новые флаги командной строки
    # старый exe отверг бы. Список пинов в аргументы процесса не копируется второй раз.
    $enroll = @("--api-url", $Server, "--environment", $Environment, "--api-key", $script:Secret, "--state-dir", $StateDir, "--enroll")
    if ($Proxy) { $enroll += @("--proxy", $Proxy) }
    if ($AllowHttp -and $Server.StartsWith("http://")) { $enroll += "--allow-http" }
    Write-Stage "enroll" "BEGIN" ("pins={0}" -f $script:Pins.Count)
    $ErrorActionPreference = "Continue"
    $output = (& $ExePath @enroll 2>&1 | ForEach-Object { "$_" }) -join " "
    $code = $LASTEXITCODE
    $ErrorActionPreference = "Stop"
    $output = Redact $output
    if ($output -match "TLS_PIN_MISMATCH" -or $code -eq 76) {
        # Один проход. Увиденный ключ в доверенные не пишется; version.json больше не выбирает пин.
        # Подсказка hint= (антивирус или шлюз) только для журнала.
        Lock-PinsAfterMismatch
        Write-Stage "enroll" "TLS_PIN_MISMATCH" $output
        if ($output -match "hint=(.+)$") {
            Write-Stage "enroll" "TLS_INSPECTION" $Matches[1].Trim()
        }
        return 76
    }
    if ($code -eq 0) {
        Write-Stage "enroll" "OK" $output
        return 0
    }
    if ($code -eq 75) {
        Write-Stage "enroll" "ENROLL_TRANSIENT" ("exit=75 {0}" -f $output)
        return 75
    }
    Write-Stage "enroll" "ENROLL_REJECTED" ("exit={0} {1}" -f $code, $output)
    return 1
}

function Start-FirstCollect {
    $marker = Join-Path $StateDir "first-collect.started"
    if (Test-Path $marker) {
        Write-Stage "collect" "SKIPPED" ""
        return
    }
    Start-ScheduledTask -TaskName $CollectTaskName | Out-Null
    Set-Content -Path $marker -Value (Get-Date -Format o) -Encoding ascii
    Write-Stage "collect" "STARTED" "первый прогон запущен"
}

function Complete-IfEnrolled([string]$ExePath) {
    Update-CollectTask $ExePath
    Start-FirstCollect
    Remove-SiteKey
    $lockPath = Get-PinLockPath
    if (Test-Path $lockPath) { Remove-Item $lockPath -Force }
    Unregister-ScheduledTask -TaskName $BootstrapTaskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Stage "done" "OK" ""
}

function Invoke-BootstrapWorker {
    Initialize-CollectClock
    $hostFile = Join-Path $StateDir "host.json"
    $already = Test-Path $hostFile
    $published = $null
    try {
        $published = Get-PublishedVersion
        Write-Stage "version" "DOWNLOAD_OK" ""
    } catch {
        if ($already -and (Test-Path (Join-Path $InstallDir "hardening-agent.exe"))) {
            Write-Stage "version" "SKIPPED_ALREADY_ENROLLED" (Redact $_.Exception.Message)
        } else {
            Write-Stage "done" "VERSION_UNAVAILABLE" "retry=scheduled"
            return 75
        }
    }
    $exe = Join-Path $InstallDir "hardening-agent.exe"
    Resolve-Pins $published $already
    if ($published) { Install-Agent $exe $published }
    Set-RuntimeEnv
    if (-not (Test-Path $exe)) {
        Write-Stage "done" "AGENT_MISSING" "retry=scheduled"
        return 1
    }
    if (-not (Test-Path $hostFile)) {
        $code = Invoke-Enroll $exe
        if ($code -ne 0) {
            $done = "ENROLL_REJECTED"
            if ($code -eq 75) { $done = "ENROLL_TRANSIENT" }
            if ($code -eq 76) { $done = "TLS_PIN_MISMATCH" }
            Write-Stage "done" $done "retry=scheduled no_trust_change=1"
            return $code
        }
    } else {
        Write-Stage "enroll" "ALREADY_ENROLLED" ""
    }
    if (-not (Test-Path $hostFile)) {
        Write-Stage "done" "ENROLL_REJECTED" "host.json не появился"
        return 1
    }
    Complete-IfEnrolled $exe
    return 0
}

function Enter-WorkerLock {
    $created = $false
    $script:Mutex = New-Object System.Threading.Mutex($false, "Global\HardeningAgentBootstrap", [ref]$created)
    try { return $script:Mutex.WaitOne(0) }
    catch {
        $inner = $_.Exception.InnerException
        if ($_.Exception -is [System.Threading.AbandonedMutexException] -or $inner -is [System.Threading.AbandonedMutexException]) {
            return $true
        }
        throw
    }
}

function Invoke-Startup {
    Initialize-CollectClock
    if (-not $SiteKey) {
        Write-Stage "startup" "SITE_KEY_MISSING" ""
        return 1
    }
    if (-not $AllowHttp -and -not $Server.StartsWith("https://")) {
        Write-Stage "startup" "HTTP_REQUIRED" "Server должен быть https://"
        return 1
    }
    Protect-StateDir
    $script:Pins = @(ConvertTo-PinList $Pin)
    Save-SiteKey $SiteKey
    Write-Stage "secret" "STORED" "path=site.key"
    Set-RuntimeEnv
    Register-BootstrapTask
    Write-Stage "startup" "TASK_SCHEDULED" ("task={0} every_min={1} random_delay_min={2}" -f $BootstrapTaskName, $BootstrapEveryMinutes, $BootstrapRandomDelayMinutes)
    $running = Get-ScheduledTask -TaskName $BootstrapTaskName -ErrorAction SilentlyContinue
    if ($running -and $running.State -eq "Running") {
        Write-Stage "startup" "ALREADY_RUNNING" "boot=not_blocked"
    } else {
        Start-ScheduledTask -TaskName $BootstrapTaskName | Out-Null
        Write-Stage "startup" "TASK_STARTED" "boot=not_blocked"
    }
    return 0
}

if ($Library) { return }

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false
$Server = $Server.TrimEnd("/")
if ($InitialJitterMaxSeconds -lt 0) { $InitialJitterMaxSeconds = 0 }
if ($RetryBudgetSeconds -lt 0) { $RetryBudgetSeconds = 0 }
if ($BootstrapEveryMinutes -lt 1) { $BootstrapEveryMinutes = 15 }
if ($BootstrapRandomDelayMinutes -lt 0) { $BootstrapRandomDelayMinutes = 0 }

if (-not $Worker) {
    try { exit (Invoke-Startup) }
    catch {
        Write-Stage "startup" "FAILED" (Redact $_.Exception.Message)
        exit 1
    }
}

if (-not $script:Secret) {
    Protect-StateDir
    $script:Secret = Read-SiteKey
    $SiteKey = $script:Secret
}
$locked = Enter-WorkerLock
if (-not $locked) {
    Write-Stage "lock" "LOCK_HELD" ""
    exit 0
}
$code = 1
try {
    $code = Invoke-BootstrapWorker
} catch {
    Write-Stage "done" "FAILED" (Redact $_.Exception.Message)
    $code = 1
} finally {
    if ($script:Mutex) {
        try { [void]$script:Mutex.ReleaseMutex() } catch { }
    }
}
exit $code
