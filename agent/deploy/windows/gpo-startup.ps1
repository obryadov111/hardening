<#
Агент «Харденинг» — сценарий запуска компьютера для групповой политики (GPO). Выполняется от SYSTEM при
включении ПК; повторный запуск безопасен: ничего не делает, если агент актуален и хост зарегистрирован.

  GPO: Конфигурация компьютера → Политики → Конфигурация Windows → Сценарии → Автозагрузка → PowerShell:
  этот файл, параметры (одной строкой):
    -Server https://audit.example.ru -SiteKey yak_... -PackPublicKey ... -Pin sha256//... -Share \\corp.local\NETLOGON\Hardening

Что делает:
  1. Берёт hardening-agent.exe из общей папки (-Share: тысяча ПК не качает файл из интернета) или с сервера и
     сверяет SHA-256 с version.json сервера: файл, подменённый в общей папке, не ставится.
  2. Кладёт его в C:\Program Files\Hardening, если версия другая.
  3. Регистрирует хост ключом площадки (--enroll), если он ещё не зарегистрирован: ключ хоста —
     C:\ProgramData\HardeningAgent\host.json (доступ только SYSTEM и «Администраторы»).
  4. Создаёт ежедневную задачу от SYSTEM с разбросом запуска до часа.
Журнал — C:\ProgramData\HardeningAgent\gpo-startup.log.

Ключ площадки в параметрах сценария виден всем пользователям домена (SYSVOL) — выдавайте его с коротким
сроком на время раскатки: зарегистрированные хосты работают и после его истечения.
#>
param(
    [Parameter(Mandatory = $true)][string]$Server,
    [Parameter(Mandatory = $true)][string]$SiteKey,
    [string]$PackPublicKey = "",
    [string]$Pin = "",
    [string]$Share = "",
    [string]$Environment = "prod",
    [string]$Proxy = "",
    [string]$InstallDir = "C:\Program Files\Hardening",
    [string]$StateDir = "C:\ProgramData\HardeningAgent",
    [switch]$AllowHttp  # только для проверки (CI, стенд): сервер по http://localhost
)
$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Server = $Server.TrimEnd("/")
$exe = Join-Path $InstallDir "hardening-agent.exe"
$log = Join-Path $StateDir "gpo-startup.log"

function Write-Log([string]$message) {
    if (-not (Test-Path $StateDir)) { New-Item -ItemType Directory -Force -Path $StateDir | Out-Null }
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $message" | Out-File -FilePath $log -Append -Encoding utf8
}

function Get-Sha256([string]$path) { (Get-FileHash -Algorithm SHA256 -Path $path).Hash.ToLowerInvariant() }

try {
    if (-not $AllowHttp -and -not $Server.StartsWith("https://")) { throw "Server должен быть https://" }
    $webArgs = @{ UseBasicParsing = $true }
    if ($Proxy) { $webArgs.Proxy = $Proxy }

    # 1–2. Агент: опубликованная версия и сумма — с сервера; файл — из общей папки или с сервера
    # Сценарий запуска выполняется при загрузке: сеть может подняться не сразу — несколько попыток
    for ($attempt = 1; ; $attempt++) {
        try { $published = Invoke-RestMethod -Uri "$Server/downloads/version.json" @webArgs; break }
        catch { if ($attempt -ge 4) { throw "сервер недоступен: $($_.Exception.Message)" }; Start-Sleep -Seconds 20 }
    }
    $file = $published.files | Where-Object { $_.platform -eq "windows" } | Select-Object -First 1
    if (-not $file) { throw "на сервере не опубликован агент для Windows" }
    if (-not $Pin -and $published.server_pin) { $Pin = $published.server_pin }

    if (-not (Test-Path $exe) -or (Get-Sha256 $exe) -ne $file.sha256) {
        $tmp = Join-Path $env:TEMP "hardening-agent-$([guid]::NewGuid()).exe"
        if ($Share) { Copy-Item -Path (Join-Path $Share $file.name) -Destination $tmp -Force }
        else { Invoke-WebRequest -Uri "$Server/downloads/$($file.name)" -OutFile $tmp @webArgs }
        $actual = Get-Sha256 $tmp
        if ($actual -ne $file.sha256) {
            Remove-Item $tmp -Force
            throw "SHA-256 агента не совпал с опубликованным ($actual вместо $($file.sha256)) — файл не установлен"
        }
        New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
        Move-Item -Path $tmp -Destination $exe -Force
        Write-Log "установлен агент версии $($file.version)"
    }

    # Открытый ключ паков и отпечаток сервера не секретны — переменные среды машины (их читает задача)
    if ($PackPublicKey) { [Environment]::SetEnvironmentVariable("HARDENING_PACK_PUBLIC_KEY", $PackPublicKey, "Machine") }
    if ($Pin) { [Environment]::SetEnvironmentVariable("HARDENING_PIN_SHA256", $Pin, "Machine") }
    if ($Proxy) { [Environment]::SetEnvironmentVariable("HARDENING_PROXY", $Proxy, "Machine") }

    # 3. Регистрация хоста — один раз; ключ площадки только в командной строке этого запуска
    if (-not (Test-Path (Join-Path $StateDir "host.json"))) {
        $enroll = @("--api-url", $Server, "--environment", $Environment, "--api-key", $SiteKey, "--state-dir", $StateDir, "--enroll")
        if ($Pin) { $enroll += @("--pin-sha256", $Pin) }
        if ($Proxy) { $enroll += @("--proxy", $Proxy) }
        if ($AllowHttp -and $Server.StartsWith("http://")) { $enroll += "--allow-http" }
        for ($attempt = 1; ; $attempt++) {
            # Агент пишет ход работы в stderr; Windows PowerShell 5.1 при Stop превращает каждую строку stderr
            # внешней программы в исключение — на время вызова Continue, результат — по коду возврата.
            $ErrorActionPreference = "Continue"
            $output = (& $exe @enroll 2>&1 | ForEach-Object { "$_" }) -join " "
            $code = $LASTEXITCODE
            $ErrorActionPreference = "Stop"
            Write-Log "регистрация (код $code): $($output.Trim())"
            if ($code -ne 75 -or $attempt -ge 3) { break }  # 75 — сервер недоступен, повторить
            Start-Sleep -Seconds 20
        }
        if ($code -ne 0) { exit $code }  # задача не создаётся без регистрации: при следующей загрузке — заново
    }

    # 4. Ежедневная задача от SYSTEM, разброс запуска до часа — тысяча ПК не обращается к серверу разом
    $arguments = "--api-url $Server --environment $Environment --use-packs --state-dir `"$StateDir`""
    if ($AllowHttp -and $Server.StartsWith("http://")) { $arguments += " --allow-http" }
    $existing = Get-ScheduledTask -TaskName "Hardening agent" -ErrorAction SilentlyContinue
    if (-not $existing -or $existing.Actions[0].Execute -ne $exe -or $existing.Actions[0].Arguments -ne $arguments) {
        $action = New-ScheduledTaskAction -Execute $exe -Argument $arguments
        $trigger = New-ScheduledTaskTrigger -Daily -At 03:00 -RandomDelay (New-TimeSpan -Hours 1)
        $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 30)
        Register-ScheduledTask -TaskName "Hardening agent" -Action $action -Trigger $trigger -Settings $settings `
            -User "SYSTEM" -RunLevel Highest -Force | Out-Null
        Write-Log "задача планировщика «Hardening agent» создана"
    }
    exit 0
}
catch {
    Write-Log "ошибка: $($_.Exception.Message)"
    exit 1
}
