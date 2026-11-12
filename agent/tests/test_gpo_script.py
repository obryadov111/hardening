"""Статические гарантии сценария GPO: на Windows его гоняет CI, здесь — то, что нельзя потерять при правке."""
import os

# Канонический сценарий — deploy/windows/gpo, на уровень выше каталога agent/.
# Прогон Python 3.6 копирует этот каталог рядом с деревом агента: см. agent-tests.yml.
ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
SCRIPT = os.path.join(ROOT, "deploy", "windows", "gpo", "gpo-startup.ps1")
TEMPLATE = os.path.join(ROOT, "deploy", "windows", "gpo", "gpo-parameters.txt")


def _text():
    with open(SCRIPT, encoding="utf-8") as fh:
        return fh.read()


def test_bootstrap_task_is_registered_before_enroll_and_startup_returns():
    text = _text()
    startup = text.split("function Invoke-Startup", 1)[1].split("function Enter-WorkerLock", 1)[0]
    assert "Register-BootstrapTask" in startup
    assert "exit (Invoke-Startup)" in text
    # Регистрация хоста живёт только в worker, который ставит задача, а не в пути автозагрузки.
    assert "--enroll" not in startup
    assert "Start-ScheduledTask -TaskName $BootstrapTaskName" in startup


def test_site_key_is_not_a_task_argument_and_not_written_to_the_log():
    text = _text()
    builder = text.split("function Get-BootstrapArguments", 1)[1].split("function Register-BootstrapTask", 1)[0]
    assert "-SiteKey" not in builder
    assert "SiteKey" not in builder
    assert "только в site.key" in builder
    assert "Write-Log" in text
    for line in text.splitlines():
        if "Write-Log" in line or "Write-Stage" in line:
            assert "$SiteKey" not in line
            assert "$script:Secret" not in line


def test_pin_is_a_list_and_mismatch_does_not_retry_or_trust_version_json():
    text = _text()
    assert "[string[]]$Pin" in text
    assert "TLS_PIN_MISMATCH" in text
    assert "TLS_INSPECTION" in text
    assert "Lock-PinsAfterMismatch" in text
    assert "LOCKED_AFTER_MISMATCH" in text
    assert "no_trust_change=1" in text
    enroll = text.split("function Invoke-Enroll", 1)[1].split("function Start-FirstCollect", 1)[0]
    assert "for (" not in enroll  # один вызов агента, без цикла повторов вокруг pin mismatch
    assert "--initial-jitter-max" not in enroll
    assert "--retry-budget-seconds" not in enroll
    assert "HARDENING_INITIAL_JITTER_MAX" in text
    assert "HARDENING_RETRY_BUDGET_SECONDS" in text
    assert "IgnoreNew" in text


def test_parameter_template_uses_the_script_defaults_and_the_live_pin():
    with open(TEMPLATE, encoding="utf-8") as fh:
        text = fh.read()
    assert "https://audit.hardening-audit.ru" in text
    assert "sha256//F2IS+EuQnazu4oq6kt82+KkSARv4DiztB0hU9vOzdsU=" in text
    assert "-InitialJitterMaxSeconds 900" in text
    assert "-RetryBudgetSeconds 1800" in text
    assert "-BootstrapEveryMinutes 15" in text
    assert "-BootstrapRandomDelayMinutes 15" in text
    assert "-Pin " in text and "-SiteKey " in text and "-Share " in text
    assert "yak_" not in text
    assert "site.key" in text


def test_daytime_collect_and_spool_flush_are_defined_once():
    text = _text()
    assert '[string]$CollectTime = "07:30"' in text
    assert "[int]$CollectRandomDelayHours = 2" in text
    assert "$SpoolEveryMinutes = 30" in text
    assert "$SpoolRandomDelayMinutes = 30" in text
    assert "$SpoolWindowHours = 10" in text
    assert "$SpoolExecutionMinutes = 15" in text
    assert "03:00" not in text
    trigger = text.split("function New-CollectTrigger", 1)[1].split("function Test-CollectTaskCurrent", 1)[0]
    assert "-At $CollectTime" in trigger
    assert "CollectRandomDelayHours" in trigger
    assert "PT2H" not in trigger
    assert "Hardening agent spool" in text
    assert "flush-spool" in text
    spool_args = text.split("function Get-SpoolArguments", 1)[1].split("function New-CollectTrigger", 1)[0]
    assert "--use-packs" not in spool_args
    assert "TASK_UNCHANGED" in text
    assert "SPOOL_SKIPPED" in text
    assert "Test-FlushSpoolSupported" in text
    assert "IgnoreNew" in text
    assert "StartWhenAvailable" in text
    compare = text.split("function Test-CollectTaskCurrent", 1)[1].split("function Test-SpoolRepetition", 1)[0]
    assert "RandomDelay" in compare
    assert "Get-TriggerClock" in compare
    assert "PT1H" in compare
    builder = text.split("function Get-BootstrapArguments", 1)[1].split("function Register-BootstrapTask", 1)[0]
    assert "-CollectTime" in builder
    assert "-CollectRandomDelayHours" in builder
    assert "-SiteKey" not in builder
    # Windows PowerShell 5.1 не принимает -RepetitionInterval у -Daily: повтор дописывается в XML.
    spool_task = text.split("function Register-SpoolTask", 1)[1].split("function Update-CollectTask", 1)[0]
    assert "-RepetitionInterval" not in spool_task
    assert "-RepetitionDuration" not in spool_task
    assert "Repair-SpoolTaskXml" in spool_task


def test_manual_installer_matches_the_daytime_schedule():
    # README лежит в каталоге агента и есть и в полном дереве, и в прогоне Rocky,
    # куда копируют только agent/ и сценарий GPO. src/ и docs/ там нет.
    paths = [os.path.join(os.path.dirname(__file__), "..", "README.md")]
    for rel in ("src/pages/AgentKeys.jsx", "docs/agent-install.md"):
        candidate = os.path.join(ROOT, rel)
        if os.path.isfile(candidate):
            paths.append(candidate)
    assert paths
    for path in paths:
        with open(path, encoding="utf-8") as fh:
            body = fh.read()
        assert "03:00" not in body, path
        assert "07:30" in body, path
        assert "flush-spool" in body, path
        assert "Hardening agent spool" in body, path


def test_downloads_use_a_minute_timeout_and_skip_same_sha256():
    text = _text()
    assert "TimeoutSec = 60" in text
    assert "UP_TO_DATE" in text
    assert "SHA256_MISMATCH" in text
    assert "code=None" in text
    assert "InitialJitterMaxSeconds = 900" in text
    assert "RetryBudgetSeconds = 1800" in text
    assert "BootstrapEveryMinutes = 15" in text
    assert "BootstrapRandomDelayMinutes = 15" in text
