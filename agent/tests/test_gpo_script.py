"""Статические гарантии сценария GPO: на Windows его гоняет CI, здесь — то, что нельзя потерять при правке."""
import os

SCRIPT = os.path.join(os.path.dirname(__file__), "..", "deploy", "windows", "gpo-startup.ps1")


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
