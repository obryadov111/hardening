"""Windows-пробы на образцах вывода: разбор secedit/auditpol/sc, умолчания реестра, запреты.
На реальной Windows те же пробы прогоняются в CI (windows-2022 / windows-2025)."""
import pytest

import probes
from probes import CmdOutput, ProbeError, parse_auditpol_backup, parse_secedit, run_probe

SECEDIT_INF = """[Unicode]
Unicode=yes
[System Access]
MinimumPasswordAge = 1
MaximumPasswordAge = 42
MinimumPasswordLength = 0
PasswordComplexity = 1
PasswordHistorySize = 24
LockoutBadCount = 0
NewAdministratorName = "Administrator"
EnableGuestAccount = 0
[Version]
signature="$CHICAGO$"
Revision=1
"""

AUDITPOL_EN = """Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value
WIN-1,System,Audit Logon,{0cce9215-69ae-11d9-bed3-505054503030},Success and Failure,,3
WIN-1,System,Audit Logoff,{0cce9216-69ae-11d9-bed3-505054503030},Success,,1
WIN-1,System,Audit Process Creation,{0cce922b-69ae-11d9-bed3-505054503030},No Auditing,,0
"""
# На русской Windows заголовки и названия локализованы — GUID и числа те же.
AUDITPOL_RU = """Имя компьютера,Цель политики,Подкатегория,GUID подкатегории,Параметр включения,Параметр исключения,Значение параметра
WIN-1,Система,Вход в систему,{0CCE9215-69AE-11D9-BED3-505054503030},Успех и сбой,,3
"""

SC_RUNNING = """
SERVICE_NAME: Spooler
        TYPE               : 110  WIN32_OWN_PROCESS  (interactive)
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
"""
SC_STOPPED = SC_RUNNING.replace("4  RUNNING", "1  STOPPED")


class WinHost:
    """Транспорт-подделка Windows: реестр, экспорт политик, вывод sc."""

    name, platform = "local", "windows"

    def __init__(self, registry=None, secpol=SECEDIT_INF, auditpol=AUDITPOL_EN, sc=None):
        self.registry, self._secpol, self._auditpol, self.sc = registry or {}, secpol, auditpol, sc or {}

    def read_registry(self, key, name):
        return self.registry.get(f"{key}\\{name}")

    def secpol(self):
        if self._secpol is None:
            raise ProbeError("экспорт политики безопасности: код 5 (нужны права администратора?)")
        return parse_secedit(self._secpol)

    def auditpol(self):
        return parse_auditpol_backup(self._auditpol)

    def run(self, argv):
        assert argv[:2] == ["sc", "query"]
        return self.sc.get(argv[2], CmdOutput("[SC] OpenService FAILED 1060:", "", 1060))


# ---------- разбор ----------

def test_parse_secedit_sections_and_quotes():
    parsed = parse_secedit(SECEDIT_INF)
    assert parsed["System Access"]["MinimumPasswordLength"] == "0"
    assert parsed["System Access"]["NewAdministratorName"] == "Administrator"


@pytest.mark.parametrize("text", [AUDITPOL_EN, AUDITPOL_RU], ids=["en", "ru"])
def test_parse_auditpol_is_language_independent(text):
    assert parse_auditpol_backup(text)["{0CCE9215-69AE-11D9-BED3-505054503030}"] == 3


# ---------- пробы ----------

def test_win_secpol_value_and_default():
    host = WinHost()
    assert run_probe(host, {"type": "win_secpol", "key": "PasswordComplexity"})["value"] == "1"
    missing = run_probe(host, {"type": "win_secpol", "key": "LockoutDuration", "default": "30"})
    assert missing["found"] and missing["value"] == "30" and "умолчанию" in missing["evidence"]


def test_win_secpol_without_admin_rights_is_error_not_a_value():
    result = run_probe(WinHost(secpol=None), {"type": "win_secpol", "key": "PasswordComplexity"})
    assert result["found"] is False and "администратора" in result["error"]


def test_win_auditpol_value_and_unknown_guid():
    host = WinHost()
    assert run_probe(host, {"type": "win_auditpol", "subcategory": "{0cce9215-69ae-11d9-bed3-505054503030}"})["value"] == 3
    unknown = run_probe(host, {"type": "win_auditpol", "subcategory": "{00000000-0000-0000-0000-000000000000}"})
    assert unknown["found"] is False


def test_reg_value_found_missing_and_default():
    key = r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
    host = WinHost(registry={rf"{key}\LmCompatibilityLevel": 5})
    assert run_probe(host, {"type": "reg_value", "key": key, "value": "LmCompatibilityLevel"})["value"] == 5
    assert run_probe(host, {"type": "reg_value", "key": key, "value": "RestrictAnonymous"})["value"] is None
    default = run_probe(host, {"type": "reg_value", "key": key, "value": "RestrictAnonymous", "default": "0"})
    assert default["value"] == "0" and "умолчанию" in default["evidence"]


@pytest.mark.parametrize("key", [r"HKLM\SAM\SAM\Domains", r"hklm\security\Policy\Secrets", r"HKCU\Software\X"])
def test_registry_secret_hives_and_non_hklm_are_refused_on_any_platform(key):
    with pytest.raises(ProbeError):
        probes.read_registry(key, "x")


def test_windows_service_state_uses_sc_and_registry():
    services = r"HKLM\SYSTEM\CurrentControlSet\Services"
    host = WinHost(
        registry={rf"{services}\Spooler\Start": 2, rf"{services}\RemoteRegistry\Start": 4},
        sc={"Spooler": CmdOutput(SC_RUNNING, "", 0), "RemoteRegistry": CmdOutput(SC_STOPPED, "", 0)},
    )
    assert run_probe(host, {"type": "service_state", "service": "Spooler"})["value"] == "active"
    assert run_probe(host, {"type": "service_state", "service": "RemoteRegistry"})["value"] == "inactive"
    assert run_probe(host, {"type": "service_state", "service": "Spooler", "field": "enabled"})["value"] == "enabled"
    assert run_probe(host, {"type": "service_state", "service": "RemoteRegistry", "field": "enabled"})["value"] == "disabled"
    assert run_probe(host, {"type": "service_state", "service": "NoSuch"})["value"] == "not-found"


@pytest.mark.skipif(probes.IS_WINDOWS, reason="на Windows реестр доступен — проверка для Linux-агента")
def test_windows_probes_on_linux_transport_are_errors():
    """Linux-агент, получивший Windows-пак, не распознает платформу, а не «пройдёт» проверки."""
    local = probes.LocalTransport()
    result = run_probe(local, {"type": "reg_value", "key": r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "value": "ProductName"})
    assert result["found"] is False
    assert run_probe(local, {"type": "win_secpol", "key": "PasswordComplexity"})["found"] is False


def test_sc_is_whitelisted_only_for_query():
    assert probes.LOCAL_COMMAND_POLICY["sc"].match("query Spooler")
    assert not probes.LOCAL_COMMAND_POLICY["sc"].match("stop Spooler")
    assert not probes.LOCAL_COMMAND_POLICY["sc"].match("config Spooler start= disabled")


def test_transport_without_windows_capabilities_gives_probe_error_not_a_crash():
    """Транспорт без реестра (старый, тестовый, сторонний) не обрывает прогон AttributeError-ом."""
    class Bare:
        name = "local"

    for probe in ({"type": "reg_value", "key": r"HKLM\SOFTWARE\X", "value": "Y"},
                  {"type": "win_secpol", "key": "PasswordComplexity"},
                  {"type": "win_auditpol", "subcategory": "{0CCE9215-69AE-11D9-BED3-505054503030}"}):
        result = run_probe(Bare(), probe)
        assert result["found"] is False and "не поддерживает" in result["error"]


@pytest.mark.skipif(not probes.IS_WINDOWS, reason="настоящий secedit/auditpol есть только на Windows")
def test_real_windows_exports_are_parsed():
    """На раннере Windows (CI): экспорт политик непустой и разбирается; повторный вызов — из кэша."""
    local = probes.LocalTransport()
    assert "MinimumPasswordLength" in local.secpol()["System Access"]
    assert "{0CCE9215-69AE-11D9-BED3-505054503030}" in local.auditpol()
    assert local.secpol() is local.secpol()


# ---------- Active Directory (win_ad) ----------

def _ad_output(facts: dict) -> str:
    import base64
    import json
    return base64.b64encode(json.dumps(facts, ensure_ascii=False).encode("utf-8")).decode("ascii")


class AdHost:
    name, platform = "local", "windows"

    def __init__(self, stdout):
        self.stdout = stdout

    def ad_facts(self):
        return probes.parse_ad_facts(self.stdout)


def test_win_ad_counter_with_names_and_plain_value():
    host = AdHost(_ad_output({
        "password_never_expires_count": {"value": 12, "names": ["svc-backup", "Сервис-1С"]},
        "machine_account_quota": {"value": 10},
        "krbtgt_password_age_days": {"value": 400, "evidence": "pwdLastSet 2025-09-06"},
    }))
    counted = run_probe(host, {"type": "win_ad", "fact": "password_never_expires_count"})
    assert counted["found"] and counted["value"] == 12
    assert counted["evidence"] == "12: svc-backup, Сервис-1С …"  # кириллица переживает Base64, «…» — показаны не все
    assert run_probe(host, {"type": "win_ad", "fact": "machine_account_quota"})["evidence"] == "machine_account_quota = 10"
    assert run_probe(host, {"type": "win_ad", "fact": "krbtgt_password_age_days"})["evidence"] == "pwdLastSet 2025-09-06"


def test_win_ad_failed_fact_and_missing_fact_are_errors_not_values():
    host = AdHost(_ad_output({"schema_admins_count": {"error": "Access is denied."}}))
    failed = run_probe(host, {"type": "win_ad", "fact": "schema_admins_count"})
    assert failed["found"] is False and "Access is denied" in failed["error"]
    missing = run_probe(host, {"type": "win_ad", "fact": "asrep_roastable_count"})
    assert missing["found"] is False and "не получено" in missing["error"]


@pytest.mark.parametrize("stdout", [_ad_output({"_error": "The specified domain either does not exist or could not be contacted."}),
                                    "", "not base64 at all", _ad_output(["list"])])
def test_win_ad_whole_script_failure_is_probe_error_for_every_check(stdout):
    """Не контроллер домена, каталог недоступен, вывод испорчен — «не проверено», а не «нарушений нет»."""
    result = run_probe(AdHost(stdout), {"type": "win_ad", "fact": "privileged_users_count"})
    assert result["found"] is False and result["error"].startswith("сведения AD")


def test_win_ad_script_is_fixed_read_only_and_not_from_manifest():
    argv = probes.ad_facts_argv()
    assert argv[:6] == ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand"]
    import base64
    script = base64.b64decode(argv[6]).decode("utf-16-le")
    assert script == probes.AD_FACTS_SCRIPT
    # только поиск по каталогу: ни записи, ни удаления, ни вызова внешних команд
    for verb in ("CommitChanges", "Put(", "DeleteTree", "Remove", "Set-AD", "New-AD", "Invoke-Expression", "Start-Process"):
        assert verb not in script
    # powershell не попадает в белый список команд манифеста: запускается только этот сценарий
    assert "powershell" not in probes.LOCAL_COMMAND_POLICY


def test_win_ad_on_linux_and_on_bare_transport_is_error():
    if not probes.IS_WINDOWS:
        assert run_probe(probes.LocalTransport(), {"type": "win_ad", "fact": "recycle_bin_enabled"})["found"] is False

    class Bare:
        name = "local"

    assert "не поддерживает" in run_probe(Bare(), {"type": "win_ad", "fact": "recycle_bin_enabled"})["error"]


@pytest.mark.skipif(not probes.IS_WINDOWS, reason="настоящий PowerShell есть только на Windows")
def test_real_powershell_runs_ad_script_outside_a_domain():
    """Раннер CI не в домене: сценарий должен запуститься, разобраться и честно сказать «каталог недоступен».
    Так проверяются синтаксис сценария, запуск powershell из агента и разбор Base64-вывода."""
    with pytest.raises(ProbeError, match="сведения AD недоступны"):
        probes.LocalTransport().ad_facts()
