"""Генерация паков windows-server / windows-client из одного описания (общие проверки не расходятся).

    python pack_sources/windows.py app/packs     # из каталога src/backend

Править проверки здесь, затем перегенерировать; tests/test_pack_sources.py следит, чтобы YAML в app/packs
совпадал с результатом генерации.
"""
import yaml

FSTEC = "Методика анализа защищённости информационных систем, ФСТЭК России, 25.11.2025"
CIS_S = "CIS Microsoft Windows Server Benchmark (адаптировано)"
CIS_C = "CIS Microsoft Windows 11 Enterprise Benchmark (адаптировано)"
CV = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
LSA = r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
SVC = r"HKLM\SYSTEM\CurrentControlSet\Services"
POL_SYS = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
POL_EXP = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
FW_POL = r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall"
FW_LOC = r"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
AUDIT = "{%s-69AE-11D9-BED3-505054503030}"


def reg(key, value, default=None):
    p = {"type": "reg_value", "key": key, "value": value}
    if default is not None:
        p["default"] = str(default)
    return p


def secpol(key, default=None):
    p = {"type": "win_secpol", "key": key}
    if default is not None:
        p["default"] = str(default)
    return p


def check(cid, title, probe, op, value, severity, remediation, ops_ids, cis=True, both=True):
    return {"id": cid, "title": title, "probe": probe, "assert": {"op": op, **({} if value is None else {"value": value})},
            "severity": severity, "remediation": remediation, "_ops": ops_ids, "_cis": cis, "_both": both}


def policy_or_local(policy_key, local_key, value, default):
    """Групповая политика главнее локальной настройки: сначала ключ Policies, затем локальный с умолчанием."""
    return {"type": "first_of", "probes": [reg(policy_key, value), reg(local_key, value, default)]}


CHECKS = [
    # --- парольная политика (ОПС.1.2) ---
    check("win.password_min_length", "Минимальная длина пароля — не менее 14 символов", secpol("MinimumPasswordLength"),
          "gte", 14, "medium", "Политика паролей: «Минимальная длина пароля» = 14.", ["ОПС.1.2"]),
    check("win.password_complexity", "Требования к сложности пароля включены", secpol("PasswordComplexity"),
          "eq", 1, "medium", "Политика паролей: «Пароль должен отвечать требованиям сложности» = Включён.", ["ОПС.1.2"]),
    check("win.password_max_age", "Максимальный срок действия пароля — от 1 до 90 дней (0 — никогда не истекает)",
          secpol("MaximumPasswordAge"), "between", [1, 90], "medium",
          "Политика паролей: «Максимальный срок действия пароля» = 90 (не 0).", ["ОПС.1.2"]),
    check("win.password_min_age", "Минимальный срок действия пароля — не менее 1 дня", secpol("MinimumPasswordAge"),
          "gte", 1, "low", "Политика паролей: «Минимальный срок действия пароля» = 1 (иначе журнал паролей обходится сменой подряд).", ["ОПС.1.2"]),
    check("win.password_history", "Журнал паролей — не менее 24 предыдущих", secpol("PasswordHistorySize"),
          "gte", 24, "low", "Политика паролей: «Вести журнал паролей» = 24.", ["ОПС.1.2"]),
    check("win.reversible_encryption_disabled", "Пароли не хранятся с обратимым шифрованием", secpol("ClearTextPassword"),
          "eq", 0, "high", "Политика паролей: «Хранить пароли, используя обратимое шифрование» = Отключён.", ["ОПС.1.2"]),
    # --- блокировка (ОПС.1.4) ---
    check("win.lockout_threshold", "Блокировка учётной записи после 1–5 неудачных попыток (0 — никогда)",
          secpol("LockoutBadCount"), "between", [1, 5], "high",
          "Политика блокировки: «Пороговое значение блокировки» = 5.", ["ОПС.1.4"]),
    check("win.lockout_duration", "Длительность блокировки — не менее 15 минут", secpol("LockoutDuration", default=0),
          "gte", 15, "medium", "Политика блокировки: «Продолжительность блокировки» = 15 минут (задаётся вместе с порогом).", ["ОПС.1.4"]),
    # --- учётные записи и доступ (ОПС.1.1, 1.3, 1.6) ---
    check("win.guest_disabled", "Учётная запись «Гость» отключена", secpol("EnableGuestAccount"),
          "eq", 0, "high", "Параметры безопасности: «Учётные записи: состояние учётной записи Гость» = Отключена.", ["ОПС.1.1"]),
    check("win.anonymous_sid_translation_disabled", "Анонимное сопоставление SID и имён запрещено",
          secpol("LSAAnonymousNameLookup"), "eq", 0, "medium",
          "Параметры безопасности: «Сетевой доступ: разрешить трансляцию анонимного SID в имя» = Отключён.", ["ОПС.1.3"]),
    check("win.restrict_anonymous_sam", "Анонимный перечень учётных записей SAM запрещён",
          reg(LSA, "RestrictAnonymousSAM", 1), "eq", 1, "medium",
          r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa: RestrictAnonymousSAM = 1.", ["ОПС.1.3"]),
    check("win.restrict_anonymous", "Анонимный перечень учётных записей и общих ресурсов запрещён",
          reg(LSA, "RestrictAnonymous", 0), "eq", 1, "medium",
          r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa: RestrictAnonymous = 1.", ["ОПС.1.3"]),
    check("win.null_session_shares_restricted", "Анонимный доступ к общим папкам и каналам ограничен",
          reg(rf"{SVC}\LanmanServer\Parameters", "RestrictNullSessAccess", 1), "eq", 1, "medium",
          r"LanmanServer\Parameters: RestrictNullSessAccess = 1.", ["ОПС.1.12"]),
    check("win.uac_enabled", "Контроль учётных записей (UAC) включён", reg(POL_SYS, "EnableLUA", 1),
          "eq", 1, "high", "Параметры безопасности: «Контроль учётных записей: все администраторы работают в режиме одобрения» = Включён.", ["ОПС.1.6"]),
    # --- устаревшие протоколы (ОПС.1.9) ---
    check("win.ntlmv1_refused", "Только NTLMv2: LM и NTLMv1 отклоняются (LmCompatibilityLevel = 5)",
          reg(LSA, "LmCompatibilityLevel", 3), "gte", 5, "high",
          "Параметры безопасности: «Сетевая безопасность: уровень проверки подлинности LAN Manager» = «Отправлять только NTLMv2, отказывать LM и NTLM».", ["ОПС.1.9"]),
    check("win.smb1_client_disabled", "Клиент SMBv1 отключён (драйвер mrxsmb10 не запускается)",
          reg(rf"{SVC}\mrxsmb10", "Start", 4), "eq", 4, "high",
          "Отключить компонент «Поддержка общего доступа к файлам SMB 1.0/CIFS» (ключа нет — драйвер не установлен, это соблюдение).", ["ОПС.1.9"]),
    check("win.smb1_server_disabled", "Сервер SMBv1 отключён явно (SMB1 = 0)",
          reg(rf"{SVC}\LanmanServer\Parameters", "SMB1", 1), "eq", 0, "high",
          r"LanmanServer\Parameters: SMB1 = 0 (или Set-SmbServerConfiguration -EnableSMB1Protocol $false). Как в CIS: значение должно быть задано явно.", ["ОПС.1.9"]),
    check("win.smb_server_signing_required", "Сервер SMB требует подпись пакетов",
          reg(rf"{SVC}\LanmanServer\Parameters", "RequireSecuritySignature", 0), "eq", 1, "medium",
          "Параметры безопасности: «Сервер сети Microsoft: использовать цифровую подпись (всегда)» = Включён.", ["ОПС.1.9"]),
    check("win.smb_client_signing_required", "Клиент SMB требует подпись пакетов",
          reg(rf"{SVC}\LanmanWorkstation\Parameters", "RequireSecuritySignature", 0), "eq", 1, "medium",
          "Параметры безопасности: «Клиент сети Microsoft: использовать цифровую подпись (всегда)» = Включён.", ["ОПС.1.9"]),
    check("win.llmnr_disabled", "Широковещательное разрешение имён LLMNR отключено",
          reg(r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast", 1), "eq", 0, "medium",
          "Групповая политика: «Отключить многоадресное разрешение имён» = Включена.", ["ОПС.1.9"]),
    check("win.wdigest_disabled", "WDigest не хранит пароли в памяти открытым текстом",
          reg(r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential", 0), "eq", 0, "high",
          r"WDigest: UseLogonCredential = 0.", ["ОПС.1.15"]),
    # --- удалённый доступ (ОПС.1.10) ---
    check("win.rdp_nla_required", "RDP требует проверки подлинности на уровне сети (NLA)",
          policy_or_local(r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services",
                          r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "UserAuthentication", 1),
          "eq", 1, "high", "Групповая политика: «Требовать проверку подлинности пользователя на уровне сети для удалённых подключений» = Включена.", ["ОПС.1.10"]),
    # --- межсетевой экран ---
    *[check(f"win.firewall_{name}_enabled", f"Брандмауэр Windows включён: профиль «{label}»",
            policy_or_local(rf"{FW_POL}\{pol}", rf"{FW_LOC}\{loc}", "EnableFirewall", 1), "eq", 1, "high",
            f"Брандмауэр Защитника Windows, профиль «{label}»: состояние = Включён.", ["ОПС.1.10"])
      for name, label, pol, loc in (("domain", "Домен", "DomainProfile", "DomainProfile"),
                                    ("private", "Частный", "PrivateProfile", "StandardProfile"),
                                    ("public", "Общий", "PublicProfile", "PublicProfile"))],
    # --- автозапуск с носителей (ОПС.1.13) ---
    check("win.autorun_disabled_all_drives", "Автозапуск отключён для всех типов носителей (NoDriveTypeAutoRun = 255)",
          reg(POL_EXP, "NoDriveTypeAutoRun", 145), "eq", 255, "medium",
          "Групповая политика: «Отключить автозапуск» = Включена, «Все дисководы».", ["ОПС.1.13"]),
    check("win.autorun_commands_disabled", "Команды автозапуска (autorun.inf) не выполняются (NoAutorun = 1)",
          reg(POL_EXP, "NoAutorun", 0), "eq", 1, "medium",
          "Групповая политика: «Задать поведение по умолчанию для AutoRun» = Не выполнять команды автозапуска.", ["ОПС.1.13"]),
    # --- журналирование (ОПС.1.11) ---
    check("win.eventlog_running", "Служба журнала событий работает", {"type": "service_state", "service": "EventLog"},
          "eq", "active", "high", "Службу «Журнал событий Windows» не останавливать и не отключать.", ["ОПС.1.11"], cis=False),
    check("win.audit_logon", "Аудит входа в систему: успех и отказ",
          {"type": "win_auditpol", "subcategory": AUDIT % "0CCE9215"}, "eq", 3, "medium",
          "Расширенная политика аудита, «Вход/выход» → «Аудит входа в систему» = Успех и отказ.", ["ОПС.1.11"]),
    check("win.audit_account_lockout", "Аудит блокировки учётных записей: отказ",
          {"type": "win_auditpol", "subcategory": AUDIT % "0CCE9217"}, "in", [2, 3], "medium",
          "Расширенная политика аудита, «Вход/выход» → «Аудит блокировки учётной записи» = Отказ.", ["ОПС.1.11"]),
    check("win.audit_credential_validation", "Аудит проверки учётных данных: успех и отказ",
          {"type": "win_auditpol", "subcategory": AUDIT % "0CCE923F"}, "eq", 3, "medium",
          "Расширенная политика аудита, «Вход учётной записи» → «Аудит проверки учётных данных» = Успех и отказ.", ["ОПС.1.11"]),
    check("win.audit_user_account_management", "Аудит управления учётными записями: успех и отказ",
          {"type": "win_auditpol", "subcategory": AUDIT % "0CCE9235"}, "eq", 3, "medium",
          "Расширенная политика аудита, «Управление учётными записями» → «Аудит управления учётными записями пользователей» = Успех и отказ.", ["ОПС.1.11"]),
    check("win.audit_policy_change", "Аудит изменения политики аудита: успех",
          {"type": "win_auditpol", "subcategory": AUDIT % "0CCE922F"}, "in", [1, 3], "medium",
          "Расширенная политика аудита, «Изменение политики» → «Аудит изменения политики аудита» = Успех.", ["ОПС.1.11"]),
    check("win.audit_process_creation", "Аудит создания процессов: успех",
          {"type": "win_auditpol", "subcategory": AUDIT % "0CCE922B"}, "in", [1, 3], "low",
          "Расширенная политика аудита, «Подробное отслеживание» → «Аудит создания процессов» = Успех.", ["ОПС.1.11"]),
    # --- службы (ОПС.1.8) ---
    check("win.telnet_server_absent", "Сервер Telnet не работает", {"type": "service_state", "service": "TlntSvr"},
          "in", ["inactive", "not-found"], "high", "Удалить компонент «Сервер Telnet».", ["ОПС.1.8"], cis=False),
    check("win.ftp_server_absent", "FTP-сервер IIS не работает", {"type": "service_state", "service": "ftpsvc"},
          "in", ["inactive", "not-found"], "medium", "Удалить компонент «FTP-сервер» IIS, если он не нужен.", ["ОПС.1.8"], cis=False),
    check("win.remote_registry_disabled", "Служба «Удалённый реестр» отключена",
          {"type": "service_state", "service": "RemoteRegistry", "field": "enabled"}, "in", ["disabled", "not-found"], "low",
          "Службу «Удалённый реестр» перевести в состояние «Отключена».", ["ОПС.1.8"]),
    check("win.print_spooler_disabled", "Диспетчер печати отключён (сервер не печатает)",
          {"type": "service_state", "service": "Spooler", "field": "enabled"}, "in", ["disabled", "not-found"], "low",
          "Службу «Диспетчер печати» отключить на серверах, которые не являются серверами печати (уязвимости PrintNightmare).",
          ["ОПС.1.8"], both=False),
    # --- обновления и антивирус ---
    check("win.automatic_updates_enabled", "Автоматические обновления не отключены политикой",
          reg(r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "NoAutoUpdate", 0), "eq", 0, "medium",
          "Групповая политика: «Настройка автоматического обновления» не должна быть «Отключена».", ["ОПС.2"]),
    check("win.defender_realtime_enabled", "Защита в реальном времени Microsoft Defender включена",
          policy_or_local(r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
                          r"HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring", 0),
          "eq", 0, "high", "Не отключать защиту в реальном времени (если установлен сторонний антивирус — проверка неприменима, оформить исключение).",
          ["ОПС.1.15"]),
]


def build(kind):
    server = kind == "server"
    cis = CIS_S if server else CIS_C
    checks = []
    for c in CHECKS:
        if not c["_both"] and not server:
            continue
        refs = ([{"source": cis}] if c["_cis"] else []) + [{"source": FSTEC, "id": i} for i in c["_ops"]]
        checks.append({k: v for k, v in c.items() if not k.startswith("_")} | {"refs": refs})
    return {
        "pack": f"windows-{kind}",
        "version": "1.0.0",
        "maturity": "draft",
        "tags": ["windows", f"windows-{kind}"],
        "transport": "local",
        "asset_type": "windows-server" if server else "windows-workstation",
        "detect": [{"probe": reg(CV, "InstallationType"), "regex": "^Server" if server else "^Client$"}],
        "checks": checks,
    }


HEADER = {
    "server": """# Пак «Windows Server»: 2016 / 2019 / 2022 / 2025 (полная установка и Server Core).
# Распознаётся по InstallationType в реестре (Server / Server Core); версия ОС в отчёте — из реестра
# (ProductName, DisplayVersion, CurrentBuildNumber).
#
# Источники значений не зависят от языка системы: на русской Windows `net accounts`, `auditpol /get`,
# `netsh` выводят русский текст. Поэтому — реестр, экспорт политики безопасности (secedit, ключи вида
# MinimumPasswordLength) и резервная копия политики аудита (auditpol /backup, GUID и числа).
# Групповая политика главнее локальной настройки: там, где у параметра есть оба места, сначала читается
# ключ Policies (first_of), затем локальный с умолчанием Windows.
#
# Права: secedit и auditpol требуют администратора — агент на Windows работает от SYSTEM (задача
# планировщика). Без прав эти проверки получают «не проверено», а не «соблюдено».
#
# maturity=draft: проверки написаны по документации Microsoft и CIS и проверены на образцах; прогон на
# реальных Windows Server 2022/2025 — в CI (GitHub Actions). Контроллер домена: политика паролей берётся
# из доменной политики — пак описывает рядовой сервер и отдельно контроллер домена не проверяет.
#
# Генерируется из pack_sources/windows.py вместе с windows-client — правки там, не здесь.
""",
    "client": """# Пак «Windows (рабочая станция)»: Windows 10 / 11 (Pro, Enterprise, Education).
# Распознаётся по InstallationType = Client. Те же источники и принципы, что у windows-server
# (см. его заголовок): реестр, secedit, auditpol /backup — независимо от языка системы.
#
# maturity=draft: реальной Windows 10/11 для проверки нет (в CI доступны только Windows Server) — проверки
# подтверждены образцами и совпадающими с серверными механизмами. Отличие от серверного пака: нет проверки
# диспетчера печати (на рабочих станциях печать нужна).
#
# Генерируется из pack_sources/windows.py вместе с windows-server — правки там, не здесь.
""",
}

if __name__ == "__main__":
    import sys
    out = sys.argv[1]
    for kind in ("server", "client"):
        text = yaml.safe_dump(build(kind), allow_unicode=True, sort_keys=False, width=200)
        open(f"{out}/windows-{kind}-1.0.0.yaml", "w", encoding="utf-8").write(HEADER[kind] + "\n" + text)
        print(kind, len(build(kind)["checks"]), "проверок")
