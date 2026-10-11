"""Генерация паков windows-server / windows-client из одного описания (общие проверки не расходятся)
и пака windows-dc (контроллер домена — дополняет windows-server, см. DC_CHECKS).

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
        # Сервер — подтверждён прогоном агента на настоящих Windows Server (CI, workflow windows-packs.yml):
        # все 40 проб выполнились, 33 значения реально найдены в реестре/политиках. Клиентской Windows в CI нет.
        "maturity": "baseline" if server else "draft",
        **({"verified_on": [
            "Windows Server 2022 Datacenter (21H2, сборка 20348) — GitHub Actions windows-2022",
            "Windows Server 2025 Datacenter (24H2, сборка 26100) — GitHub Actions windows-2025",
        ]} if server else {}),
        "tags": ["windows", f"windows-{kind}"],
        "transport": "local",
        "asset_type": "windows-server" if server else "windows-workstation",
        "detect": [{"probe": reg(CV, "InstallationType"), "regex": "^Server" if server else "^Client$"}],
        "checks": checks,
    }



# ============================== контроллер домена ==============================
# windows-dc не заменяет windows-server, а дополняет его: на контроллере домена распознаются оба пака
# (как docker поверх ubuntu-server). Общие для сервера проверки (SMB, NTLM, брандмауэр, аудит входа,
# диспетчер печати, политика паролей — на DC secedit отдаёт доменную) остаются в windows-server; здесь —
# только то, что есть лишь у контроллера: службы каталога (LDAP, Netlogon, DSRM), аудит каталога и Kerberos,
# состояние самого домена (win_ad).

CIS_DC = "CIS Microsoft Windows Server Benchmark, профиль Domain Controller (адаптировано)"
ANSSI = "ANSSI, контрольные точки безопасности Active Directory (адаптировано)"
MS_AD = "Microsoft, рекомендации по защите Active Directory (адаптировано)"
NTDS = r"HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
NETLOGON = r"HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
PRODUCT_TYPE = r"HKLM\SYSTEM\CurrentControlSet\Control\ProductOptions"


def dc_check(cid, title, probe, op, value, severity, remediation, sources, ops_ids=()):
    refs = [{"source": src} for src in sources] + [{"source": FSTEC, "id": i} for i in ("ДИС.1", *ops_ids)]
    return {"id": cid, "title": title, "probe": probe, "assert": {"op": op, **({} if value is None else {"value": value})},
            "severity": severity, "remediation": remediation, "refs": refs}


def ad(fact):
    return {"type": "win_ad", "fact": fact}


def no_accounts(cid, fact, title, severity, remediation, sources, ops_ids=()):
    """Счётчик учётных записей с опасным признаком: соблюдено, только если таких нет (в свидетельстве — до 10 имён)."""
    return dc_check(cid, title, ad(fact), "eq", 0, severity, remediation, sources, ops_ids)


DC_CHECKS = [
    # --- службы каталога (реестр) ---
    dc_check("windc.ldap_signing_required", "Сервер LDAP требует подпись (LDAPServerIntegrity = 2)",
             reg(NTDS, "LDAPServerIntegrity", 1), "eq", 2, "high",
             "Параметры безопасности: «Контроллер домена: требования к подписи для LDAP-сервера» = «Требовать подпись».",
             [CIS_DC], ["ОПС.1.9"]),
    dc_check("windc.ldap_channel_binding", "LDAPS требует привязку к каналу (LdapEnforceChannelBinding = 2)",
             reg(NTDS, "LdapEnforceChannelBinding", 0), "eq", 2, "medium",
             "Параметры безопасности: «Контроллер домена: требования к маркеру привязки канала LDAP-сервера» = «Всегда» "
             "(предварительно проверить по событию 3039, что клиенты её поддерживают).", [CIS_DC], ["ОПС.1.9"]),
    dc_check("windc.netlogon_full_secure_channel", "Netlogon требует защищённый канал для всех (защита от ZeroLogon, CVE-2020-1472)",
             reg(NETLOGON, "FullSecureChannelProtection", 1), "eq", 1, "critical",
             r"Netlogon\Parameters: FullSecureChannelProtection = 1 (или удалить значение — с обновления 02.2021 это режим принудительной защиты).",
             [MS_AD], ["ОПС.1.15"]),
    dc_check("windc.netlogon_no_vulnerable_allowlist", "Нет исключений из защиты Netlogon (vulnerablechannelallowlist)",
             reg(NETLOGON, "vulnerablechannelallowlist"), "absent", None, "high",
             "Групповая политика «Контроллер домена: разрешить уязвимые подключения защищённого канала Netlogon» — не задана; "
             "устройства из списка обновить или вывести из домена.", [MS_AD], ["ОПС.1.15"]),
    dc_check("windc.machine_password_change_allowed", "Контроллер не запрещает смену паролей учётных записей компьютеров",
             reg(NETLOGON, "RefusePasswordChange", 0), "eq", 0, "low",
             "Параметры безопасности: «Контроллер домена: запретить изменение пароля учётных записей компьютера» = Отключён.", [CIS_DC]),
    dc_check("windc.dsrm_network_logon_disabled", "Учётная запись DSRM не входит по сети (DsrmAdminLogonBehavior = 0)",
             reg(LSA, "DsrmAdminLogonBehavior", 0), "eq", 0, "high",
             r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa: DsrmAdminLogonBehavior = 0 (или удалить значение).", [ANSSI], ["ОПС.1.6"]),
    # --- аудит каталога и Kerberos (ОПС.1.11) ---
    dc_check("windc.audit_ds_changes", "Аудит изменений службы каталогов: успех",
             {"type": "win_auditpol", "subcategory": AUDIT % "0CCE923C"}, "in", [1, 3], "medium",
             "Расширенная политика аудита, «Доступ к DS» → «Аудит изменений службы каталогов» = Успех.", [CIS_DC], ["ОПС.1.11"]),
    dc_check("windc.audit_ds_access", "Аудит доступа к службе каталогов: отказ",
             {"type": "win_auditpol", "subcategory": AUDIT % "0CCE923B"}, "in", [2, 3], "low",
             "Расширенная политика аудита, «Доступ к DS» → «Аудит доступа к службе каталогов» = Отказ.", [CIS_DC], ["ОПС.1.11"]),
    dc_check("windc.audit_kerberos_authentication", "Аудит службы проверки подлинности Kerberos: успех и отказ",
             {"type": "win_auditpol", "subcategory": AUDIT % "0CCE9242"}, "eq", 3, "medium",
             "Расширенная политика аудита, «Вход учётной записи» → «Аудит службы проверки подлинности Kerberos» = Успех и отказ.",
             [CIS_DC], ["ОПС.1.11"]),
    dc_check("windc.audit_kerberos_service_tickets", "Аудит операций с билетами службы Kerberos: успех и отказ",
             {"type": "win_auditpol", "subcategory": AUDIT % "0CCE9240"}, "eq", 3, "low",
             "Расширенная политика аудита, «Вход учётной записи» → «Аудит операций с билетами службы Kerberos» = Успех и отказ.",
             [CIS_DC], ["ОПС.1.11"]),
    dc_check("windc.audit_computer_account_management", "Аудит управления учётными записями компьютеров: успех",
             {"type": "win_auditpol", "subcategory": AUDIT % "0CCE9236"}, "in", [1, 3], "low",
             "Расширенная политика аудита, «Управление учётными записями» → «Аудит управления учётными записями компьютеров» = Успех.",
             [CIS_DC], ["ОПС.1.11"]),
    # --- домен: учётные записи и привилегии ---
    dc_check("windc.krbtgt_password_rotated", "Пароль krbtgt менялся не позднее 180 дней назад",
             ad("krbtgt_password_age_days"), "lte", 180, "high",
             "Сменить пароль krbtgt дважды с интервалом не меньше времени репликации (сценарий Microsoft New-KrbtgtKeys.ps1); "
             "после компрометации домена — обязательно.", [ANSSI, MS_AD], ["ОПС.1.2"]),
    dc_check("windc.privileged_users_limited", "Не более 5 учётных записей с правами администратора домена или леса",
             ad("privileged_users_count"), "lte", 5, "medium",
             "Пересмотреть состав групп «Администраторы домена», «Администраторы предприятия», «Администраторы схемы», "
             "«Администраторы» (включая вложенные): для повседневной работы — отдельные учётные записи без этих прав.",
             [ANSSI, MS_AD], ["ОПС.1.6"]),
    no_accounts("windc.schema_admins_empty", "schema_admins_count", "Группа «Администраторы схемы» пуста", "medium",
                "Добавлять в «Администраторы схемы» только на время изменения схемы, затем удалять.", [MS_AD], ["ОПС.1.6"]),
    no_accounts("windc.privileged_without_spn", "privileged_spn_users_count",
                "У привилегированных учётных записей нет SPN (не подвержены Kerberoasting)", "high",
                "Снять SPN с привилегированных учётных записей; службам — отдельные учётные записи (лучше gMSA) без административных прав.",
                [ANSSI], ["ОПС.1.6"]),
    no_accounts("windc.no_unconstrained_delegation", "unconstrained_delegation_count",
                "Нет учётных записей с неограниченным делегированием (кроме контроллеров домена)", "high",
                "Свойства учётной записи → «Делегирование»: заменить «Доверять для делегирования любой службе» на ограниченное делегирование.",
                [ANSSI, MS_AD], ["ОПС.1.6"]),
    no_accounts("windc.no_asrep_roastable", "asrep_roastable_count",
                "Нет учётных записей без предварительной проверки подлинности Kerberos (AS-REP roasting)", "high",
                "Свойства учётной записи → «Учётная запись»: снять «Без предварительной проверки подлинности Kerberos».",
                [ANSSI], ["ОПС.1.2"]),
    no_accounts("windc.no_password_not_required", "password_not_required_count",
                "Нет учётных записей, которым разрешён пустой пароль (PASSWD_NOTREQD)", "high",
                "Снять признак PASSWD_NOTREQD (userAccountControl, флаг 32) и задать пароль.", [ANSSI], ["ОПС.1.1", "ОПС.1.2"]),
    no_accounts("windc.no_reversible_encryption_users", "reversible_encryption_users_count",
                "Нет учётных записей с хранением пароля обратимым шифрованием", "high",
                "Свойства учётной записи: снять «Хранить пароль, используя обратимое шифрование», затем сменить пароль.",
                [ANSSI], ["ОПС.1.2"]),
    no_accounts("windc.no_des_only_users", "des_only_users_count", "Нет учётных записей, ограниченных шифрованием DES в Kerberos", "medium",
                "Свойства учётной записи: снять «Использовать только типы шифрования Kerberos DES», затем сменить пароль.",
                [ANSSI], ["ОПС.1.9"]),
    no_accounts("windc.no_password_never_expires", "password_never_expires_count",
                "Нет активных учётных записей с бессрочным паролем", "medium",
                "Снять «Срок действия пароля не ограничен»; учётные записи служб перевести на gMSA. Оставшиеся исключения — принятым риском.",
                [ANSSI], ["ОПС.1.2"]),
    # --- домен и лес: параметры ---
    dc_check("windc.machine_account_quota_zero", "Обычные пользователи не могут добавлять компьютеры в домен (ms-DS-MachineAccountQuota = 0)",
             ad("machine_account_quota"), "eq", 0, "medium",
             "Set-ADDomain -Replace @{'ms-DS-MachineAccountQuota'=0}; присоединение к домену — делегированием на подразделение.",
             [ANSSI], ["ОПС.1.6"]),
    dc_check("windc.anonymous_ldap_disabled", "Анонимные операции LDAP запрещены (dSHeuristics)",
             ad("anonymous_ldap_allowed"), "eq", 0, "high",
             "Атрибут dSHeuristics (CN=Directory Service,CN=Windows NT,CN=Services в разделе конфигурации): седьмой символ — не 2.",
             [ANSSI], ["ОПС.1.3"]),
    dc_check("windc.functional_level_2016", "Функциональный уровень домена — не ниже Windows Server 2016",
             ad("domain_functional_level"), "gte", 7, "low",
             "Обновить контроллеры домена и поднять функциональный уровень (на 2016+ доступны защита учётных данных и PAM).",
             [ANSSI]),
    dc_check("windc.recycle_bin_enabled", "Корзина Active Directory включена", ad("recycle_bin_enabled"), "eq", 1, "low",
             "Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target <лес>.", [MS_AD]),
    dc_check("windc.laps_schema_present", "Схема расширена для LAPS (уникальные пароли локальных администраторов)",
             ad("laps_schema_present"), "eq", 1, "medium",
             "Развернуть Windows LAPS (Update-LapsADSchema) и политику LAPS для компьютеров. Пак проверяет только схему: "
             "применение политики на каждом компьютере — отдельно.", [MS_AD]),
]


def build_dc():
    return {
        "pack": "windows-dc",
        "version": "1.0.0",
        # Живого контроллера домена для проверки нет: пути реестра, GUID аудита и запросы к каталогу подтверждены
        # только образцами и документацией. Повысить до baseline — после прогона на настоящем домене.
        "maturity": "draft",
        "tags": ["windows", "windows-dc", "active-directory"],
        "transport": "local",
        "asset_type": "windows-server",
        # ProductType: LanmanNt — контроллер домена, ServerNT — рядовой сервер, WinNT — рабочая станция.
        "detect": [{"probe": reg(PRODUCT_TYPE, "ProductType"), "equals": "LanmanNt"}],
        "checks": DC_CHECKS,
    }


DC_HEADER = """# Пак «Windows Server — контроллер домена Active Directory» (2016 / 2019 / 2022 / 2025).
# Распознаётся по ProductType = LanmanNt. Дополняет windows-server (он на контроллере тоже срабатывает):
# здесь только то, что есть лишь у контроллера домена, — службы каталога (подпись и привязка LDAP, Netlogon,
# DSRM), аудит каталога и Kerberos, состояние домена. Пункт методики ФСТЭК — ДИС.1 «Конфигурация домена».
#
# Состояние домена (проба win_ad): агент выполняет на контроллере свой встроенный сценарий PowerShell —
# чтение каталога по LDAP через ADSI, без модуля ActiveDirectory; манифест выбирает только имя сведения из
# закрытого списка. Группы определяются по SID, поэтому язык системы не важен. Счётчики учётных записей
# в свидетельстве дают до 10 имён. Отключённые учётные записи не считаются.
#
# maturity=draft: живого контроллера домена для проверки не было — пути реестра, GUID подкатегорий аудита
# и запросы к каталогу подтверждены только образцами (pack_tests/windows-dc.yaml) и документацией. На
# Windows Server 2025 умолчания подписи LDAP могли измениться (как у подписи SMB) — проверить на живой системе.
#
# Генерируется из pack_sources/windows.py — правки там, не здесь.
"""

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
# maturity=baseline: прогон агента на настоящих Windows Server 2022 и 2025 (CI, windows-packs.yml): все пробы
# выполнились, распознавание верное; 33 из 40 значений реально найдены в реестре/политиках — пути, ключи
# secedit и GUID аудита подтверждены живой системой. Остальные 7 параметров на чистой системе в реестре
# отсутствуют (LmCompatibilityLevel, SMB1, EnableMulticast, UseLogonCredential, NoDriveTypeAutoRun,
# NoAutorun, mrxsmb10) — берутся умолчания Windows; их пути — стандартные (CIS), живой проверкой не
# подтверждаемы. Контроллер домена: политика паролей берётся из доменной политики — пак описывает рядовой
# сервер и отдельно контроллер домена не проверяет.
#
# Известное ограничение: подпись SMB (RequireSecuritySignature). На Windows Server 2022 значение записано в
# реестре, на 2025 — отсутствует: у 2025 / Windows 11 24H2 другие умолчания подписи SMB. При отсутствии
# значения пак консервативно считает 0 (нарушение); на 2025 это может быть ложным срабатыванием — проверить
# `Get-SmbServerConfiguration` / `Get-SmbClientConfiguration` и при необходимости оформить исключение.
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

def render_dc() -> str:
    return DC_HEADER + "\n" + yaml.safe_dump(build_dc(), allow_unicode=True, sort_keys=False, width=200)


if __name__ == "__main__":
    import sys
    out = sys.argv[1]
    for kind in ("server", "client"):
        text = yaml.safe_dump(build(kind), allow_unicode=True, sort_keys=False, width=200)
        open(f"{out}/windows-{kind}-1.0.0.yaml", "w", encoding="utf-8").write(HEADER[kind] + "\n" + text)
        print(kind, len(build(kind)["checks"]), "проверок")
    open(f"{out}/windows-dc-1.0.0.yaml", "w", encoding="utf-8").write(render_dc())
    print("dc", len(DC_CHECKS), "проверок")
