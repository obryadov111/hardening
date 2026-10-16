"""Движок проб агента «Харденинг»: выполняет пробы из манифеста пака.

Зависимости: только стандартная библиотека Python 3.9+ (как и collector.py).

Агент — последний рубеж защиты и не доверяет манифесту слепо, даже подписанному:
  * выполняются только типы проб из закрытого списка PROBES, и только на чтение;
  * локальные команды — только из белого списка LOCAL_COMMAND_POLICY, без shell (argv);
  * файловые пробы не читают секреты (DENIED_PATH_PATTERNS), символические ссылки
    разворачиваются до проверки; права файла проверяются через file_stat без чтения содержимого;
  * по SSH выполняются только команды на чтение (is_readonly_cli);
  * по выгрузке конфигурации (OfflineConfigTransport) ничего не выполняется: читаются только
    файлы выгрузки в заданном каталоге, имя файла строится из команды (без путей);
  * подпись манифеста (HMAC-SHA256) проверяется до выполнения чего-либо.

Ограничение подписи: ключ симметричный, им же проверяет агент, поэтому компрометация
хоста с агентом раскрывает ключ подписи. Ключ подписи должен быть отдельным от ключа
агента и своим на организацию; при желании схема заменяется на асимметричную
(Ed25519) без изменения формата манифеста.
"""
import glob
import hashlib
import hmac
import json
import os
import re
import shutil
import subprocess
import tempfile
import time

MANIFEST_SCHEMA = 1
SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
IS_WINDOWS = os.name == "nt"
# На Windows команды ищутся только в System32 — как SAFE_PATH на Linux, без PATH пользователя.
WINDOWS_SYSTEM32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
# Windows PowerShell 5.1 — только для встроенного в агент сценария чтения AD (AD_FACTS_SCRIPT), не из манифеста.
WINDOWS_POWERSHELL_DIR = os.path.join(WINDOWS_SYSTEM32, "WindowsPowerShell", "v1.0")
MAX_FILE_BYTES = 2_000_000
COMMAND_TIMEOUT = 15
AD_TIMEOUT = 120
MAX_INCLUDE_DEPTH = 5
MAX_INCLUDE_FILES = 50


class ManifestError(Exception):
    """Манифест не прошёл проверку (подпись, схема) — выполнять его нельзя."""


class ProbeError(Exception):
    """Проба не смогла выполниться (нет файла, команда запрещена или недоступна)."""


# --- подпись манифеста ----------------------------------------------------------

def canonical_json(manifest: dict) -> bytes:
    """Те же байты, что формирует сервер (app/services/packs/manifest.py)."""
    return json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def verify_manifest(manifest: dict, signature: str, key: str) -> bool:
    """Старая схема: HMAC-SHA256 общим ключом. Им же можно и подписать — ключ с любого хоста с агентом
    позволяет подделывать паки для всех. Оставлена для перехода; новая схема — Ed25519 (ниже)."""
    expected = hmac.new(key.encode("utf-8"), canonical_json(manifest), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature or "")


# Ed25519 (RFC 8032, раздел 5.1.7): у агента только ОТКРЫТЫЙ ключ сервера — подписать им нельзя, и
# компрометация хоста с агентом не даёт подделать паки для других. Только проверка подписи, на чистом
# Python (в стандартной библиотеке Ed25519 нет): агент остаётся без зависимостей. Проверка по тестовым
# векторам RFC 8032 и сверка с библиотекой cryptography — agent/tests, src/backend/tests.
_ED_P = 2 ** 255 - 19
_ED_L = 2 ** 252 + 27742317777372353535851937790883648493
_ED_D = -121665 * pow(121666, _ED_P - 2, _ED_P) % _ED_P
_ED_SQRT_M1 = pow(2, (_ED_P - 1) // 4, _ED_P)


def _ed_add(a, b):
    """Сложение точек в расширенных координатах (X, Y, Z, T)."""
    p = _ED_P
    x = (a[1] - a[0]) * (b[1] - b[0]) % p
    y = (a[1] + a[0]) * (b[1] + b[0]) % p
    c = 2 * a[3] * b[3] * _ED_D % p
    d = 2 * a[2] * b[2] % p
    e, f, g, h = y - x, d - c, d + c, y + x
    return (e * f, g * h, f * g, e * h)


def _ed_mul(scalar: int, point):
    result = (0, 1, 1, 0)
    while scalar > 0:
        if scalar & 1:
            result = _ed_add(result, point)
        point = _ed_add(point, point)
        scalar >>= 1
    return result


def _ed_equal(a, b) -> bool:
    p = _ED_P
    return (a[0] * b[2] - b[0] * a[2]) % p == 0 and (a[1] * b[2] - b[1] * a[2]) % p == 0


def _ed_recover_x(y: int, sign: int):
    p = _ED_P
    if y >= p:
        return None
    x2 = (y * y - 1) * pow(_ED_D * y * y + 1, p - 2, p) % p
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (p + 3) // 8, p)
    if (x * x - x2) % p:
        x = x * _ED_SQRT_M1 % p
    if (x * x - x2) % p:
        return None
    return p - x if (x & 1) != sign else x


def _ed_decompress(data: bytes):
    y = int.from_bytes(data, "little")
    sign, y = y >> 255, y & ((1 << 255) - 1)
    x = _ed_recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _ED_P)


_ED_GY = 4 * pow(5, _ED_P - 2, _ED_P) % _ED_P
_ED_G = (_ed_recover_x(_ED_GY, 0), _ED_GY, 1, _ed_recover_x(_ED_GY, 0) * _ED_GY % _ED_P)


def ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    if len(public_key) != 32 or len(signature) != 64:
        return False
    a = _ed_decompress(public_key)
    r = _ed_decompress(signature[:32])
    if a is None or r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _ED_L:  # неканоническая подпись (RFC 8032: отвергать)
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32] + public_key + message).digest(), "little") % _ED_L
    return _ed_equal(_ed_mul(s, _ED_G), _ed_add(r, _ed_mul(h, a)))


def decode_public_key(text: str) -> bytes:
    """Открытый ключ сервера: 32 байта в Base64 (как его показывает сервер) или в hex."""
    import base64
    import binascii

    text = (text or "").strip()
    try:
        raw = bytes.fromhex(text) if len(text) == 64 else base64.b64decode(text, validate=True)
    except (ValueError, binascii.Error):
        raw = b""
    if len(raw) != 32:
        raise ManifestError("открытый ключ подписи паков — 32 байта в Base64 или hex")
    return raw


def verify_manifest_ed25519(manifest: dict, signature: str, public_key: bytes) -> bool:
    import base64
    import binascii

    try:
        raw = base64.b64decode(signature or "", validate=True)
    except (ValueError, binascii.Error):
        return False
    return ed25519_verify(public_key, canonical_json(manifest), raw)


def load_verified_manifests(response: dict, key: "str | None" = None, public_key: "bytes | None" = None) -> "list[dict]":
    """Проверяет подпись каждого манифеста из ответа сервера. Любая подделка — ManifestError:
    это событие безопасности, а не повод молча пропустить один пак. С открытым ключом (Ed25519)
    HMAC-подпись не принимается вовсе: иначе подделка HMAC обошла бы новую схему."""
    if public_key is None and not key:
        raise ManifestError("нет ключа проверки подписи паков (открытый ключ Ed25519 или старый общий ключ)")
    verified = []
    for item in response.get("manifests", []):
        manifest = item.get("manifest")
        name = manifest.get("pack") if isinstance(manifest, dict) else "?"
        if public_key is not None:
            ok = isinstance(manifest, dict) and verify_manifest_ed25519(manifest, item.get("signature_ed25519"), public_key)
        else:
            ok = isinstance(manifest, dict) and verify_manifest(manifest, item.get("signature"), key)
        if not ok:
            raise ManifestError(f"Подпись манифеста {name!r} неверна — выполнение остановлено")
        if manifest.get("schema") != MANIFEST_SCHEMA:
            raise ManifestError(f"Неподдерживаемая схема манифеста {manifest.get('schema')!r}")
        verified.append(manifest)
    return verified


# --- ограничения -----------------------------------------------------------------

DENIED_PATH_PATTERNS = [
    re.compile(p)
    for p in (
        r"^/etc/g?shadow-?$",
        r"^/etc/security/opasswd$",
        r"^/etc/ssh/ssh_host_.*_key$",
        r"^/root/\.ssh/",
        r"^/home/[^/]+/\.ssh/",
        r"/id_(rsa|dsa|ecdsa|ed25519)$",
        r"\.(pem|key|p12|pfx)$",
        r"^/proc/[^/]+/environ$",
    )
]

# Локальные команды: исполняемый файл -> допустимые аргументы (строка через пробел). Только чтение.
LOCAL_COMMAND_POLICY = {
    "systemctl": re.compile(r"^(is-active|is-enabled|is-failed) [A-Za-z0-9_.@:-]+$"),
    "ufw": re.compile(r"^status( verbose)?$"),
    "dpkg-query": re.compile(r"^-W -f=\S+ [A-Za-z0-9_.+:-]+$"),
    "rpm": re.compile(r"^-q --qf \S+ [A-Za-z0-9_.+:-]+$"),
    "sysctl": re.compile(r"^-n [a-z0-9_.]+$"),
    "getenforce": re.compile(r"^$"),
    "aa-status": re.compile(r"^--enabled$"),
    "timedatectl": re.compile(r"^show( -p [A-Za-z]+)?( --value)?$"),
    "ss": re.compile(r"^-[tuln]+p?$"),
    # «сухой» прогон: modprobe только показывает, что сделал бы (install /bin/false — модуль запрещён)
    "modprobe": re.compile(r"^-n -v [a-z0-9_-]+$"),
    # Windows: состояние службы (sc query <имя>); вывод sc не локализуется, состояние — числом и константой
    "sc": re.compile(r"^query [A-Za-z0-9_.-]+$"),
    # только список запущенных контейнеров, одно поле inspect по конкретному id из закрытого списка
    # полей и флаг icc сети bridge (docker.yaml, СКО.1.2/1.3/1.5–1.9 по методике ФСТЭК); run/exec/rm — отказ
    "docker": re.compile(
        r"^(ps -q|inspect --format \{\{(\.HostConfig\.Privileged|\.HostConfig\.Binds|\.Config\.User"
        r"|\.HostConfig\.Memory|\.HostConfig\.NanoCpus|\.HostConfig\.NetworkMode|\.HostConfig\.PidMode"
        r"|json \.HostConfig\.PortBindings|json \.HostConfig\.SecurityOpt)"
        r"\}\} [a-f0-9]{6,64}"
        r'|network inspect bridge --format \{\{index \.Options "com\.docker\.network\.bridge\.enable_icc"\}\})$'
    ),
}

# Кусты с секретами (хэши паролей, секреты LSA): агент их не читает, даже если так написано в манифесте.
REG_DENIED = re.compile(r"^HKLM\\(SAM|SECURITY)(\\|$)", re.IGNORECASE)
_SC_STATE = re.compile(r"^\s*\S+\s*:\s*(\d)\s+(STOPPED|START_PENDING|STOP_PENDING|RUNNING|CONTINUE_PENDING|PAUSE_PENDING|PAUSED)\b", re.M)
# Start службы в реестре: 0/1 — загрузка/система, 2 — автоматически, 3 — вручную, 4 — отключена
_WIN_START = {0: "enabled", 1: "enabled", 2: "enabled", 3: "manual", 4: "disabled"}


def read_registry(key: str, name: str):
    """Значение HKLM\\... реестра или None, если ключа/значения нет. DWORD — int, MULTI_SZ — строка через запятую."""
    # Запреты — до всего остального: действуют независимо от платформы (и проверяемы тестами на Linux).
    if REG_DENIED.match(key):
        raise ProbeError(f"чтение {key} запрещено политикой агента")
    if not key.upper().startswith("HKLM\\"):
        raise ProbeError("агент читает только HKLM")
    if not IS_WINDOWS:
        raise ProbeError("реестр доступен только на Windows")
    import winreg  # стандартная библиотека на Windows

    try:
        # KEY_WOW64_64KEY: 64-битное представление реестра, даже если агент собран 32-битным
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key[5:], 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as handle:
            value, kind = winreg.QueryValueEx(handle, name)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ProbeError(f"нет доступа к {key}\\{name}: {exc.strerror or exc}") from exc
    if kind == winreg.REG_MULTI_SZ:
        return ",".join(value)
    if isinstance(value, bytes):
        return value.hex()
    return value


def parse_secedit(text: str) -> dict:
    """INF из `secedit /export`: {раздел: {ключ: значение}}."""
    sections, current = {}, None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            current = sections.setdefault(line[1:-1], {})
        elif current is not None and "=" in line:
            key, value = line.split("=", 1)
            current[key.strip()] = value.strip().strip('"')
    return sections


def parse_auditpol_backup(text: str) -> dict:
    """CSV из `auditpol /backup`: {GUID подкатегории: Setting Value (0–3)}. Колонки берутся по положению:
    их заголовки локализуются, а порядок и GUID — нет."""
    import csv
    import io

    result = {}
    for row in csv.reader(io.StringIO(text)):
        # Machine Name, Policy Target, Subcategory, Subcategory GUID, Inclusion, Exclusion, Setting Value
        if len(row) >= 7 and row[3].startswith("{") and row[6].strip().isdigit():
            result[row[3].strip().upper()] = int(row[6].strip())
    return result


# --- Active Directory (контроллер домена) ------------------------------------------
# Сведения о домене читаются одним сценарием PowerShell, ЗАШИТЫМ В АГЕНТ: манифест выбирает только имя
# сведения (win_ad, fact) из закрытого списка, но не текст запроса. Сценарий только читает каталог через
# ADSI (System.DirectoryServices, LDAP к самому контроллеру) — модуль ActiveDirectory и RSAT не нужны,
# ничего не изменяет. Группы ищутся по SID, а не по имени: на русской Windows «Администраторы домена».
# Вывод — JSON в Base64: только ASCII, кодовая страница консоли не важна (имена учётных записей бывают
# на кириллице). Каждое сведение со своей ошибкой: сбой одного запроса не обнуляет остальные.
AD_FACTS_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$out = [ordered]@{}
function Find-All([string]$base, [string]$filter, [string]$scope, [string[]]$props) {
    $s = New-Object System.DirectoryServices.DirectorySearcher
    $s.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$base")
    $s.Filter = $filter
    $s.SearchScope = $scope
    $s.PageSize = 1000
    foreach ($p in $props) { [void]$s.PropertiesToLoad.Add($p) }
    $r = $s.FindAll()
    try { foreach ($x in $r) { ,$x.Properties } } finally { $r.Dispose() }
}
function Get-Attr([string]$dn, [string]$attr) {
    $p = @(Find-All $dn '(objectClass=*)' 'Base' @($attr))
    if ($p.Count -eq 0 -or $p[0][$attr.ToLower()].Count -eq 0) { return $null }
    return $p[0][$attr.ToLower()][0]
}
function Required([string]$dn, [string]$attr) {
    $v = Get-Attr $dn $attr
    if ($null -eq $v) { throw "$attr is not set on $dn" }
    return $v
}
function Esc([string]$v) { $v -replace '\\', '\5c' -replace '\*', '\2a' -replace '\(', '\28' -replace '\)', '\29' }
function Sid([byte[]]$b) { (New-Object System.Security.Principal.SecurityIdentifier($b, 0)).Value }
function Group-Dn([string]$sid) { [string](Get-Attr "<SID=$sid>" 'distinguishedName') }
function Users([string]$filter) {
    @(Find-All $dn "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))$filter)" 'Subtree' @('samaccountname'))
}
function Counted($items) {
    $names = @($items | ForEach-Object { [string]$_['samaccountname'][0] } | Sort-Object | Select-Object -First 10)
    @{ value = @($items).Count; names = $names }
}
function Fact([string]$name, [scriptblock]$body) {
    try { $out[$name] = & $body } catch { $out[$name] = @{ error = $_.Exception.Message } }
}
function InChain([string[]]$sids) {
    # Группа леса (518, 519) из дочернего домена может не разрешиться — считаются остальные.
    $parts = foreach ($s in $sids) { try { $g = Group-Dn $s; if ($g) { '(memberOf:1.2.840.113556.1.4.1941:=' + (Esc $g) + ')' } } catch { } }
    if (-not $parts) { throw 'privileged groups not resolved' }
    '(|' + ($parts -join '') + ')'
}
try {
    $rootDse = New-Object System.DirectoryServices.DirectoryEntry('LDAP://RootDSE')
    $dn = [string]$rootDse.Properties['defaultNamingContext'][0]
    $cfg = [string]$rootDse.Properties['configurationNamingContext'][0]
    $forest = [string]$rootDse.Properties['rootDomainNamingContext'][0]
    $schema = [string]$rootDse.Properties['schemaNamingContext'][0]
    if (-not $dn) { throw 'RootDSE: defaultNamingContext is empty' }
    $domSid = Sid (Get-Attr $dn 'objectSid')
    $rootSid = Sid (Get-Attr $forest 'objectSid')
    $privileged = @("$domSid-512", "$rootSid-519", "$rootSid-518", 'S-1-5-32-544')
    Fact 'krbtgt_password_age_days' {
        $k = @(Find-All $dn '(&(objectClass=user)(sAMAccountName=krbtgt))' 'Subtree' @('pwdlastset'))
        $set = [DateTime]::FromFileTimeUtc([int64]$k[0]['pwdlastset'][0])
        @{ value = [int][Math]::Floor(((Get-Date).ToUniversalTime() - $set).TotalDays); evidence = 'pwdLastSet ' + $set.ToString('yyyy-MM-dd') }
    }
    Fact 'privileged_users_count' { Counted (Users (InChain $privileged)) }
    Fact 'schema_admins_count' { Counted (Users (InChain @("$rootSid-518"))) }
    Fact 'privileged_spn_users_count' { Counted (Users ('(servicePrincipalName=*)(!(sAMAccountName=krbtgt))' + (InChain $privileged))) }
    Fact 'unconstrained_delegation_count' {
        Counted @(Find-All $dn '(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=8192))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' 'Subtree' @('samaccountname'))
    }
    Fact 'asrep_roastable_count' { Counted (Users '(userAccountControl:1.2.840.113556.1.4.803:=4194304)') }
    Fact 'password_never_expires_count' { Counted (Users '(userAccountControl:1.2.840.113556.1.4.803:=65536)') }
    Fact 'password_not_required_count' { Counted (Users '(userAccountControl:1.2.840.113556.1.4.803:=32)') }
    Fact 'reversible_encryption_users_count' { Counted (Users '(userAccountControl:1.2.840.113556.1.4.803:=128)') }
    Fact 'des_only_users_count' { Counted (Users '(userAccountControl:1.2.840.113556.1.4.803:=2097152)') }
    Fact 'machine_account_quota' { @{ value = [int](Required $dn 'ms-DS-MachineAccountQuota') } }
    Fact 'domain_functional_level' { @{ value = [int](Required $dn 'msDS-Behavior-Version') } }
    Fact 'recycle_bin_enabled' {
        $bl = @(Find-All "CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,$cfg" '(objectClass=*)' 'Base' @('msds-enabledfeaturebl'))
        @{ value = [int]($bl.Count -gt 0 -and $bl[0]['msds-enabledfeaturebl'].Count -gt 0) }
    }
    Fact 'anonymous_ldap_allowed' {
        $h = [string](Get-Attr "CN=Directory Service,CN=Windows NT,CN=Services,$cfg" 'dSHeuristics')
        @{ value = [int]($h.Length -ge 7 -and $h[6] -eq '2'); evidence = "dSHeuristics=$h" }
    }
    Fact 'laps_schema_present' {
        $a = @(Find-All $schema '(|(lDAPDisplayName=ms-Mcs-AdmPwd)(lDAPDisplayName=msLAPS-Password))' 'OneLevel' @('ldapdisplayname'))
        @{ value = [int]($a.Count -gt 0); evidence = (@($a | ForEach-Object { [string]$_['ldapdisplayname'][0] }) -join ', ') }
    }
} catch {
    $out['_error'] = $_.Exception.Message
}
$json = $out | ConvertTo-Json -Depth 4 -Compress
[Console]::Out.Write([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json)))
"""


def ad_facts_argv() -> "list[str]":
    """Запуск встроенного сценария: -EncodedCommand (UTF-16LE в Base64) — без файлов и без экранирования."""
    import base64

    encoded = base64.b64encode(AD_FACTS_SCRIPT.encode("utf-16-le")).decode("ascii")
    return ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded]


def parse_ad_facts(stdout: str) -> dict:
    """Base64(JSON) сценария → {сведение: {value[, names, evidence] | error}}. Общая ошибка (_error) —
    контроллер домена недоступен, хост не в домене: ProbeError для всех проверок, а не «нарушений нет»."""
    import base64

    text = stdout.strip()
    try:
        facts = json.loads(base64.b64decode(text, validate=True).decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ProbeError(f"сведения AD: не удалось разобрать вывод ({text[:120]!r})") from exc
    if not isinstance(facts, dict):
        raise ProbeError("сведения AD: неожиданный формат")
    if facts.get("_error"):
        raise ProbeError(f"сведения AD недоступны: {str(facts['_error'])[:300]}")
    return facts


CLI_FILTERS = ("include", "exclude", "begin", "section", "count", "match", "except")
_CLI_SEGMENT = re.compile(r"^[A-Za-z0-9 _./^:\-]+$")
_CLI_READONLY = re.compile(
    r"^(show|display) [A-Za-z0-9 _./^:\-]+$"
    r"|^/export( [A-Za-z0-9 _./=\-]+)?$"
    r"|^/[a-z0-9/ -]+ print( [A-Za-z0-9 _./=\-]+)?$"
    # ViPNet Coordinator (командный интерпретатор ИнфоТеКС): просмотр — «<группа> show …», «iplir option get <параметр>»
    # и «version»; остальные команды групп (set, start, stop, config) меняют состояние и сюда не входят.
    r"|^(inet|iplir|machine|failover|mftp|ups) show( [A-Za-z0-9 _./:\-]+)?$"
    r"|^iplir option get [a-z-]+$"
    r"|^version( full)?$"
)
# Слово-секрет — отдельное слово: не часть составного (prohibit-password, password-encryption, PasswordAuthentication).
_SECRET_WORDS = re.compile(r"(?i)(?<![\w-])(password|passwd|secret|community|token|hash|psk|pre-shared-key|private-key)(?![\w-]).*$")
_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")
_USER_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*$")


def is_readonly_cli(command: str) -> bool:
    """Команда конфигурации сетевого устройства только на чтение. После `|` допустимы лишь
    фильтры вывода самого устройства (include/exclude/…), а не произвольные команды."""
    if len(command) > 200:
        return False
    head, *filters = command.split("|")
    if not _CLI_READONLY.match(head.strip()):
        return False
    for segment in filters:
        words = segment.strip().split(None, 1)
        if not words or words[0] not in CLI_FILTERS or not _CLI_SEGMENT.match(segment):
            return False
    return True


def redact(line: str) -> str:
    """Свидетельство для отчёта: всё, что идёт после слова-секрета, маскируется. Хэши паролей
    и SNMP-community не покидают хост."""
    return _SECRET_WORDS.sub(lambda m: m.group(1) + " ***", line.strip())[:300]


class CmdOutput:
    def __init__(self, stdout: str, stderr: str, code: int):
        self.stdout, self.stderr, self.code = stdout, stderr, code

    @property
    def text(self) -> str:
        return self.stdout if self.stdout.strip() else self.stderr


# --- транспорты ------------------------------------------------------------------

class LocalTransport:
    """Пробы выполняются на самом хосте, где запущен агент."""

    name = "local"

    def __init__(self):
        self.platform = "windows" if IS_WINDOWS else "posix"
        self._secpol = self._auditpol = self._ad = None  # кэш на прогон: экспорт дорогой и одинаков для всех проверок

    def _check_path(self, path: str) -> str:
        real = os.path.realpath(path)
        for candidate in (path, real):
            if any(p.search(candidate) for p in DENIED_PATH_PATTERNS):
                raise ProbeError(f"чтение {candidate} запрещено политикой агента")
        return real

    def read_file(self, path: str) -> str:
        real = self._check_path(path)
        try:
            with open(real, encoding="utf-8", errors="replace") as fh:
                return fh.read(MAX_FILE_BYTES)
        except OSError as exc:
            raise ProbeError(f"не удалось прочитать {path}: {exc.strerror or exc}") from exc

    def stat_file(self, path: str) -> os.stat_result:
        try:
            return os.stat(path)
        except OSError as exc:
            raise ProbeError(f"не удалось получить stat {path}: {exc.strerror or exc}") from exc

    def glob(self, pattern: str) -> "list[str]":
        """Файлы по маске в лексическом порядке; запрещённые политикой пути в выдачу не попадают."""
        found = sorted(glob.glob(pattern))[:MAX_INCLUDE_FILES]
        return [p for p in found if not any(d.search(p) or d.search(os.path.realpath(p)) for d in DENIED_PATH_PATTERNS)]

    def run(self, argv: "list[str]") -> CmdOutput:
        policy = LOCAL_COMMAND_POLICY.get(argv[0]) if argv else None
        if policy is None or not policy.match(" ".join(argv[1:])):
            raise ProbeError(f"команда вне белого списка агента: {' '.join(argv)}")
        return self._execute(argv)

    def _execute(self, argv: "list[str]", timeout: int = COMMAND_TIMEOUT) -> CmdOutput:
        """Запуск без shell из системного каталога. Команды из манифеста попадают сюда только через run()
        (белый список); secedit и auditpol с фиксированными аргументами агент вызывает сам."""
        search = WINDOWS_SYSTEM32 + os.pathsep + WINDOWS_POWERSHELL_DIR if IS_WINDOWS else SAFE_PATH
        exe = shutil.which(argv[0], path=search)
        if exe is None:
            raise ProbeError(f"команда {argv[0]} не найдена")
        env = ({"SystemRoot": os.environ.get("SystemRoot", r"C:\Windows"), "PATH": WINDOWS_SYSTEM32,
                "TEMP": tempfile.gettempdir(), "TMP": tempfile.gettempdir()}
               if IS_WINDOWS else {"PATH": SAFE_PATH, "LANG": "C", "LC_ALL": "C"})
        try:
            proc = subprocess.run(
                [exe, *argv[1:]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=timeout,
                env=env, check=False, errors="replace",
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ProbeError(f"команда {argv[0]} не выполнилась: {exc}") from exc
        return CmdOutput(proc.stdout, proc.stderr, proc.returncode)

    def read_registry(self, key: str, name: str):
        return read_registry(key, name)

    def _export(self, build_argv, what: str) -> str:
        """secedit /export и auditpol /backup пишут результат в файл: временный файл в личном TEMP агента,
        читается и сразу удаляется. Системная конфигурация не меняется."""
        if not IS_WINDOWS:
            raise ProbeError(f"{what} доступен только на Windows")
        # Файла заранее быть не должно: auditpol /backup отказывается перезаписывать существующий
        # (код 80, «Failed to open file»), а secedit в том же случае мог «успешно» не записать ничего.
        # Поэтому — новый временный каталог, путь к ещё не созданному файлу в нём.
        workdir = tempfile.mkdtemp(prefix="hardening-")
        path = os.path.join(workdir, "export.txt")
        try:
            out = self._execute(build_argv(path))
            if out.code != 0:
                raise ProbeError(f"{what}: код {out.code} (нужны права администратора?) {out.text.strip()[:150]}")
            try:
                raw = open(path, "rb").read()
            except OSError as exc:
                raise ProbeError(f"{what}: результат не записан ({exc.strerror or exc})") from exc
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
        if not raw.strip(b"\x00\r\n \t\xff\xfe\xef\xbb\xbf"):
            # Пустой экспорт — сбой, а не «ничего не задано»: иначе все проверки молча ушли бы в умолчания.
            raise ProbeError(f"{what}: пустой результат")
        for encoding in ("utf-16", "utf-8-sig", "cp1251"):
            try:
                return raw.decode(encoding)
            except UnicodeDecodeError:
                continue
        raise ProbeError(f"{what}: не удалось прочитать результат")

    def secpol(self) -> dict:
        if self._secpol is None:
            parsed = parse_secedit(self._export(
                lambda path: ["secedit", "/export", "/cfg", path, "/areas", "SECURITYPOLICY", "/quiet"],
                "экспорт политики безопасности"))
            if "System Access" not in parsed:
                raise ProbeError("экспорт политики безопасности: нет раздела [System Access]")
            self._secpol = parsed
        return self._secpol

    def auditpol(self) -> dict:
        if self._auditpol is None:
            parsed = parse_auditpol_backup(self._export(
                lambda path: ["auditpol", "/backup", f"/file:{path}"], "резервная копия политики аудита"))
            if not parsed:
                raise ProbeError("резервная копия политики аудита: подкатегории не найдены")
            self._auditpol = parsed
        return self._auditpol

    def ad_facts(self) -> dict:
        if not IS_WINDOWS:
            raise ProbeError("сведения AD доступны только на контроллере домена Windows")
        if self._ad is None:
            out = self._execute(ad_facts_argv(), timeout=AD_TIMEOUT)
            if out.code != 0 and not out.stdout.strip():
                raise ProbeError(f"сведения AD: powershell, код {out.code}: {out.stderr.strip()[:200]}")
            self._ad = parse_ad_facts(out.stdout)
        return self._ad

    def run_cli(self, command: str) -> CmdOutput:
        raise ProbeError("cli_config недоступна на локальном транспорте")


class SshTransport:
    """Внешний сбор с сетевого устройства по SSH. Учётка на устройстве — только на чтение,
    ключ/пароль вне пака. Проверка ключа хоста включена и не отключается: устройство должно
    быть в known_hosts (иначе это подмена устройства, а не повод продолжать)."""

    name = "ssh"

    def __init__(self, host: str, user: "str | None" = None, port: int = 22, key_path: "str | None" = None,
                 connect_timeout: int = 10, command_timeout: int = 30, runner=None):
        if not _HOST_RE.match(host) or (user is not None and not _USER_RE.match(user)):
            raise ValueError("недопустимое имя хоста или пользователя SSH")
        self.destination = f"{user}@{host}" if user else host
        self.port, self.key_path = port, key_path
        self.connect_timeout, self.command_timeout = connect_timeout, command_timeout
        self._runner = runner or subprocess.run

    def _ssh_argv(self, command: str) -> "list[str]":
        argv = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                "-o", f"ConnectTimeout={self.connect_timeout}", "-p", str(self.port)]
        if self.key_path:
            argv += ["-i", self.key_path]
        return argv + ["--", self.destination, command]

    def run_cli(self, command: str) -> CmdOutput:
        if not is_readonly_cli(command):
            raise ProbeError(f"по SSH допустимы только команды на чтение: {command!r}")
        try:
            proc = self._runner(self._ssh_argv(command), stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                                timeout=self.command_timeout, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            raise ProbeError(f"SSH-команда не выполнилась: {exc}") from exc
        if proc.returncode == 255:  # код самого ssh: соединение/аутентификация/ключ хоста
            raise ProbeError(f"ssh: {(proc.stderr or '').strip()[:200] or 'ошибка соединения'}")
        return CmdOutput(proc.stdout, proc.stderr, proc.returncode)

    def run(self, argv: "list[str]") -> CmdOutput:
        return self.run_cli(" ".join(argv))

    def read_file(self, path: str) -> str:
        raise ProbeError("файловые пробы недоступны на транспорте ssh")

    def stat_file(self, path: str) -> os.stat_result:
        raise ProbeError("file_stat недоступна на транспорте ssh")

    platform = "network"

    def read_registry(self, key: str, name: str):
        raise ProbeError("реестр недоступен на транспорте ssh")

    def secpol(self) -> dict:
        raise ProbeError("политика безопасности Windows недоступна на транспорте ssh")

    def auditpol(self) -> dict:
        raise ProbeError("политика аудита Windows недоступна на транспорте ssh")


MAX_OFFLINE_BYTES = 5_000_000


def offline_file_name(command: str) -> str:
    """Имя файла выгрузки для команды: `show running-config` → `show_running-config.txt`,
    `display current-configuration` → `display_current-configuration.txt`, `/export` → `export.txt`."""
    return re.sub(r"[^A-Za-z0-9.-]+", "_", command).strip("_") + ".txt"


class OfflineConfigTransport:
    """Сбор по выгрузке конфигурации вместо живого устройства: вывод команд заранее сохранён в файлы
    (бэкап Oxidized/RANCID, выгрузка администратором, образец от заказчика). Для устройств, к которым нет
    SSH-доступа, и для вендоров, которых нет на стенде. Паки те же, что для ssh (pack_transport), и проба
    cli_config та же — меняется только источник текста. Ничего не выполняется: файлы только читаются.

    Выгрузка — не живое устройство: конфигурация могла измениться после неё. Поэтому transport.name
    другой («offline-config»), а describe() отдаёт хэш и время каждого прочитанного файла для отчёта."""

    name = "offline-config"
    pack_transport = "ssh"
    platform = "network"

    def __init__(self, directory: str):
        if not os.path.isdir(directory):
            raise ValueError(f"нет каталога выгрузки {directory}")
        self.directory = directory
        self.used = {}      # команда → {file, sha256, modified}
        self.missing = set()  # команды, выгрузки которых нет (для detect по --pack)

    def run_cli(self, command: str) -> CmdOutput:
        # Тот же белый список, что и по SSH: подписанный манифест не может «прочитать» команду на изменение.
        if not is_readonly_cli(command):
            raise ProbeError(f"допустимы только команды на чтение: {command!r}")
        if "|" in command:
            # Фильтры include/section/begin выполняет само устройство, и их смысл у вендоров разный —
            # эмуляция по файлу дала бы другой ответ, чем устройство. Пак для выгрузки фильтров не использует.
            raise ProbeError(f"фильтры вывода по выгрузке не поддерживаются: {command!r}")
        name = offline_file_name(command)
        path = os.path.join(self.directory, name)
        if not os.path.isfile(path) or os.path.islink(path):
            self.missing.add(command)
            raise ProbeError(f"нет выгрузки команды {command!r} (ожидается файл {name})")
        if os.path.getsize(path) > MAX_OFFLINE_BYTES:
            raise ProbeError(f"выгрузка {name} больше {MAX_OFFLINE_BYTES} байт")
        with open(path, "rb") as fh:
            raw = fh.read()
        if not raw.strip(b"\x00\r\n \t\xef\xbb\xbf"):
            # Пустой файл — сбой выгрузки, а не «ничего не задано»: иначе проверки «параметра нет» прошли бы.
            raise ProbeError(f"выгрузка {name} пустая")
        for encoding in ("utf-8-sig", "cp1251"):
            try:
                text = raw.decode(encoding)
                break
            except UnicodeDecodeError:
                continue
        self.used[command] = {
            "command": command, "file": name, "sha256": hashlib.sha256(raw).hexdigest(),
            "modified": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(os.path.getmtime(path))),
        }
        return CmdOutput(text, "", 0)

    def run(self, argv: "list[str]") -> CmdOutput:
        return self.run_cli(" ".join(argv))

    def describe(self) -> dict:
        """Откуда взяты данные — для снимка и отчёта."""
        return {"source": self.name, "files": [self.used[c] for c in sorted(self.used)]}

    def read_file(self, path: str) -> str:
        raise ProbeError("файловые пробы недоступны на выгрузке конфигурации")

    def stat_file(self, path: str) -> os.stat_result:
        raise ProbeError("file_stat недоступна на выгрузке конфигурации")

    def read_registry(self, key: str, name: str):
        raise ProbeError("реестр недоступен на выгрузке конфигурации")

    def secpol(self) -> dict:
        raise ProbeError("политика безопасности Windows недоступна на выгрузке конфигурации")

    def auditpol(self) -> dict:
        raise ProbeError("политика аудита Windows недоступна на выгрузке конфигурации")


# --- пробы -----------------------------------------------------------------------

def _ok(value, evidence: "str | None" = None) -> dict:
    return {"found": True, "value": value, "evidence": redact(evidence) if evidence else None}


def _search(pattern: str, text: str) -> "tuple[str | None, str | None]":
    m = re.search(pattern, text, re.MULTILINE)
    if not m:
        return None, None
    return (m.group(1) if m.groups() else m.group(0)), m.group(0)


def _expand_lines(t, path: str, base_dir: str, follow_include: bool, skip_match: bool, state: dict, depth: int = 0):
    """Строки файла в порядке разбора. Include подставляется на месте директивы (как в sshd: маска,
    относительные пути — от base_dir, файлы по маске в лексическом порядке). Строки после Match
    условные и в глобальное значение не входят; в sshd блок Match заканчивается вместе с файлом,
    поэтому Match во включённом файле не «протекает» в следующий."""
    for raw in t.read_file(path).splitlines():
        line = raw.strip()
        lowered = line.lower()
        if skip_match and lowered.startswith("match "):
            return
        if follow_include and lowered.startswith("include "):
            if depth >= MAX_INCLUDE_DEPTH:
                continue
            for pattern in line.split()[1:]:
                full = pattern if pattern.startswith("/") else base_dir.rstrip("/") + "/" + pattern
                for included in t.glob(full):
                    if state["files"] >= MAX_INCLUDE_FILES:
                        return
                    state["files"] += 1
                    try:
                        yield from _expand_lines(t, included, base_dir, follow_include, skip_match, state, depth + 1)
                    except ProbeError:
                        continue  # нечитаемый включаемый файл не отменяет остальные
            continue
        yield raw


def probe_file_kv(t, p: dict) -> dict:
    """Параметр `ключ значение` / `ключ=значение`. Для формата whitespace (sshd_config) разбор в каждом
    файле останавливается на строке Match — параметры ниже неё условные. С follow_include: true
    директивы Include раскрываются (на Ubuntu 22.04+ параметры sshd лежат и в sshd_config.d/*.conf,
    а первое найденное значение побеждает)."""
    key, sep = p["key"], p.get("separator", "whitespace")
    ignore_case, take_last = p.get("ignore_case", True), p.get("match", "first") == "last"
    lines = _expand_lines(t, p["path"], os.path.dirname(p["path"]), bool(p.get("follow_include")),
                          sep == "whitespace", {"files": 0})
    value = line_found = None
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("=", 1) if sep == "equals" else line.split(None, 1)
        if len(parts) != 2:
            continue
        name = parts[0].strip()
        if (name.lower() == key.lower()) if ignore_case else (name == key):
            value, line_found = parts[1].strip().strip('"').strip("'"), line
            if not take_last:
                break
    if value is None:
        default = p.get("default")
        return _ok(default, "(значение по умолчанию)") if default is not None else _ok(None)
    return _ok(value, line_found)


def probe_file_regex(t, p: dict) -> dict:
    value, matched = _search(p["pattern"], t.read_file(p["path"]))
    return _ok(value, matched)


def probe_file_stat(t, p: dict) -> dict:
    st = t.stat_file(p["path"])
    field = p.get("field", "mode")
    if field == "mode":
        return _ok(format(st.st_mode & 0o7777, "o"))
    if field in ("uid", "gid"):
        return _ok(getattr(st, "st_" + field))
    try:
        import grp
        import pwd
        name = pwd.getpwuid(st.st_uid).pw_name if field == "owner" else grp.getgrgid(st.st_gid).gr_name
    except (ImportError, KeyError):
        name = str(st.st_uid if field == "owner" else st.st_gid)
    return _ok(name)


def probe_cmd_regex(t, p: dict) -> dict:
    out = t.run(p["cmd"])
    value, matched = _search(p["pattern"], out.text)
    return _ok(value, matched)


def probe_cmd_foreach(t, p: dict) -> dict:
    """Команда-список, затем команда по каждому элементу; значение — число элементов, вывод которых
    подходит под pattern. Каждый вызов проходит белый список отдельно (id контейнера — тоже аргумент
    под проверкой, а не подстановка в строку). Ошибка любой из команд — проба не выполнилась, а не «0»:
    иначе недоступный docker выглядел бы как «привилегированных контейнеров нет»."""
    listing = t.run(p["list_cmd"])
    if listing.code != 0:
        raise ProbeError(f"{p['list_cmd'][0]} завершилась с кодом {listing.code}: {listing.stderr.strip()[:150]}")
    items = [line.strip() for line in listing.stdout.splitlines() if line.strip()]
    limit = min(int(p.get("max_items", 100)), 200)
    if len(items) > limit:
        raise ProbeError(f"элементов {len(items)} больше допустимых {limit}")
    matched = 0
    for item in items:
        out = t.run([*p["item_cmd"], item])
        if out.code != 0:
            raise ProbeError(f"{p['item_cmd'][0]} для {item[:12]} завершилась с кодом {out.code}")
        if re.search(p["pattern"], out.stdout, re.MULTILINE):
            matched += 1
    return _ok(matched, f"{matched} из {len(items)}")


def _cli_text(t, p: dict) -> str:
    """Вывод команды устройства, проверенный ДО разбора: при нехватке прав IOS отвечает `% Invalid input…`
    вместо конфигурации, и все проверки «параметра нет» ложно прошли бы на пустом выводе. Поэтому строка-ошибка
    `% …` — отказ пробы, а `require` (необязательно) задаёт признак настоящего вывода (например, завершающий
    `end` running-config)."""
    text = t.run_cli(p["cmd"]).stdout
    first = next((line for line in text.splitlines() if line.strip()), "")
    if re.match(r"\s*%\s", first):
        raise ProbeError(f"устройство вернуло ошибку: {first.strip()[:120]}")
    if p.get("require") and not re.search(p["require"], text, re.MULTILINE):
        raise ProbeError("вывод команды не похож на ожидаемый (нет прав на просмотр конфигурации или неверная команда)")
    return text


def probe_cli_config(t, p: dict) -> dict:
    """Строка/раздел конфигурации устройства (первая строка, совпавшая с match)."""
    lines = _cli_text(t, p).splitlines()
    section = p.get("section")
    if section is not None:
        scoped, inside = [], False
        for line in lines:
            if line[:1] not in (" ", "\t") and line.strip():
                inside = re.search(section, line) is not None
            elif inside:
                scoped.append(line)
        lines = scoped
    for line in lines:
        m = re.search(p["match"], line)
        if m:
            return _ok(_cli_value(m, line), line)
    if "default" in p:
        # Значение по умолчанию устройство в running-config не показывает: нет строки — действует умолчание
        # (минимальная длина пароля 1, срок действия не ограничен и т. п.), а не «нечего сравнивать».
        return _ok(p["default"], "строки нет — значение по умолчанию")
    return _ok(None)


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" \t"))


def _cli_blocks(lines: "list[str]", header: str) -> "list[tuple[str, list[str]]]":
    """Блоки конфигурации по отступам: заголовок (строка, совпавшая с header) и все следующие строки с большим
    отступом. Блок кончается на первой непустой строке с отступом не больше, чем у заголовка, — это и `!` у
    Cisco/Qtech, и `exit` у Eltex. Строки тела — исходные, с отступами (для вложенного поиска)."""
    found = []
    for i, line in enumerate(lines):
        if not line.strip() or not re.search(header, line.strip()):
            continue
        level, body = _indent(line), []
        for nxt in lines[i + 1:]:
            if not nxt.strip():
                continue
            if _indent(nxt) <= level:
                break
            body.append(nxt)
        found.append((line.strip(), body))
    return found


def probe_cli_blocks(t, p: dict) -> dict:
    """ЧИСЛО блоков конфигурации, удовлетворяющих условиям: в теле есть строка под каждое выражение `has` и нет ни
    одной строки под выражения `lacks`. `within` — блок-родитель (например, пара зон Eltex ESR), внутри которого
    ищутся блоки `block` (правила). Так выражается то, что одной строкой не проверить: «правило разрешает доступ
    и НЕ ограничивает адрес источника», «в каждом блоке line vty задан transport input»."""
    lines = _cli_text(t, p).splitlines()
    scopes = [body for _, body in _cli_blocks(lines, p["within"])] if p.get("within") else [lines]
    total, matched = 0, []
    for scope in scopes:
        for header, body in _cli_blocks(scope, p["block"]):
            total += 1
            stripped = [line.strip() for line in body]
            if all(any(re.search(rx, line) for line in stripped) for rx in p.get("has", [])) and not any(
                re.search(rx, line) for rx in p.get("lacks", []) for line in stripped
            ):
                matched.append(header)
    evidence = "; ".join(matched[:5]) if matched else f"подходящих блоков нет (всего блоков: {total})"
    return _ok(len(matched), evidence)


def _cli_value(m, line: str) -> str:
    """Значение для сервера — без секретов, как и свидетельство: значение сохраняется в снимке и попадает
    в интерфейс и отчёты. Строка целиком маскируется (`enable secret ***`); группа, захватившая текст
    после слова-секрета (`snmp-server community (\\S+)`), заменяется на «***»."""
    if not m.groups():
        return redact(line)
    secret = _SECRET_WORDS.search(line)
    if secret and m.end(1) > secret.end(1):
        return "***"
    return m.group(1)


# Состояния, которые печатает systemctl is-active / is-enabled (systemd 219+, RHEL 7 и новее).
_SYSTEMD_ACTIVE_STATES = {"active", "inactive", "failed", "activating", "deactivating", "reloading", "refreshing",
                          "maintenance", "unknown"}
_SYSTEMD_ENABLED_STATES = {"enabled", "enabled-runtime", "disabled", "static", "masked", "masked-runtime", "indirect",
                           "generated", "transient", "alias", "linked", "linked-runtime", "not-found"}
# Именно «юнита нет», а не любая ошибка: «Failed to connect to bus: No such file or directory» — сбой шины.
_UNIT_MISSING = re.compile(
    r"Unit \S+ could not be found|Failed to get unit file state for \S+: No such file or directory|Unit \S+ not loaded",
    re.IGNORECASE,
)


def _windows_service_state(t, p: dict) -> dict:
    """Та же проба на Windows, в тех же словах, что systemd: active/inactive, enabled/manual/disabled.
    Автозапуск — из реестра (Start), работа — из `sc query` (число и константа состояния не локализуются)."""
    service = p["service"]
    if p.get("field") == "enabled":
        start = _capability(t, "read_registry")(f"HKLM\\SYSTEM\\CurrentControlSet\\Services\\{service}", "Start")
        if start is None:
            return _ok("not-found", "служба не установлена")
        return _ok(_WIN_START.get(int(start), f"start-{start}"), f"Start={start}")
    out = t.run(["sc", "query", service])
    if out.code == 1060:  # ERROR_SERVICE_DOES_NOT_EXIST
        return _ok("not-found", "служба не установлена")
    match = _SC_STATE.search(out.stdout)
    if not match:
        raise ProbeError(f"sc query {service}: состояние не распознано (код {out.code})")
    return _ok("active" if match.group(2) == "RUNNING" else "inactive", f"{match.group(1)} {match.group(2)}")


def _capability(t, name: str):
    """Метод транспорта или ProbeError: транспорт, который этого не умеет (Linux, SSH, тестовый), даёт
    «проба не выполнилась», а не AttributeError, обрывающий весь прогон."""
    method = getattr(t, name, None)
    if method is None:
        raise ProbeError(f"транспорт {getattr(t, 'name', '?')} не поддерживает {name}")
    return method


def probe_reg_value(t, p: dict) -> dict:
    value = _capability(t, "read_registry")(p["key"], p["value"])
    if value is None:
        default = p.get("default")
        return _ok(default, "(значение по умолчанию Windows)") if default is not None else _ok(None)
    return _ok(value, f"{p['value']}={value}")


def probe_win_secpol(t, p: dict) -> dict:
    section = _capability(t, "secpol")().get(p.get("section", "System Access"), {})
    value = section.get(p["key"])
    if value is None:
        default = p.get("default")
        return _ok(default, "(значение по умолчанию Windows)") if default is not None else _ok(None)
    return _ok(value, f"{p['key']} = {value}")


def probe_win_auditpol(t, p: dict) -> dict:
    guid = p["subcategory"].upper()
    policy = _capability(t, "auditpol")()
    if guid not in policy:
        raise ProbeError(f"подкатегория аудита {guid} не найдена в политике аудита")
    labels = {0: "нет", 1: "успех", 2: "отказ", 3: "успех и отказ"}
    return _ok(policy[guid], f"{guid}: {labels.get(policy[guid], policy[guid])}")


def probe_win_ad(t, p: dict) -> dict:
    """Сведение о домене из закрытого списка (AD_FACTS_SCRIPT). Счётчики учётных записей — число, в
    свидетельстве до 10 имён: администратору сразу видно, кого исправлять."""
    fact = _capability(t, "ad_facts")().get(p["fact"])
    if fact is None:
        raise ProbeError(f"сведение AD {p['fact']} не получено")
    if "error" in fact:
        raise ProbeError(f"сведение AD {p['fact']}: {str(fact['error'])[:300]}")
    value, names = fact.get("value"), fact.get("names") or []
    if names:
        evidence = f"{value}: {', '.join(names)}" + (" …" if isinstance(value, int) and value > len(names) else "")
    else:
        evidence = fact.get("evidence") or f"{p['fact']} = {value}"
    return _ok(value, evidence)


def probe_service_state(t, p: dict) -> dict:
    if getattr(t, "platform", "posix") == "windows":
        return _windows_service_state(t, p)
    verb = "is-enabled" if p.get("field") == "enabled" else "is-active"
    out = t.run(["systemctl", verb, p["service"]])
    # Значение — только известное состояние из stdout. Раньше при пустом stdout значением становился текст
    # ошибки из stderr («System has not been booted with systemd», «Failed to connect to bus»): проверка
    # «служба не активна» (ne active) засчитывалась как соблюдённая, «служба активна» — как нарушенная,
    # хотя состояние неизвестно. Найдено прогоном агента в контейнерах RHEL-семейства без systemd.
    first = out.stdout.strip().splitlines()[0].strip() if out.stdout.strip() else ""
    if first in (_SYSTEMD_ENABLED_STATES if verb == "is-enabled" else _SYSTEMD_ACTIVE_STATES):
        return _ok(first)
    error = (out.stderr or out.stdout).strip()
    if _UNIT_MISSING.search(error):
        return _ok("not-found", error.splitlines()[0][:200])
    raise ProbeError(f"systemctl {verb} {p['service']}: состояние не получено ({error.splitlines()[0][:150] if error else f'код {out.code}'})")


def probe_pkg_version(t, p: dict) -> dict:
    name = p["package"]
    if shutil.which("dpkg-query", path=SAFE_PATH):
        out = t.run(["dpkg-query", "-W", "-f=${Status}|${Version}", name])
        status, _, version = out.stdout.partition("|")
        return _ok(version.strip() if status.startswith("install ok installed") and version.strip() else None)
    out = t.run(["rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}", name])
    text = out.stdout.strip()
    return _ok(None if (not text or "is not installed" in text) else text)


def probe_first_of(t, p: dict) -> dict:
    """Источники по порядку: результат первой пробы, нашедшей значение. Так старый сборщик получал
    состояние ufw: `ufw status` (нужен root), иначе файл конфигурации. Если ни одна не нашла значение,
    но хоть один источник прочитан — значение пусто; если ни один не доступен — проба не выполнилась."""
    readable, last_error = False, None
    for sub in p["probes"]:
        if sub.get("type") == "first_of":
            raise ProbeError("first_of не может содержать другой first_of")
        result = run_probe(t, sub)
        if result["found"]:
            readable = True
            if result["value"] is not None:
                return result
        else:
            last_error = result.get("error")
    if readable:
        return _ok(None)
    raise ProbeError(last_error or "ни один источник first_of недоступен")


PROBES = {
    "file_kv": probe_file_kv,
    "file_regex": probe_file_regex,
    "file_stat": probe_file_stat,
    "cmd_regex": probe_cmd_regex,
    "cmd_foreach": probe_cmd_foreach,
    "cli_config": probe_cli_config,
    "cli_blocks": probe_cli_blocks,
    "service_state": probe_service_state,
    "pkg_version": probe_pkg_version,
    "first_of": probe_first_of,
    "reg_value": probe_reg_value,
    "win_secpol": probe_win_secpol,
    "win_auditpol": probe_win_auditpol,
    "win_ad": probe_win_ad,
}


def run_probe(transport, probe: dict) -> dict:
    """Результат пробы: {found, value, evidence[, error]}. found=False — проба не смогла выполниться."""
    handler = PROBES.get(probe.get("type"))
    try:
        if handler is None:
            raise ProbeError(f"тип пробы {probe.get('type')!r} не поддерживается агентом")
        return handler(transport, probe)
    except ProbeError as exc:
        return {"found": False, "value": None, "evidence": None, "error": str(exc)[:500]}


# --- манифест: детект и выполнение -------------------------------------------------

def matches_detect(transport, detect_rules: "list[dict]") -> bool:
    """Платформа распознана, только если совпали все условия detect."""
    for rule in detect_rules:
        result = run_probe(transport, rule["probe"])
        if not result["found"] or result["value"] is None:
            return False
        actual = str(result["value"]).strip().strip('"').lower()
        if "equals" in rule:
            if actual != str(rule["equals"]).strip().lower():
                return False
        elif not re.search(rule["regex"], str(result["value"])):
            return False
    return True


def pack_transport(transport) -> str:
    """Каким пакам подходит транспорт: выгрузка конфигурации читается теми же паками, что и SSH."""
    return getattr(transport, "pack_transport", transport.name)


def select_manifests(transport, manifests: "list[dict]", declared: "str | None" = None) -> "list[dict]":
    """Паки, чей detect совпал. declared — пак, заданный оператором явно (--pack): для выгрузки
    конфигурации он принимается и без detect, если выгрузки команды detect нет (обычно сохраняют только
    running-config, без show version). Если выгрузка есть и detect не совпал — пак не применяется:
    явное указание не перекрывает противоречащие ему данные."""
    selected = []
    for m in manifests:
        if m.get("transport") != pack_transport(transport):
            continue
        if matches_detect(transport, m["detect"]) or (m["pack"] == declared and _detect_unavailable(transport, m["detect"])):
            selected.append(m)
    return selected


def _detect_unavailable(transport, detect_rules: "list[dict]") -> bool:
    """Ни для одного условия detect нет выгрузки — платформу по данным не проверить (ни подтвердить, ни опровергнуть)."""
    missing = getattr(transport, "missing", None)
    if missing is None or not detect_rules:
        return False
    for rule in detect_rules:
        run_probe(transport, rule["probe"])
        if rule["probe"].get("cmd") not in missing:
            return False
    return True


def run_manifest(transport, manifest: dict, log=None) -> dict:
    """Выполняет пробы пака, возвращает {id проверки: результат}. log(entry) — журнал запуска
    (что и как долго выполнялось) для аудита самого агента."""
    results = {}
    for check in manifest["checks"]:
        started = time.monotonic()
        results[check["id"]] = run_probe(transport, check["probe"])
        if log:
            log({
                "pack": manifest["pack"], "version": manifest["version"], "check": check["id"],
                "probe": check["probe"].get("type"), "found": results[check["id"]]["found"],
                "seconds": round(time.monotonic() - started, 3),
            })
    return results
