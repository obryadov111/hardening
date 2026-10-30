#!/usr/bin/env python3
"""Агент-сборщик «Харденинг» для Linux-хостов.

Собирает факты о конфигурации хоста (SSH, firewall, обновления, парольная
политика, ядро, Docker) и список установленного ПО, затем отправляет их
на бэкенд POST /api/ingest, где движок сравнения (app/services/hardening_engine.py)
сверяет факты с hardening_rules и пересчитывает compliance_score.

Зависимости: только стандартная библиотека Python 3 — скрипт не требует
pip install и запускается на целевом хосте как есть.

Пример запуска:
    python3 collector.py \\
        --api-url https://hardening.example.com \\
        --api-key <ключ, выданный create_agent_key.py> \\
        --environment prod

Ключ агента передаётся через --api-key либо переменную окружения
HARDENING_AGENT_API_KEY (предпочтительно — не остаётся в истории shell).
"""
import argparse
import base64
import datetime
import hashlib
import hmac
import http.client
import json
import os
import random
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


def read_file(path: str) -> "str | None":
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return None


def run(cmd: "list[str]", timeout: int = 15) -> "str | None":
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=timeout)
        if result.returncode != 0:
            return None
        return result.stdout
    except (OSError, subprocess.SubprocessError):
        return None


def read_stripped(path: str) -> "str | None":
    text = read_file(path)
    if text is None:
        return None
    text = text.strip()
    return text or None


def list_dir(path: str) -> "list[str]":
    try:
        return sorted(os.listdir(path))
    except OSError:
        return []


# --- sshd_config -------------------------------------------------------

SSHD_DEFAULTS = {
    "permitrootlogin": "no",  # дефолт современных sshd (>= 7.0); старые сборки — "yes"
    "passwordauthentication": "yes",
    "permitemptypasswords": "no",
    "x11forwarding": "no",
    "maxauthtries": "6",
}


def parse_sshd_config(text: str) -> dict:
    values = dict(SSHD_DEFAULTS)
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or " " not in line:
            continue
        key, _, value = line.partition(" ")
        key = key.strip().lower()
        value = value.strip()
        if key in values and value:
            values[key] = value
    return {
        "permit_root_login": values["permitrootlogin"].lower(),
        "password_authentication": values["passwordauthentication"].lower(),
        "permit_empty_passwords": values["permitemptypasswords"].lower(),
        "x11_forwarding": values["x11forwarding"].lower(),
        "max_auth_tries": values["maxauthtries"],
    }


def collect_ssh_facts() -> dict:
    sshd_config = read_file("/etc/ssh/sshd_config")
    if sshd_config is None:
        return {}
    return parse_sshd_config(sshd_config)


# --- firewall (ufw) ------------------------------------------------------

def collect_firewall_facts() -> dict:
    facts = {}

    ufw_conf = read_file("/etc/ufw/ufw.conf")
    if ufw_conf is not None:
        m = re.search(r"^\s*ENABLED\s*=\s*(\w+)", ufw_conf, re.MULTILINE)
        if m:
            facts["ufw_enabled"] = "true" if m.group(1).lower() == "yes" else "false"

    status_output = run(["ufw", "status", "verbose"])
    if status_output:
        if re.search(r"Status:\s*active", status_output, re.IGNORECASE):
            facts["ufw_enabled"] = "true"
        elif re.search(r"Status:\s*inactive", status_output, re.IGNORECASE):
            facts["ufw_enabled"] = "false"
        m = re.search(r"Default:\s*(deny|allow|reject)\s*\(incoming\)", status_output, re.IGNORECASE)
        if m:
            facts["default_incoming_policy"] = m.group(1).lower()

    if "default_incoming_policy" not in facts:
        ufw_defaults = read_file("/etc/default/ufw")
        if ufw_defaults is not None:
            m = re.search(r'^\s*DEFAULT_INPUT_POLICY\s*=\s*"?(\w+)"?', ufw_defaults, re.MULTILINE)
            if m:
                facts["default_incoming_policy"] = m.group(1).lower()

    return facts


# --- unattended-upgrades ---------------------------------------------------

def collect_updates_facts() -> dict:
    conf = read_file("/etc/apt/apt.conf.d/20auto-upgrades")
    if conf is None:
        return {}
    m = re.search(r'Unattended-Upgrade\s+"(\d)"', conf)
    if not m:
        return {}
    return {"unattended_upgrades_enabled": "true" if m.group(1) == "1" else "false"}


# --- password policy -------------------------------------------------------

def collect_password_policy_facts() -> dict:
    facts = {}

    login_defs = read_file("/etc/login.defs")
    if login_defs is not None:
        m = re.search(r"^\s*PASS_MAX_DAYS\s+(\d+)", login_defs, re.MULTILINE)
        if m:
            facts["pass_max_days"] = m.group(1)

    pwquality = read_file("/etc/security/pwquality.conf")
    if pwquality is not None:
        m = re.search(r"^\s*minlen\s*=\s*(\d+)", pwquality, re.MULTILINE)
        if m:
            facts["pass_min_len"] = m.group(1)

    faillock = read_file("/etc/security/faillock.conf")
    common_auth = read_file("/etc/pam.d/common-auth")
    has_faillock = bool(faillock) or bool(common_auth and "pam_faillock" in common_auth)
    has_tally2 = bool(common_auth and "pam_tally2" in common_auth)
    if common_auth is not None:
        facts["lockout_on_failure"] = "true" if (has_faillock or has_tally2) else "false"

    return facts


# --- kernel ------------------------------------------------------------

def collect_kernel_facts() -> dict:
    value = read_file("/proc/sys/net/ipv4/ip_forward")
    if value is None:
        return {}
    return {"ip_forward": value.strip()}


# --- docker --------------------------------------------------------------

def collect_docker_facts() -> dict:
    ids_output = run(["docker", "ps", "-q"])
    if ids_output is None:
        return {}
    ids = [line for line in ids_output.splitlines() if line.strip()]
    if not ids:
        return {"no_privileged_containers": "true"}

    inspect_output = run(["docker", "inspect", "--format", "{{.HostConfig.Privileged}}", *ids])
    if inspect_output is None:
        return {}
    any_privileged = any(line.strip().lower() == "true" for line in inspect_output.splitlines())
    return {"no_privileged_containers": "false" if any_privileged else "true"}


# --- asset / software ------------------------------------------------------

WINDOWS_CURRENT_VERSION = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
WINDOWS_UNINSTALL_KEYS = (
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",  # 32-битные программы на 64-битной ОС
)


def get_windows_version() -> "str | None":
    """«Windows Server 2022 Datacenter (21H2, сборка 20348)». У Windows 11 в реестре ProductName по-прежнему
    «Windows 10» — поэтому по номеру сборки (22000+) название исправляется."""
    import probes

    name = probes.read_registry(WINDOWS_CURRENT_VERSION, "ProductName")
    build = probes.read_registry(WINDOWS_CURRENT_VERSION, "CurrentBuildNumber") or probes.read_registry(WINDOWS_CURRENT_VERSION, "CurrentBuild")
    release = probes.read_registry(WINDOWS_CURRENT_VERSION, "DisplayVersion") or probes.read_registry(WINDOWS_CURRENT_VERSION, "ReleaseId")
    if not name:
        return None
    if str(name).startswith("Windows 10") and build and str(build).isdigit() and int(build) >= 22000:
        name = "Windows 11" + str(name)[len("Windows 10"):]
    details = ", ".join(x for x in (release and str(release), build and f"сборка {build}") if x)
    return f"{name} ({details})" if details else str(name)


def collect_windows_software() -> "list[dict]":
    """Установленные программы из разделов Uninstall реестра (как «Программы и компоненты»)."""
    import winreg

    items, seen = [], set()
    for path in WINDOWS_UNINSTALL_KEYS:
        try:
            root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        except OSError:
            continue
        with root:
            for index in range(winreg.QueryInfoKey(root)[0]):
                try:
                    with winreg.OpenKey(root, winreg.EnumKey(root, index)) as entry:
                        def value(name, entry=entry):
                            try:
                                return str(winreg.QueryValueEx(entry, name)[0]).strip() or None
                            except OSError:
                                return None
                        name = value("DisplayName")
                        if not name or value("SystemComponent") == "1":
                            continue
                        key = (name, value("DisplayVersion"))
                        if key in seen:
                            continue
                        seen.add(key)
                        items.append({"name": name, "version": key[1], "vendor": value("Publisher"),
                                      "category": "application", "type": "package"})
                except OSError:
                    continue
    return items


def get_os_pretty_name() -> "str | None":
    if os.name == "nt":
        return get_windows_version()
    os_release = read_file("/etc/os-release")
    if not os_release:
        return None
    m = re.search(r'^PRETTY_NAME="?([^"\n]+)"?', os_release, re.MULTILINE)
    return m.group(1) if m else None


def get_primary_ip() -> "str | None":
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("10.255.255.255", 1))
            return s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        return None


def collect_software() -> "list[dict]":
    """dpkg (Debian/Ubuntu) в приоритете, rpm — фолбэк для RHEL-семейства, на Windows — реестр."""
    if os.name == "nt":
        return collect_windows_software()
    dpkg_output = run(["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Source}\n"])
    if dpkg_output is not None:
        items = []
        for line in dpkg_output.splitlines():
            parts = line.split("\t")
            if len(parts) < 2 or not parts[0]:
                continue
            name, version = parts[0], parts[1]
            items.append({"name": name, "version": version or None, "vendor": None, "category": "os-package", "type": "package"})
        return items

    rpm_output = run(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"])
    if rpm_output is not None:
        items = []
        for line in rpm_output.splitlines():
            parts = line.split("\t")
            if len(parts) < 2 or not parts[0]:
                continue
            items.append({"name": parts[0], "version": parts[1] or None, "vendor": None, "category": "os-package", "type": "package"})
        return items

    return []


# --- инвентаризация оборудования -------------------------------------------
#
# Паспорт «железа» хоста для инвентаризации активов. Только stdlib и чтение sysfs/procfs (без прав
# root) на Linux; на Windows — один вызов PowerShell (CIM). Железо не влияет на оценку compliance —
# это справочные данные актива. Имя пользователя/домен/группы (ПДн) собираются только при
# --collect-identity, по умолчанию выключено.

_VIRTUAL_DISK_PREFIXES = ("loop", "ram", "dm-", "sr", "fd", "zram", "md")
_VIRTUAL_NET_PREFIXES = ("lo", "docker", "veth", "br-", "virbr", "vnet", "tap", "tun", "wg", "kube")
_ZERO_MAC = "00:00:00:00:00:00"


def primary_interface() -> "str | None":
    """Сетевой интерфейс, через который хост ходит наружу (по таблице маршрутизации)."""
    out = run(["ip", "-o", "route", "get", "1.1.1.1"])
    if out:
        m = re.search(r"\bdev\s+(\S+)", out)
        if m:
            return m.group(1)
    return None


def collect_mac_address() -> "str | None":
    """MAC интерфейса с дефолтным маршрутом; иначе первый физический не-loopback интерфейс."""
    preferred = primary_interface()
    if preferred:
        mac = read_stripped(f"/sys/class/net/{preferred}/address")
        if mac and mac != _ZERO_MAC:
            return mac
    for name in list_dir("/sys/class/net"):
        if name.startswith(_VIRTUAL_NET_PREFIXES):
            continue
        mac = read_stripped(f"/sys/class/net/{name}/address")
        if mac and mac != _ZERO_MAC:
            return mac
    return None


def collect_device_uuid() -> "str | None":
    """Стабильный идентификатор устройства: machine-id (без прав) → DMI product_uuid (нужен root)."""
    for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        value = read_stripped(path)
        if value:
            return value
    return read_stripped("/sys/class/dmi/id/product_uuid")


def collect_cpu() -> "tuple[str | None, int | None]":
    text = read_file("/proc/cpuinfo")
    if not text:
        return None, None
    model = None
    cores = 0
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if not sep:
            continue
        key = key.strip().lower()
        if key == "model name" and model is None:
            model = value.strip()
        elif key == "processor":
            cores += 1
    return model, cores or None


def collect_memory_mb() -> "int | None":
    text = read_file("/proc/meminfo")
    if not text:
        return None
    m = re.search(r"^MemTotal:\s+(\d+)\s*kB", text, re.MULTILINE)
    return int(m.group(1)) // 1024 if m else None


def collect_motherboard() -> "tuple[str | None, str | None]":
    return read_stripped("/sys/class/dmi/id/board_vendor"), read_stripped("/sys/class/dmi/id/board_name")


def collect_disks() -> "list[dict]":
    disks = []
    for name in list_dir("/sys/block"):
        if name.startswith(_VIRTUAL_DISK_PREFIXES):
            continue
        size = read_stripped(f"/sys/block/{name}/size")  # число секторов по 512 байт
        if size is None:
            continue
        try:
            size_gb = round(int(size) * 512 / 1_000_000_000, 1)
        except ValueError:
            continue
        rotational = read_stripped(f"/sys/block/{name}/queue/rotational")
        if name.startswith("nvme"):
            kind = "nvme"
        elif rotational == "0":
            kind = "ssd"
        elif rotational == "1":
            kind = "hdd"
        else:
            kind = "unknown"
        disks.append({
            "name": name,
            "model": read_stripped(f"/sys/block/{name}/device/model"),
            "size_gb": size_gb,
            "type": kind,
        })
    return disks


# Кто работает за ПК (иначе — кто входил последним) и его группы; от SYSTEM группы доменной учётки даёт
# S4U-вход по неявному UPN (имя@домен). Вывод — Base64(UTF-8): кириллица не зависит от кодовой страницы консоли.
WIN_IDENTITY_PS = (
    "$ErrorActionPreference='SilentlyContinue';$cs=Get-CimInstance Win32_ComputerSystem;$u=$cs.UserName;"
    "if(-not $u){$u=(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\LogonUI').LastLoggedOnSAMUser};"
    "$d=$null;$g=@();if($cs.PartOfDomain){$d=$cs.Domain;"
    "if($u -and $u.Split('\\')[0] -notin @('.',$env:COMPUTERNAME)){try{"
    "$id=New-Object Security.Principal.WindowsIdentity(($u.Split('\\')[-1])+'@'+$d);"
    "$g=@($id.Groups|ForEach-Object{try{$_.Translate([Security.Principal.NTAccount]).Value}catch{}})}catch{}}};"
    "$j=[pscustomobject]@{username=$u;domain=$d;domain_groups=$g}|ConvertTo-Json -Compress;"
    "[Console]::Out.Write([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($j)))"
)
SYSTEM_USERS = {"root", "reboot", "shutdown", "wtmp"}


def collect_windows_identity() -> dict:
    encoded = base64.b64encode(WIN_IDENTITY_PS.encode("utf-16-le")).decode("ascii")
    out = run(["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded], timeout=60)
    try:
        data = json.loads(base64.b64decode(out or "").decode("utf-8"))
    except ValueError:
        return {"username": None, "domain": None, "domain_groups": None}
    groups = data.get("domain_groups") or []
    if isinstance(groups, str):  # ConvertTo-Json отдаёт одиночный элемент не списком
        groups = [groups]
    # «Все», NT AUTHORITY\… есть у любого входа — оставляем группы домена и BUILTIN (локальный админ)
    groups = [g for g in groups if "\\" in g and not g.upper().startswith("NT AUTHORITY\\")]
    return {"username": data.get("username"), "domain": data.get("domain"), "domain_groups": groups or None}


def linux_interactive_user() -> "str | None":
    """Первый вошедший пользователь (who), иначе последний входивший (last); root и служебные записи — мимо."""
    for cmd in (["who"], ["last", "-w", "-n", "50"]):
        for line in (run(cmd) or "").splitlines():
            name = line.split()[0] if line.split() else ""
            if name and name not in SYSTEM_USERS:
                return name
    return None


def collect_identity() -> dict:
    """Учётные данные (ПДн) сотрудника за компьютером. Агент работает как служба (root/SYSTEM) — его
    собственная учётная запись не нужна, поэтому берётся интерактивный или последний вошедший пользователь."""
    if os.name == "nt":
        return collect_windows_identity()
    username = linux_interactive_user()
    groups = []
    if username:
        gz = run(["id", "-Gnz", username])  # NUL-разделитель: в именах групп AD бывают пробелы
        groups = [g for g in gz.split("\0") if g] if gz else (run(["id", "-Gn", username]) or "").split()
    domain = None
    krb = read_file("/etc/krb5.conf")
    if krb:
        m = re.search(r"^\s*default_realm\s*=\s*(\S+)", krb, re.MULTILINE)
        if m:
            domain = m.group(1)
    return {"username": username, "domain": domain, "domain_groups": groups or None}


WIN_HW_PS = (
    "$ErrorActionPreference='SilentlyContinue';"
    "$cs=Get-CimInstance Win32_ComputerSystem;"
    "$bb=Get-CimInstance Win32_BaseBoard;"
    "$cpu=Get-CimInstance Win32_Processor|Select-Object -First 1;"
    "$uuid=(Get-CimInstance Win32_ComputerSystemProduct).UUID;"
    "$mac=(Get-CimInstance Win32_NetworkAdapter -Filter 'NetEnabled=true'|Select-Object -First 1).MACAddress;"
    "$disks=@(Get-CimInstance -Namespace root/Microsoft/Windows/Storage MSFT_PhysicalDisk|ForEach-Object{[pscustomobject]@{"
    "name=$_.FriendlyName;model=$_.Model;size_gb=[math]::Round($_.Size/1e9,1);media_type=$_.MediaType;bus_type=$_.BusType}});"
    "[pscustomobject]@{mac_address=$mac;device_uuid=$uuid;cpu_model=$cpu.Name;"
    "cpu_cores=$cpu.NumberOfLogicalProcessors;memory_mb=[math]::Round($cs.TotalPhysicalMemory/1MB);"
    "board_vendor=$bb.Manufacturer;board_product=$bb.Product;disks=$disks}|ConvertTo-Json -Depth 4 -Compress"
)


# MSFT_PhysicalDisk: MediaType 3 — HDD, 4 — SSD; BusType 17 — NVMe
WIN_MEDIA_TYPES = {3: "hdd", 4: "ssd"}
WIN_BUS_NVME = 17


def win_disk_type(disk: dict) -> str:
    if disk.get("bus_type") == WIN_BUS_NVME:
        return "nvme"
    return WIN_MEDIA_TYPES.get(disk.get("media_type"), "unknown")


def is_blank_uuid(value: "str | None") -> bool:
    """Нулевой или FFFF… UUID — прошивка его не задала (ВМ, дешёвые платы): это не идентификатор устройства."""
    digits = (value or "").replace("-", "").upper()
    return not digits or set(digits) <= {"0"} or set(digits) <= {"F"}


def collect_windows_hardware() -> dict:
    # Пять запросов CIM занимают ~10 с на прогретой машине, при загрузке ПК (первый прогон из GPO) — дольше
    out = run(["powershell", "-NoProfile", "-NonInteractive", "-Command", WIN_HW_PS], timeout=120)
    if not out:
        return {}
    try:
        data = json.loads(out)
    except ValueError:
        return {}
    disks = data.get("disks") or []
    if isinstance(disks, dict):  # ConvertTo-Json отдаёт одиночный объект не списком
        disks = [disks]
    data["disks"] = [
        {"name": d.get("name"), "model": d.get("model"), "size_gb": d.get("size_gb"), "type": win_disk_type(d)}
        for d in disks if isinstance(d, dict)
    ]
    if is_blank_uuid(data.get("device_uuid")):
        data["device_uuid"] = None
    return data


def collect_hardware(collect_identity_pii: bool = False) -> "dict | None":
    """Полный паспорт актива. None — ничего собрать не удалось (не затираем прежнюю инвентаризацию)."""
    if os.name == "nt":
        inventory = collect_windows_hardware()
    else:
        cpu_model, cpu_cores = collect_cpu()
        board_vendor, board_product = collect_motherboard()
        inventory = {
            "mac_address": collect_mac_address(),
            "device_uuid": collect_device_uuid(),
            "cpu_model": cpu_model,
            "cpu_cores": cpu_cores,
            "memory_mb": collect_memory_mb(),
            "board_vendor": board_vendor,
            "board_product": board_product,
            "disks": collect_disks(),
        }
    if collect_identity_pii:
        inventory.update(collect_identity())
    # Пустой словарь или только пустые значения — инвентаризацию не прислали.
    if not any(v for v in inventory.values()):
        return None
    return inventory


def collect_facts() -> dict:
    facts = {}
    ssh = collect_ssh_facts()
    if ssh:
        facts["ssh"] = ssh
    firewall = collect_firewall_facts()
    if firewall:
        facts["firewall"] = firewall
    updates = collect_updates_facts()
    if updates:
        facts["updates"] = updates
    password_policy = collect_password_policy_facts()
    if password_policy:
        facts["password_policy"] = password_policy
    kernel = collect_kernel_facts()
    if kernel:
        facts["kernel"] = kernel
    docker_facts = collect_docker_facts()
    if docker_facts:
        facts["docker"] = docker_facts
    return facts


def build_payload(args: argparse.Namespace) -> dict:
    return {
        "environment": args.environment,
        "asset": {
            "hostname": args.hostname or socket.gethostname(),
            "ip_address": args.ip_address or get_primary_ip(),
            "os": get_os_pretty_name(),
            "asset_type": args.asset_type,
            "criticality": args.criticality,
        },
        "inventory": collect_hardware(collect_identity_pii=args.collect_identity),
        "software": collect_software(),
        "facts": collect_facts(),
        "scan_label": args.scan_label,
    }


# --- связь с сервером ------------------------------------------------------------
#
# Агент сам обращается к серверу (забрать паки, отправить результат), к агенту никто не подключается:
# от объекта заказчика нужен только исходящий HTTPS на 443 к одному адресу. Защита канала:
# - только HTTPS; http:// — лишь на localhost (агент на самом сервере) или явно --allow-http (VPN, стенд);
# - проверка сертификата (системные корневые или --ca-file) и TLS не ниже 1.2;
# - --pin-sha256: закрепление открытого ключа сервера (как curl --pinnedpubkey) — защита от подмены
#   сервера своим корневым сертификатом в сети заказчика (TLS-инспекция, MITM);
# - --proxy: корпоративный прокси (служба под SYSTEM / systemd не видит прокси пользователя).

LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


class TransientError(Exception):
    """Сервер недоступен или временно не принял данные — прогон стоит отложить в очередь.
    code — HTTP-код (None — нет связи), retry_after — пауза, которую просит сервер (Retry-After), в секундах."""

    def __init__(self, message: str, code: "int | None" = None, retry_after: "float | None" = None):
        super().__init__(message)
        self.code, self.retry_after = code, retry_after


# Повторы при перегрузке сервера: паузы (с), к каждой — случайная добавка до 50 % — всего до ~10 мин (худший
# случай нагрузочного теста — 1000 хостов разом за одним NAT — очередь сервера рассасывается за ~9 мин); потом — очередь.
RETRY_CODES = (429, 502, 503, 504)
RETRY_DELAYS = (15, 45, 120, 240)


def _retry_after(headers) -> "float | None":
    try:
        return min(float(headers.get("Retry-After")), 300.0)
    except (TypeError, ValueError, AttributeError):
        return None


class RejectedError(Exception):
    """Сервер отказал по существу (ключ, формат) — повтор не поможет."""

    def __init__(self, code: int, detail: str):
        super().__init__(f"HTTP {code} — {detail}")
        self.code, self.detail = code, detail


def check_api_url(api_url: str, allow_http: bool) -> None:
    parsed = urllib.parse.urlsplit(api_url)
    if parsed.scheme == "https":
        return
    if parsed.scheme == "http" and (allow_http or (parsed.hostname or "").lower() in LOOPBACK_HOSTS):
        return
    raise SystemExit(
        f"Ошибка: {api_url} — нужен https:// (ключ агента и результаты нельзя передавать открытым текстом). "
        "http:// допустим только для localhost или с --allow-http внутри VPN/стенда"
    )


def _der_element(data: bytes, pos: int) -> "tuple[int, int, int]":
    """(тег, начало содержимого, конец элемента) DER-элемента с позиции pos."""
    tag, length = data[pos], data[pos + 1]
    pos += 2
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(data[pos:pos + count], "big")
        pos += count
    return tag, pos, pos + length


def spki_pin(cert_der: bytes) -> str:
    """Base64(SHA-256(SubjectPublicKeyInfo)) сертификата — тот же отпечаток, что у curl --pinnedpubkey и HPKP.
    Закрепляется ключ, а не сертификат: при продлении Let's Encrypt с тем же ключом (--reuse-key) пин не меняется."""
    _, pos, _ = _der_element(cert_der, 0)       # Certificate
    _, pos, _ = _der_element(cert_der, pos)     # tbsCertificate
    tag, _, end = _der_element(cert_der, pos)
    if tag == 0xA0:                             # [0] version
        pos = end
    for _ in range(5):                          # serialNumber, signature, issuer, validity, subject
        _, _, pos = _der_element(cert_der, pos)
    _, _, end = _der_element(cert_der, pos)     # subjectPublicKeyInfo
    return base64.b64encode(hashlib.sha256(cert_der[pos:end]).digest()).decode("ascii")


def normalize_pin(pin: str) -> str:
    pin = pin.strip()
    return pin[len("sha256//"):] if pin.startswith("sha256//") else pin


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    pins: "tuple[str, ...]" = ()
    seen: "list[str]" = []

    def connect(self):
        super().connect()
        pin = spki_pin(self.sock.getpeercert(binary_form=True))
        self.seen.append(pin)
        if self.pins and pin not in self.pins:
            self.close()
            # OSError → urllib.error.URLError: тот же путь, что у любой ошибки соединения
            raise ssl.SSLError(f"открытый ключ сервера не совпал с закреплённым (получен sha256//{pin})")


class _HTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, context: ssl.SSLContext, pins: "tuple[str, ...]", seen: "list[str]"):
        super().__init__(context=context)
        self.pins, self.seen = pins, seen

    def https_open(self, req):
        pins, seen = self.pins, self.seen

        def connection(host, **kwargs):
            conn = _PinnedHTTPSConnection(host, **kwargs)
            conn.pins, conn.seen = pins, seen
            return conn

        return self.do_open(connection, req, context=self._context)


class ServerConnection:
    """Соединение агента с сервером: URL, ключ агента, TLS-контекст, закреплённые ключи, прокси."""

    def __init__(self, api_url: str, api_key: "str | None", ca_file: "str | None" = None, pins=(), proxy: "str | None" = None,
                 allow_http: bool = False, timeout: int = 30):
        check_api_url(api_url, allow_http)
        self.api_url, self.api_key, self.timeout = api_url.rstrip("/"), api_key, timeout
        context = ssl.create_default_context(cafile=ca_file)
        if hasattr(ssl, "TLSVersion"):
            context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.seen_pins: "list[str]" = []
        handlers = [_HTTPSHandler(context, tuple(normalize_pin(p) for p in pins), self.seen_pins)]
        # Без --proxy — прокси из окружения (HTTPS_PROXY), как у любой программы; с --proxy — только он.
        handlers.append(urllib.request.ProxyHandler({"https": proxy, "http": proxy} if proxy else None))
        self.opener = urllib.request.build_opener(*handlers)

    def request(self, method: str, path: str, payload: "dict | None" = None) -> dict:
        """Запрос к серверу. Перегрузка (429, 502–504: лимит запросов, перезапуск сервера) — несколько
        повторов с паузой и случайным разбросом: тысяча хостов, получивших отказ одновременно, не должна
        повторить запрос одновременно. Не помогло — TransientError, прогон уходит в очередь."""
        for attempt, delay in enumerate((*RETRY_DELAYS, None)):
            try:
                return self._request_once(method, path, payload)
            except TransientError as exc:
                if delay is None or exc.code not in RETRY_CODES:
                    raise
                pause = max(exc.retry_after or 0, delay) * random.uniform(1.0, 1.5)
                print(f"сервер занят (HTTP {exc.code}) — повтор через {pause:.0f} с ({attempt + 1}/{len(RETRY_DELAYS)})",
                      file=sys.stderr)
                time.sleep(pause)

    def _request_once(self, method: str, path: str, payload: "dict | None" = None) -> dict:
        headers = {"X-Agent-Api-Key": self.api_key or ""}
        data = None
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.api_url + path, data=data, method=method, headers=headers)
        try:
            with self.opener.open(req, timeout=self.timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:2000]
            try:  # FastAPI: {"detail": "причина"} — человеку нужна причина, а не JSON
                parsed = json.loads(detail).get("detail")
                if parsed:
                    detail = parsed if isinstance(parsed, str) else json.dumps(parsed, ensure_ascii=False)
            except (ValueError, AttributeError):
                pass
            detail = detail[:500]
            # 408/429/5xx — сервер перегружен или перезапускается; прочее (401 ключ, 422 формат) — отказ по существу
            if exc.code in (408, 429) or exc.code >= 500:
                raise TransientError(f"HTTP {exc.code} — {detail}", exc.code, _retry_after(exc.headers)) from None
            raise RejectedError(exc.code, detail) from None
        except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
            reason = getattr(exc, "reason", exc)
            if isinstance(reason, ssl.SSLError) and "закреплённым" in str(reason):
                # Подмена сервера — событие безопасности, а не «сервер недоступен»: в очередь не откладывается.
                raise SystemExit(f"Ошибка безопасности: {reason.args[0] if reason.args else reason}") from None
            # Python 3.7+: SSLCertVerificationError; 3.6 (RHEL 8): SSLError с reason CERTIFICATE_VERIFY_FAILED
            # или CertificateError (имя в сертификате не совпало) — проверяется по признаку, а не по классу.
            if isinstance(reason, ssl.CertificateError) or (
                    isinstance(reason, ssl.SSLError) and getattr(reason, "reason", None) == "CERTIFICATE_VERIFY_FAILED"):
                raise SystemExit(f"Ошибка безопасности: сертификат сервера не прошёл проверку ({reason}); "
                                 "для корпоративного корневого сертификата — --ca-file") from None
            raise TransientError(f"нет связи с {self.api_url}: {reason}") from None


def send_ingest(conn: ServerConnection, payload: dict) -> dict:
    return conn.request("POST", "/api/ingest", payload)


# --- очередь неотправленных прогонов ----------------------------------------------
#
# Сервер недоступен (нет интернета, перезапуск, отключили свет) — прогон не теряется: он сохраняется в
# каталог очереди и досылается при следующем запуске, раньше нового прогона (порядок снимков сохраняется).
# Повторная отправка безопасна: у прогона run_id, сервер второй снимок не создаёт (HTTP 409 = уже принят).
# Время снимка — collected_at, когда агент собрал данные, а не когда прогон дошёл.

SPOOL_MAX_FILES = 50
SPOOL_MAX_AGE_DAYS = 30


def default_state_dir() -> str:
    """Каталог состояния агента: ключ хоста и очередь прогонов."""
    if os.name == "nt":
        return os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "HardeningAgent")
    # systemd: StateDirectory=hardening-agent/<экземпляр> (agent/deploy/hardening-agent@.service)
    return os.environ.get("STATE_DIRECTORY", "/var/lib/hardening-agent").split(":")[0]


def default_spool_dir() -> str:
    return os.path.join(default_state_dir(), "spool")


def spool_save(spool_dir: str, payload: dict) -> str:
    make_private_dir(spool_dir)
    name = f"{payload['collected_at'].replace(':', '').replace('-', '')[:15]}-{payload['run_id']}.json"
    path = os.path.join(spool_dir, name)
    # 0600: в прогоне конфигурация хоста — читать её должен только агент
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False)
    spool_trim(spool_dir)
    return path


def spool_files(spool_dir: str) -> "list[str]":
    if not os.path.isdir(spool_dir):
        return []
    return sorted(os.path.join(spool_dir, f) for f in os.listdir(spool_dir) if f.endswith(".json"))


def spool_trim(spool_dir: str) -> None:
    """Очередь ограничена: старше SPOOL_MAX_AGE_DAYS — удаляются (сервер их уже не примет), сверх
    SPOOL_MAX_FILES — удаляются самые старые."""
    files = spool_files(spool_dir)
    cutoff = time.time() - SPOOL_MAX_AGE_DAYS * 86400
    for path in files:
        if os.path.getmtime(path) < cutoff:
            os.remove(path)
    files = spool_files(spool_dir)
    for path in files[:max(0, len(files) - SPOOL_MAX_FILES)]:
        os.remove(path)


def spool_flush(conn: ServerConnection, spool_dir: str, log) -> int:
    """Досылает очередь по порядку. Сервер снова недоступен — TransientError, остаток ждёт следующего
    запуска. Отказ по существу (кроме ключа) — файл переименовывается в .rejected и больше не шлётся."""
    if os.path.isdir(spool_dir):
        spool_trim(spool_dir)
    sent = 0
    for path in spool_files(spool_dir):
        with open(path, encoding="utf-8") as fh:
            payload = json.load(fh)
        try:
            send_ingest(conn, payload)
        except RejectedError as exc:
            if exc.code == 409:  # уже принят раньше — ответ тогда потерялся
                os.remove(path)
                continue
            if exc.code in (401, 403):
                raise  # ключ отозван или просрочен: очередь сохраняется до нового ключа
            os.replace(path, path[:-5] + ".rejected")
            log(f"прогон {os.path.basename(path)} отклонён сервером ({exc}) — оставлен как .rejected")
            continue
        os.remove(path)
        sent += 1
    return sent


# --- регистрация хоста --------------------------------------------------------------
#
# Ключ площадки (из интерфейса «Агенты») ставится на все хосты сразу — GPO, Ansible, образ ОС. При первом
# запуске агент обменивает его на собственный ключ хоста (POST /api/agent/enroll) и дальше работает с ним:
# сервер принимает по ключу хоста отчёт только с именем этого хоста, поэтому ключ, вынутый с одного хоста,
# не позволит подделать отчёты остальных, а отозвать можно один хост. Ключ хоста — в файле host.json
# каталога состояния, читать его могут только SYSTEM и администраторы (Windows) или сам агент (Linux, 0600).
# Для хоста с несколькими экземплярами агента (сетевые устройства по SSH) у каждого экземпляра свой
# каталог состояния и своя регистрация — на имя устройства.

HOST_FILE = "host.json"
# Windows: SYSTEM и «Администраторы» — по SID, а не по имени (на русской Windows группа называется иначе)
WINDOWS_PRIVATE_ACL = ["/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"]


def make_private_dir(path: str) -> None:
    """Каталог, который читают только агент и администраторы: в нём ключ хоста и собранная конфигурация."""
    os.makedirs(path, mode=0o700, exist_ok=True)
    if os.name == "nt":
        # ProgramData наследует чтение для «Пользователей» — наследование снимается
        result = subprocess.run(["icacls", path, *WINDOWS_PRIVATE_ACL], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                universal_newlines=True)
        if result.returncode != 0:
            raise OSError(f"не удалось ограничить доступ к {path}: {result.stdout.strip()}")


def load_host_key(state_dir: str) -> "str | None":
    try:
        with open(os.path.join(state_dir, HOST_FILE), encoding="utf-8") as fh:
            return json.load(fh).get("key") or None
    except (OSError, ValueError):
        return None


def save_host_registration(state_dir: str, registration: dict) -> str:
    make_private_dir(state_dir)
    path = os.path.join(state_dir, HOST_FILE)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(registration, fh, ensure_ascii=False)
    os.replace(tmp, path)
    return path


def forget_host_registration(state_dir: str) -> None:
    try:
        os.remove(os.path.join(state_dir, HOST_FILE))
    except FileNotFoundError:
        pass


class EnrollmentConflict(Exception):
    """Сервер отказал в регистрации по существу (имя занято, регистрация отозвана) — повтор не поможет."""


def enroll_host(conn: ServerConnection, site_key: str, state_dir: str, hostname: str, os_name: "str | None", log) -> bool:
    """Регистрирует хост ключом площадки и переключает соединение на ключ хоста. False — сервер без
    регистрации хостов (старая версия): агент работает с ключом площадки, как раньше."""
    # Каталог проверяется до регистрации: ключ, выданный сервером и не сохранённый, занял бы имя хоста.
    make_private_dir(state_dir)
    if not os.access(state_dir, os.W_OK):
        raise OSError(f"нет прав на запись в {state_dir}")
    conn.api_key = site_key
    try:
        response = conn.request("POST", "/api/agent/enroll", {"hostname": hostname, "os": os_name})
    except RejectedError as exc:
        if exc.code in (404, 405):
            log("сервер не поддерживает регистрацию хостов — отчёт отправляется ключом площадки")
            return False
        if exc.code == 409:
            raise EnrollmentConflict(exc.detail) from None
        raise
    path = save_host_registration(state_dir, {
        "host_id": response["host_id"], "hostname": response["hostname"], "key": response["key"],
        "server": conn.api_url, "enrolled_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
    })
    conn.api_key = response["key"]
    log(f"хост {response['hostname']} зарегистрирован на сервере, ключ хоста сохранён в {path}")
    return True


# --- подписанный отчёт для переноса файлом (изолированный сегмент) --------------
#
# Подпись — HMAC-SHA256 ключом SHA-256(ключ агента): сервер хранит именно этот хэш (сам ключ — нет) и
# проверяет подпись, а тот, кто переносит файл, ключа не знает и результаты подменить не может.

def report_signing_key(api_key: str) -> bytes:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest().encode("ascii")


def canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign_report(payload: dict, api_key: str) -> dict:
    signature = hmac.new(report_signing_key(api_key), canonical(payload), hashlib.sha256).hexdigest()
    return {"format": "hardening-agent-report", "version": 1, "payload": payload, "signature": signature}


# --- режим паков (--use-packs) ---------------------------------------------------
#
# Агент получает с сервера подписанные манифесты паков, проверяет подпись, определяет
# по условиям detect, какой пак подходит платформе, выполняет только его пробы (только
# чтение) и отправляет результаты в POST /api/ingest как probe_results. Сравнение с
# нормой делает сервер. Движок проб — рядом, в probes.py (при обычном запуске не нужен).

def fetch_manifests(conn: ServerConnection, transport_name: str) -> dict:
    try:
        return conn.request("GET", f"/api/agent/manifests?transport={transport_name}")
    except RejectedError as exc:
        if exc.code == 401:
            raise  # ключ хоста отвергнут — main решает, регистрироваться ли заново
        raise SystemExit(f"Бэкенд не выдал манифесты: {exc}") from None
    except TransientError as exc:
        # Без паков прогон собрать нечем; отправленное раньше осталось в очереди до следующего запуска.
        raise SystemExit(f"Не удалось получить манифесты: {exc}") from None


def build_pack_payload(args: argparse.Namespace, probes_module, conn: "ServerConnection | None" = None) -> dict:
    """Payload ingest по результатам проб пака. Завершает работу (SystemExit) с понятной причиной,
    если манифест не прошёл проверку подписи или платформа не распознана однозначно."""
    if not args.pack_key and not args.pack_public_key:
        raise SystemExit("Ошибка: для --use-packs нужен открытый ключ подписи паков --pack-public-key "
                         "(HARDENING_PACK_PUBLIC_KEY) или старый общий ключ --pack-key (HARDENING_PACK_KEY)")

    if args.offline_dir and args.ssh_host:
        raise SystemExit("Ошибка: --offline-dir и --ssh-host взаимоисключающие — либо выгрузка, либо живое устройство")
    if args.offline_dir:
        if not args.hostname:
            raise SystemExit("Ошибка: для --offline-dir нужен --hostname (имя устройства, чья это выгрузка)")
        try:
            transport = probes_module.OfflineConfigTransport(args.offline_dir)
        except ValueError as exc:
            raise SystemExit(f"Ошибка: {exc}")
    elif args.ssh_host:
        transport = probes_module.SshTransport(args.ssh_host, args.ssh_user, args.ssh_port, args.ssh_key)
    else:
        transport = probes_module.LocalTransport()

    if args.manifests_file:
        with open(args.manifests_file, encoding="utf-8") as fh:
            response = json.load(fh)
    else:
        if conn is None or not conn.api_key:  # ключ хоста (host.json) или ключ площадки
            raise SystemExit("Ошибка: нужен --api-key или переменная окружения HARDENING_AGENT_API_KEY")
        response = fetch_manifests(conn, probes_module.pack_transport(transport))

    try:
        public_key = probes_module.decode_public_key(args.pack_public_key) if args.pack_public_key else None
        manifests = probes_module.load_verified_manifests(response, args.pack_key, public_key)
    except probes_module.ManifestError as exc:
        raise SystemExit(f"Ошибка безопасности: {exc}")

    if args.pack:
        manifests = [m for m in manifests if m["pack"] == args.pack]
    matched = probes_module.select_manifests(transport, manifests, declared=args.pack if args.offline_dir else None)
    if not matched:
        if args.offline_dir and not args.pack:
            raise SystemExit("Платформа по выгрузке не распознана (нет выгрузки команды detect, например show_version.txt) — "
                             "укажите пак явно: --pack <id>")
        raise SystemExit("Платформа не распознана ни одним паком — данные не отправлены (агент не гадает)")

    def log(entry: dict) -> None:
        print(json.dumps(entry, ensure_ascii=False), file=sys.stderr)

    # Хосту может подходить несколько паков сразу (ОС + Docker + СУБД): выполняются все подошедшие
    # и уходят одним запросом — один прогон, один снимок, общая оценка.
    runs, tags, asset_type = [], [], None
    for manifest in matched:
        runs.append({
            "id": manifest["pack"], "version": manifest["version"],
            "probe_results": probes_module.run_manifest(transport, manifest, log=log),
        })
        tags.extend(tag for tag in manifest["tags"] if tag not in tags)
        asset_type = asset_type or manifest.get("asset_type")
    local = transport.name == "local"
    # Сетевое устройство: модель и версия прошивки из паков (поле firmware) — ПО актива для сопоставления с БДУ.
    firmware = []
    for manifest in [] if local else matched:
        entry = probes_module.collect_firmware(transport, manifest)
        if entry and entry not in firmware:
            firmware.append(entry)
    payload = {
        "environment": args.environment,
        "asset": {
            "hostname": args.hostname or args.ssh_host or socket.gethostname(),
            "ip_address": args.ip_address or (get_primary_ip() if local else None),
            "os": get_os_pretty_name() if local else None,
            "asset_type": asset_type or args.asset_type,
            "criticality": args.criticality,
        },
        "software": collect_software() if local else firmware,
        "inventory": collect_hardware(collect_identity_pii=args.collect_identity) if local else None,
        "platform_tags": tags,
        "packs": runs,
        "scan_label": args.scan_label,
    }
    if hasattr(transport, "describe"):
        # Источник данных — в снимок: проверка по выгрузке не равна проверке живого устройства.
        payload["collection"] = transport.describe()
        payload["collection"]["declared_pack"] = any(not probes_module.matches_detect(transport, m["detect"]) for m in matched)
    return payload


def parse_args(argv: "list[str]") -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--api-url", required=True, help="Базовый URL бэкенда, например https://hardening.example.com")
    parser.add_argument("--api-key", default=os.environ.get("HARDENING_AGENT_API_KEY"),
                        help="Ключ площадки из интерфейса «Агенты» (или HARDENING_AGENT_API_KEY): при первом запуске агент "
                             "регистрирует по нему хост и дальше работает с ключом хоста, после регистрации он не нужен")
    parser.add_argument("--enroll", action="store_true",
                        help="Только зарегистрировать хост (установка через GPO, Ansible, образ ОС) и выйти")
    parser.add_argument("--state-dir", default=os.environ.get("HARDENING_STATE_DIR") or default_state_dir(),
                        help="Каталог состояния: ключ хоста (host.json) — доступ только у агента и администраторов")
    parser.add_argument("--environment", required=True, help="Имя окружения (prod/staging/…), создаётся автоматически при первом прогоне")
    parser.add_argument("--hostname", default=None, help="По умолчанию — hostname хоста")
    parser.add_argument("--ip-address", default=None, help="По умолчанию — определяется автоматически")
    parser.add_argument("--asset-type", default="server", help="Тип актива (по умолчанию: server)")
    parser.add_argument("--criticality", default="medium", choices=["low", "medium", "high", "critical"])
    parser.add_argument("--scan-label", default=None, help="Метка прогона для отчёта")
    parser.add_argument("--collect-identity", action="store_true",
                        help="Собирать учётные данные (имя пользователя, домен, группы) — это ПДн; по умолчанию выключено")
    parser.add_argument("--dry-run", action="store_true", help="Собрать факты и вывести payload, не отправляя на бэкенд")
    parser.add_argument("--out", default=None,
                        help="Изолированный сегмент: сохранить прогон в файл, подписанный ключом агента, вместо отправки "
                             "(файл загружается на сервер через интерфейс)")
    net = parser.add_argument_group("связь с сервером")
    net.add_argument("--ca-file", default=os.environ.get("HARDENING_CA_FILE"),
                     help="Корневой сертификат (PEM) для проверки сервера вместо системных (или HARDENING_CA_FILE)")
    net.add_argument("--pin-sha256", action="append", default=[p for p in os.environ.get("HARDENING_PIN_SHA256", "").split(",") if p],
                     help="Закреплённый открытый ключ сервера sha256//<base64> (можно несколько: текущий и резервный; "
                          "или HARDENING_PIN_SHA256 через запятую)")
    net.add_argument("--proxy", default=os.environ.get("HARDENING_PROXY"), help="Прокси, например http://proxy.corp:3128 (или HARDENING_PROXY)")
    net.add_argument("--allow-http", action="store_true", help="Разрешить http:// не на localhost (только внутри VPN или стенда)")
    net.add_argument("--spool-dir", default=os.environ.get("HARDENING_SPOOL_DIR") or default_spool_dir(),
                     help="Каталог очереди: неотправленные прогоны досылаются при следующем запуске")
    net.add_argument("--no-spool", action="store_true", help="Не откладывать прогон в очередь, если сервер недоступен")
    net.add_argument("--show-server-pin", action="store_true", help="Показать отпечаток ключа сервера для --pin-sha256 и выйти")
    packs = parser.add_argument_group("режим паков", "Подписанные манифесты с сервера; нужен probes.py рядом со скриптом")
    packs.add_argument("--use-packs", action="store_true", help="Собирать по манифестам паков вместо встроенных проверок")
    packs.add_argument("--pack-public-key", default=os.environ.get("HARDENING_PACK_PUBLIC_KEY"),
                       help="Открытый ключ Ed25519 сервера для проверки подписи паков (или HARDENING_PACK_PUBLIC_KEY)")
    packs.add_argument("--pack-key", default=os.environ.get("HARDENING_PACK_KEY"),
                       help="Старый общий ключ HMAC для проверки подписи (или HARDENING_PACK_KEY); при --pack-public-key не используется")
    packs.add_argument("--pack", default=None, help="Выполнить только указанный пак (id) из подошедших платформе")
    packs.add_argument("--manifests-file", default=None, help="Взять манифесты из файла (JSON ответа /api/agent/manifests) вместо сервера")
    packs.add_argument("--ssh-host", default=None, help="Внешний сбор с сетевого устройства по SSH (вместо локального хоста)")
    packs.add_argument("--ssh-user", default=None, help="Пользователь SSH (учётка только на чтение)")
    packs.add_argument("--ssh-port", type=int, default=22)
    packs.add_argument("--ssh-key", default=None, help="Путь к приватному ключу SSH (сам ключ в пак не попадает)")
    packs.add_argument("--offline-dir", default=None,
                       help="Проверка по выгрузке конфигурации вместо живого устройства: каталог с выводом команд "
                            "(show_running-config.txt, show_version.txt …); нужен --hostname, без show_version — и --pack")
    return parser.parse_args(argv)


def _utf8_console() -> None:
    """Вывод в UTF-8 на Windows: консоль и перенаправление там по умолчанию в cp1252/cp866, и кириллица в
    отчёте и журнале роняла собранный .exe (UnicodeEncodeError; PYTHONUTF8 на него не действует)."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def main(argv: "list[str] | None" = None) -> int:
    if os.name == "nt":
        _utf8_console()
    args = parse_args(argv if argv is not None else sys.argv[1:])

    def log(message: str) -> None:
        print(message, file=sys.stderr)

    offline = args.dry_run or args.manifests_file and args.out
    conn = None
    if args.show_server_pin or not offline or (args.use_packs and not args.manifests_file):
        conn = ServerConnection(args.api_url, args.api_key, args.ca_file, args.pin_sha256, args.proxy, args.allow_http)
    if args.show_server_pin:
        try:
            conn.request("GET", "/health")
        except (TransientError, RejectedError) as exc:
            if not conn.seen_pins:
                print(f"Ошибка: {exc}", file=sys.stderr)
                return 1
        if not conn.seen_pins:
            print("Ошибка: соединение не по HTTPS — отпечатка нет", file=sys.stderr)
            return 1
        print(f"sha256//{conn.seen_pins[-1]}")
        return 0

    host_key = None if args.dry_run else load_host_key(args.state_dir)
    if host_key and conn is not None:
        conn.api_key = host_key
    if not args.dry_run and not args.api_key and not host_key:
        print("Ошибка: нужен ключ площадки --api-key или переменная окружения HARDENING_AGENT_API_KEY "
              f"(хост ещё не зарегистрирован: нет {os.path.join(args.state_dir, HOST_FILE)})", file=sys.stderr)
        return 1

    if args.enroll:
        if host_key:
            print(f"Хост уже зарегистрирован: {os.path.join(args.state_dir, HOST_FILE)}")
            return 0
        hostname = args.hostname or args.ssh_host or socket.gethostname()  # то же имя, что в отчёте
        try:
            enroll_host(conn, args.api_key, args.state_dir, hostname, get_os_pretty_name(), log)
        except (EnrollmentConflict, RejectedError, TransientError, OSError) as exc:
            print(f"Хост {hostname} не зарегистрирован: {exc}", file=sys.stderr)
            return 75 if isinstance(exc, TransientError) else 1
        return 0

    if os.name == "nt" and not args.use_packs:
        # Встроенные проверки старого режима написаны для Linux; на Windows — только паки.
        print("Ошибка: на Windows агент работает только с паками — добавьте --use-packs", file=sys.stderr)
        return 1

    probes_module = None
    if args.use_packs:
        try:
            import probes as probes_module
        except ImportError:
            print("Ошибка: для --use-packs нужен файл probes.py рядом с collector.py", file=sys.stderr)
            return 1

    def collect() -> dict:
        return build_pack_payload(args, probes_module, conn) if args.use_packs else build_payload(args)

    def reenroll(hostname: str, os_name: "str | None") -> None:
        # Регистрацию хоста удалили на сервере (переустановка, освобождение имени) — регистрируемся заново.
        # Отозванный администратором хост сервер заново не зарегистрирует (409).
        log("ключ хоста больше не действует — повторная регистрация")
        forget_host_registration(args.state_dir)
        enroll_host(conn, args.api_key, args.state_dir, hostname, os_name, log)

    try:
        try:
            payload = collect()
        except RejectedError:  # 401 на манифесты: ключ хоста отозван или регистрация удалена
            if not (host_key and args.api_key):
                raise
            reenroll(args.hostname or args.ssh_host or socket.gethostname(), get_os_pretty_name())
            host_key = conn.api_key
            payload = collect()
    except EnrollmentConflict as exc:
        print(f"Хост не зарегистрирован: {exc}", file=sys.stderr)
        return 1
    except (RejectedError, OSError) as exc:
        hint = " — ключ хоста отозван или регистрация удалена; для повторной регистрации нужен ключ площадки (--api-key)"
        print(f"Бэкенд не выдал манифесты: {exc}{hint if host_key and not args.api_key else ''}", file=sys.stderr)
        return 1
    payload["run_id"] = str(uuid.uuid4())
    payload["collected_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")

    if args.dry_run:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 0
    if args.out:
        fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            # изолированный сегмент: хост мог и не регистрироваться — тогда подпись ключом площадки
            json.dump(sign_report(payload, host_key or args.api_key), fh, ensure_ascii=False)
        print(f"Отчёт сохранён в {args.out}: загрузите его на сервер в интерфейсе («Отчёт агента из файла»)")
        return 0

    def deliver() -> dict:
        sent = spool_flush(conn, args.spool_dir, log) if not args.no_spool else 0
        if sent:
            log(f"дослано из очереди: {sent}")
        try:
            return send_ingest(conn, payload)
        except RejectedError as exc:
            if exc.code != 409:
                raise
            # Сервер принял прогон, но ответ не дошёл (504 под нагрузкой), а повтор получил «уже принят»
            log(f"прогон {payload['run_id']} уже принят сервером")
            return {"run_id": payload["run_id"], "status": "already-accepted"}

    asset = payload.get("asset") or {}
    try:
        if not host_key:
            enroll_host(conn, args.api_key, args.state_dir, asset.get("hostname") or socket.gethostname(), asset.get("os"), log)
        try:
            result = deliver()
        except RejectedError as exc:
            if not (exc.code == 401 and host_key and args.api_key):
                raise
            reenroll(asset.get("hostname") or socket.gethostname(), asset.get("os"))
            result = deliver()
    except EnrollmentConflict as exc:
        print(f"Хост не зарегистрирован: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Ключ хоста не сохранён в {args.state_dir}: {exc}", file=sys.stderr)
        return 1
    except RejectedError as exc:
        hint = ""
        if exc.code == 401 and host_key and not args.api_key:
            hint = (" — ключ хоста отозван или регистрация удалена; для повторной регистрации нужен ключ площадки"
                    " (--api-key)")
        print(f"Бэкенд отклонил данные: {exc}{hint}", file=sys.stderr)
        return 1
    except TransientError as exc:
        if args.no_spool:
            print(f"Данные не отправлены: {exc}", file=sys.stderr)
            return 1
        try:
            path = spool_save(args.spool_dir, payload)
        except OSError as err:
            print(f"Данные не отправлены ({exc}) и не сохранены в очередь {args.spool_dir}: {err}", file=sys.stderr)
            return 1
        print(f"Сервер недоступен ({exc}): прогон сохранён в очередь {path}, будет дослан при следующем запуске", file=sys.stderr)
        return 75  # EX_TEMPFAIL
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
