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
import json
import os
import re
import socket
import subprocess
import sys
import urllib.error
import urllib.request


def read_file(path: str) -> "str | None":
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return None


def run(cmd: "list[str]") -> "str | None":
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=15)
        if result.returncode != 0:
            return None
        return result.stdout
    except (OSError, subprocess.SubprocessError):
        return None


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
        "software": collect_software(),
        "facts": collect_facts(),
        "scan_label": args.scan_label,
    }


def send_ingest(api_url: str, api_key: str, payload: dict, timeout: int = 30) -> dict:
    url = api_url.rstrip("/") + "/api/ingest"
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Agent-Api-Key": api_key,
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise SystemExit(f"Бэкенд отклонил данные: HTTP {exc.code} — {detail}")
    except urllib.error.URLError as exc:
        raise SystemExit(f"Не удалось связаться с бэкендом ({url}): {exc.reason}")


# --- режим паков (--use-packs) ---------------------------------------------------
#
# Агент получает с сервера подписанные манифесты паков, проверяет подпись, определяет
# по условиям detect, какой пак подходит платформе, выполняет только его пробы (только
# чтение) и отправляет результаты в POST /api/ingest как probe_results. Сравнение с
# нормой делает сервер. Движок проб — рядом, в probes.py (при обычном запуске не нужен).

def fetch_manifests(api_url: str, api_key: str, transport_name: str, timeout: int = 30) -> dict:
    url = f"{api_url.rstrip('/')}/api/agent/manifests?transport={transport_name}"
    request = urllib.request.Request(url, headers={"X-Agent-Api-Key": api_key})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise SystemExit(f"Бэкенд не выдал манифесты: HTTP {exc.code} — {detail}")
    except urllib.error.URLError as exc:
        raise SystemExit(f"Не удалось связаться с бэкендом ({url}): {exc.reason}")


def build_pack_payload(args: argparse.Namespace, probes_module) -> dict:
    """Payload ingest по результатам проб пака. Завершает работу (SystemExit) с понятной причиной,
    если манифест не прошёл проверку подписи или платформа не распознана однозначно."""
    if not args.pack_key:
        raise SystemExit("Ошибка: для --use-packs нужен --pack-key или переменная окружения HARDENING_PACK_KEY")

    if args.ssh_host:
        transport = probes_module.SshTransport(args.ssh_host, args.ssh_user, args.ssh_port, args.ssh_key)
    else:
        transport = probes_module.LocalTransport()

    if args.manifests_file:
        with open(args.manifests_file, encoding="utf-8") as fh:
            response = json.load(fh)
    else:
        if not args.api_key:
            raise SystemExit("Ошибка: нужен --api-key или переменная окружения HARDENING_AGENT_API_KEY")
        response = fetch_manifests(args.api_url, args.api_key, transport.name)

    try:
        manifests = probes_module.load_verified_manifests(response, args.pack_key)
    except probes_module.ManifestError as exc:
        raise SystemExit(f"Ошибка безопасности: {exc}")

    if args.pack:
        manifests = [m for m in manifests if m["pack"] == args.pack]
    matched = probes_module.select_manifests(transport, manifests)
    if not matched:
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
    return {
        "environment": args.environment,
        "asset": {
            "hostname": args.hostname or args.ssh_host or socket.gethostname(),
            "ip_address": args.ip_address or (get_primary_ip() if local else None),
            "os": get_os_pretty_name() if local else None,
            "asset_type": asset_type or args.asset_type,
            "criticality": args.criticality,
        },
        "software": collect_software() if local else [],
        "platform_tags": tags,
        "packs": runs,
        "scan_label": args.scan_label,
    }


def parse_args(argv: "list[str]") -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--api-url", required=True, help="Базовый URL бэкенда, например https://hardening.example.com")
    parser.add_argument("--api-key", default=os.environ.get("HARDENING_AGENT_API_KEY"), help="Ключ агента (или переменная окружения HARDENING_AGENT_API_KEY)")
    parser.add_argument("--environment", required=True, help="Имя окружения (prod/staging/…), создаётся автоматически при первом прогоне")
    parser.add_argument("--hostname", default=None, help="По умолчанию — hostname хоста")
    parser.add_argument("--ip-address", default=None, help="По умолчанию — определяется автоматически")
    parser.add_argument("--asset-type", default="server", help="Тип актива (по умолчанию: server)")
    parser.add_argument("--criticality", default="medium", choices=["low", "medium", "high", "critical"])
    parser.add_argument("--scan-label", default=None, help="Метка прогона для отчёта")
    parser.add_argument("--dry-run", action="store_true", help="Собрать факты и вывести payload, не отправляя на бэкенд")
    packs = parser.add_argument_group("режим паков", "Подписанные манифесты с сервера; нужен probes.py рядом со скриптом")
    packs.add_argument("--use-packs", action="store_true", help="Собирать по манифестам паков вместо встроенных проверок")
    packs.add_argument("--pack-key", default=os.environ.get("HARDENING_PACK_KEY"), help="Ключ проверки подписи манифестов (или HARDENING_PACK_KEY)")
    packs.add_argument("--pack", default=None, help="Выполнить только указанный пак (id) из подошедших платформе")
    packs.add_argument("--manifests-file", default=None, help="Взять манифесты из файла (JSON ответа /api/agent/manifests) вместо сервера")
    packs.add_argument("--ssh-host", default=None, help="Внешний сбор с сетевого устройства по SSH (вместо локального хоста)")
    packs.add_argument("--ssh-user", default=None, help="Пользователь SSH (учётка только на чтение)")
    packs.add_argument("--ssh-port", type=int, default=22)
    packs.add_argument("--ssh-key", default=None, help="Путь к приватному ключу SSH (сам ключ в пак не попадает)")
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

    if not args.dry_run and not args.api_key:
        print("Ошибка: нужен --api-key или переменная окружения HARDENING_AGENT_API_KEY", file=sys.stderr)
        return 1

    if os.name == "nt" and not args.use_packs:
        # Встроенные проверки старого режима написаны для Linux; на Windows — только паки.
        print("Ошибка: на Windows агент работает только с паками — добавьте --use-packs", file=sys.stderr)
        return 1

    if args.use_packs:
        try:
            import probes
        except ImportError:
            print("Ошибка: для --use-packs нужен файл probes.py рядом с collector.py", file=sys.stderr)
            return 1
        payload = build_pack_payload(args, probes)
    else:
        payload = build_payload(args)

    if args.dry_run:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 0

    result = send_ingest(args.api_url, args.api_key, payload)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
