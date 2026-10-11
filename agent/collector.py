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
    """Сервер недоступен или временно не принял данные — прогон стоит отложить в очередь."""


class RejectedError(Exception):
    """Сервер отказал по существу (ключ, формат) — повтор не поможет."""

    def __init__(self, code: int, detail: str):
        super().__init__(f"HTTP {code} — {detail}")
        self.code = code


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
            detail = exc.read().decode("utf-8", errors="replace")[:500]
            # 408/429/5xx — сервер перегружен или перезапускается; прочее (401 ключ, 422 формат) — отказ по существу
            if exc.code in (408, 429) or exc.code >= 500:
                raise TransientError(f"HTTP {exc.code} — {detail}") from None
            raise RejectedError(exc.code, detail) from None
        except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
            reason = getattr(exc, "reason", exc)
            if isinstance(reason, ssl.SSLError) and "закреплённым" in str(reason):
                # Подмена сервера — событие безопасности, а не «сервер недоступен»: в очередь не откладывается.
                raise SystemExit(f"Ошибка безопасности: {reason.args[0] if reason.args else reason}") from None
            if isinstance(reason, getattr(ssl, "SSLCertVerificationError", ssl.CertificateError)):
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


def default_spool_dir() -> str:
    if os.name == "nt":
        return os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "HardeningAgent", "spool")
    # systemd: StateDirectory=hardening-agent (agent/deploy/hardening-agent@.service)
    return os.path.join(os.environ.get("STATE_DIRECTORY", "/var/lib/hardening-agent").split(":")[0], "spool")


def spool_save(spool_dir: str, payload: dict) -> str:
    os.makedirs(spool_dir, mode=0o700, exist_ok=True)
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
        if not args.api_key or conn is None:
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
    payload = {
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
    if hasattr(transport, "describe"):
        # Источник данных — в снимок: проверка по выгрузке не равна проверке живого устройства.
        payload["collection"] = transport.describe()
        payload["collection"]["declared_pack"] = any(not probes_module.matches_detect(transport, m["detect"]) for m in matched)
    return payload


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
        payload = build_pack_payload(args, probes, conn)
    else:
        payload = build_payload(args)
    payload["run_id"] = str(uuid.uuid4())
    payload["collected_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")

    if args.dry_run:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 0
    if args.out:
        fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(sign_report(payload, args.api_key), fh, ensure_ascii=False)
        print(f"Отчёт сохранён в {args.out}: загрузите его на сервер в интерфейсе («Отчёт агента из файла»)")
        return 0

    try:
        sent = spool_flush(conn, args.spool_dir, log) if not args.no_spool else 0
        if sent:
            log(f"дослано из очереди: {sent}")
        result = send_ingest(conn, payload)
    except RejectedError as exc:
        print(f"Бэкенд отклонил данные: {exc}", file=sys.stderr)
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
