#!/usr/bin/env python3
"""Доступ агента к Код Безопасности «Континент 4» через HTTP API ЦУС.

Узел проверяет обычный агент с хоста в сети заказчика (не сервер). ЦУС на порту 444
принимает только TLS 1.2 с шифрами ГОСТ (Kuznyechik). Агент остаётся на стандартной
библиотеке Python и перебирает способы, пока один не установит ГОСТ-TLS:

1. ssl этого процесса, если движок ГОСТ уже загружен (OPENSSL_CONF до import ssl);
2. отдельный процесс Python с OPENSSL_CONF на gost.so — ssl импортируется уже с движком;
3. curl с тем же OPENSSL_CONF;
4. openssl s_client с тем же OPENSSL_CONF.

Пароль читается из файла 0600 и не попадает в аргументы процессов. Наружу уходит только
текст команд show continent …, без полей password*, pasword* (опечатка схемы), community,
ключей и подписей.

Живой опрос — три GET и только они (белый список в коде и в подписанном манифесте):
/api-v1-objects/config, /api-v1-objects/config/active/cgw,
/api-v1-server/config/active/export-config-for-cgw/{hwserial}?view=full.
POST, PUT, DELETE, lock, fork, commit, install-policy и set-password агент не вызывает.

Та же выгрузка JSON (c4_config_exporter или локальное меню) читается офлайн: агент
--offline-dir и загрузка через интерфейс.
"""
from __future__ import print_function

import base64
import hashlib
import json
import os
import re
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time

try:
    import probes
except ImportError:  # пакет бэкенда грузит файл по пути, каталог agent не в sys.path
    import importlib.util

    _probes_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "probes.py")
    _spec = importlib.util.spec_from_file_location("hardening_agent_probes_for_continent4", _probes_path)
    probes = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(probes)


# Совпадает с C4_READONLY_PATHS в app/services/packs/models.py.
# Сюда нельзя добавлять пути записи: пак их объявить не сможет, а агент не откроет путь
# вне этого набора, даже если подпись манифеста его содержит.
C4_READONLY_PATHS = (
    "/api-v1-objects/config",
    "/api-v1-objects/config/active/cgw",
    "/api-v1-server/config/active/export-config-for-cgw",
)
_EXPORT_PREFIX = "/api-v1-server/config/active/export-config-for-cgw/"
_SERIAL_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_TLS_ORDER = ("in-process", "python", "curl", "openssl")
_GOST_CIPHERS = "ALL:@SECLEVEL=0"
_MAX_BODY = 8 * 1024 * 1024

CMD_VERSION = "show continent version"
CMD_PASSWORD = "show continent password-policy"
CMD_ADMINS = "show continent administrators"
CMD_SSH = "show continent ssh"
CMD_SNMP = "show continent snmp"
CMD_SYSLOG = "show continent syslog"
COMMANDS = (CMD_VERSION, CMD_PASSWORD, CMD_ADMINS, CMD_SSH, CMD_SNMP, CMD_SYSLOG)

# Пробы и пороги — те же, что в паке kontinent-4 1.1.0. Живой скрипт печатает вердикт сам,
# без сервера; тест сверяет эти словари с паком, чтобы они не разъехались.
DETECT_PROBE = {
    "type": "cli_config",
    "cmd": CMD_VERSION,
    "require": "(?m)^product:",
    "match": r"^product:\s*(\S+)",
}
DETECT_EQUALS = "continent"
VERSION_PROBE = {
    "type": "cli_config",
    "cmd": CMD_VERSION,
    "require": "(?m)^update_version:",
    "match": r"^update_version:\s*(\S+)",
}
CHECKS = (
    {
        "id": "kontinent4.password_min_length",
        "probe": {
            "type": "cli_config",
            "cmd": CMD_PASSWORD,
            "require": "(?m)^min_length:",
            "match": r"^min_length:\s*(\d+)",
        },
        "op": "gte",
        "value": 8,
    },
    {
        "id": "kontinent4.lockout_enabled",
        "probe": {
            "type": "cli_config",
            "cmd": CMD_PASSWORD,
            "require": "(?m)^lockout:",
            "match": r"^lockout:\s*(\S+)",
        },
        "op": "eq",
        "value": "on",
    },
    {
        "id": "kontinent4.personal_admin_accounts",
        "probe": {
            "type": "cli_blocks",
            "cmd": CMD_ADMINS,
            "block": r"^login:",
            "has": [r"^enabled:\s*yes", r"^autocreated:\s*no", r"^primary:\s*no", r"^role:\s*\S"],
            "require": "(?m)^login:",
        },
        "op": "gte",
        "value": 1,
    },
    {
        "id": "kontinent4.ssh_access_restricted",
        "probe": {
            "type": "cli_config",
            "cmd": CMD_SSH,
            "require": "(?m)^state:",
            "match": r"^state:\s*(.+)$",
        },
        "op": "in",
        "value": ["выключен", "включён, адреса ограничены"],
    },
    {
        "id": "kontinent4.snmp_secure",
        "probe": {
            "type": "cli_config",
            "cmd": CMD_SNMP,
            "require": "(?m)^state:",
            "match": r"^state:\s*(.+)$",
        },
        "op": "in",
        "value": ["SNMP выключен", "SNMP v3: аутентификация SHA и шифрование AES"],
    },
    {
        "id": "kontinent4.remote_syslog",
        "probe": {
            "type": "cli_config",
            "cmd": CMD_SYSLOG,
            "require": "(?m)^remote:",
            "match": r"^remote:\s*(\S+)",
        },
        "op": "eq",
        "value": "yes",
    },
)

_SECRET_EXACT = {
    "password", "_old_passwords", "sign", "dbdata", "pubkey", "_auth_pass", "community_name",
    "auth_login", "_password", "_first_server_key", "_second_server_key", "keytab", "keys",
    "password_expired_date", "psk", "secret", "private_key", "key", "confirm_password",
}
_MASK_TEXT = re.compile(
    r'("(?:password[a-z_0-9]*|pasword[a-z_0-9]*|_old_passwords|sign|pubkey|dbdata|_auth_pass|'
    r'community_name|_password|keytab|confirm_password)"\s*:\s*)("(?:[^"\\]|\\.)*"|\[[^\]]*\])',
    re.IGNORECASE,
)
_ENGINE_GLOBS = (
    "/usr/lib/*/engines-3/gost.so",
    "/usr/lib/*/engines-1.1/gost.so",
    "/usr/lib64/engines-3/gost.so",
    "/usr/lib/engines-3/gost.so",
    "/usr/lib/ssl/engines/gost.so",
    "/usr/lib64/openssl/engines/gost.so",
    "/usr/lib/x86_64-linux-gnu/engines-3/gost.so",
    "/usr/lib/aarch64-linux-gnu/engines-3/gost.so",
)
_ANY_ADDRESS = {"0.0.0.0", "0.0.0.0/0", "::/0", "any", "*", "все"}
_V3 = {"v3", "3", "snmpv3"}
_SHA = {"SHA", "SHA1", "SHA-1", "SHA256", "SHA-256", "SHA384", "SHA512"}
_SNMP_OFF = "SNMP выключен"
_SNMP_GOOD = "SNMP v3: аутентификация SHA и шифрование AES"
_SNMP_WEAK = "SNMP v3 без шифрования или с DES/MD5"
_SNMP_V2 = "SNMP v2 (сообщество)"
_SSH_OFF = "выключен"
_SSH_LIMITED = "включён, адреса ограничены"
_SSH_OPEN = "включён без ограничения адресов"
_GOST_HINT = (
    "Порт 444 ЦУС принимает только ГОСТ TLS 1.2 (GOST2012-KUZNYECHIK-KUZNYECHIKOMAC). "
    "На хосте агента нужен OpenSSL 3 и пакет libengine-gost-openssl "
    "(файл gost.so, обычно /usr/lib/<архитектура>/engines-3/gost.so). "
    "Либо задайте openssl_conf или gost_engine в файле цели. "
    "Без движка ГОСТ ни один способ подключения не заработает."
)


class Continent4Error(probes.ProbeError):
    """ЦУС не отдал конфигурацию. Для проб это тот же отказ, что ProbeError."""


class TlsUnavailable(Continent4Error):
    """Этот способ не смог установить ГОСТ-TLS. Следующий способ ещё можно пробовать."""


def is_secret_key(name):
    """password* и pasword* (опечатка схемы 4.2.1), плюс ключи из sanitize.py лаборатории."""
    if not isinstance(name, str):
        return False
    low = name.lower()
    if low.startswith("pasword") or low == "password" or low.startswith("password_"):
        return True
    return low in _SECRET_EXACT


def sanitize(value):
    """Копия JSON без секретов. Пустые поля не трогаем: их и так нечего скрывать."""
    if isinstance(value, dict):
        clean = {}
        for key, item in value.items():
            if is_secret_key(key) and item not in (None, "", [], {}):
                if isinstance(item, list):
                    clean[key] = []
                elif isinstance(item, dict):
                    clean[key] = {}
                else:
                    clean[key] = "REDACTED"
            else:
                clean[key] = sanitize(item)
        return clean
    if isinstance(value, list):
        return [sanitize(item) for item in value]
    return value


def scrub_text(text, secrets=()):
    out = _MASK_TEXT.sub(r'\1"<masked>"', text or "")
    for secret in secrets:
        if secret and len(str(secret)) >= 4:
            out = out.replace(str(secret), "***")
    return out


def one_line(value):
    return " ".join(str(value or "").replace("\r", " ").replace("\n", " ").split())


def _int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def parse_tls_list(text):
    """Пустая строка — все четыре способа. Иначе список через запятую из _TLS_ORDER."""
    if text is None or str(text).strip() == "":
        return list(_TLS_ORDER)
    items = [part.strip() for part in str(text).split(",") if part.strip()]
    if not items or any(item not in _TLS_ORDER for item in items):
        raise ValueError("--tls: список из in-process, python, curl, openssl через запятую")
    return items


def parse_pin(value):
    """SHA-256 сертификата ЦУС: hex, sha256:<hex> или sha256//<base64 дайджеста>."""
    if value is None or value == "":
        return ""
    text = str(value).strip()
    if text.startswith("sha256//"):
        try:
            raw = base64.b64decode(text[len("sha256//"):])
        except (TypeError, ValueError):
            raise ValueError("pin_sha256: sha256// и base64 SHA-256")
        if len(raw) != 32:
            raise ValueError("pin_sha256: в sha256// ожидается 32 байта")
        return raw.hex()
    if text.lower().startswith("sha256:"):
        text = text.split(":", 1)[1]
    text = text.replace(":", "").replace(" ", "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", text):
        raise ValueError("pin_sha256: SHA-256 сертификата в hex или sha256//base64")
    return text


def cert_sha256(der):
    if not der:
        return ""
    return hashlib.sha256(der).hexdigest()


def find_gost_engine(explicit=None):
    if explicit:
        if os.path.isfile(explicit) and not os.path.islink(explicit):
            return explicit
        raise ValueError("gost_engine: нет файла {0}".format(explicit))
    import glob

    seen = []
    for pattern in _ENGINE_GLOBS:
        seen.extend(glob.glob(pattern))
    for path in seen:
        if os.path.isfile(path) and not os.path.islink(path):
            return path
    return None


def conf_mentions_gost(path):
    """Файл похож на конфиг движка ГОСТ, а не на чужой OPENSSL_CONF."""
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            text = handle.read().lower()
    except OSError:
        return False
    if "gost.so" in text:
        return True
    return re.search(r"engine_id\s*=\s*gost\b", text) is not None


def openssl_conf_text(engine_path):
    return (
        "openssl_conf = openssl_init\n"
        "\n"
        "[openssl_init]\n"
        "engines = engine_section\n"
        "\n"
        "[engine_section]\n"
        "gost = gost_section\n"
        "\n"
        "[gost_section]\n"
        "engine_id = gost\n"
        "dynamic_path = {0}\n"
        "default_algorithms = ALL\n"
    ).format(engine_path)


def classify_document(data):
    """export — выгрузка УБ, cgw — список узлов с update_version, config — список конфигураций,
    bundle — {export, cgw} в одном файле. None — это не ответ ЦУС."""
    if isinstance(data, dict) and ("export" in data or "cgw" in data) and (
        isinstance(data.get("export"), (dict, list)) or isinstance(data.get("cgw"), (dict, list))
    ):
        return "bundle"
    if _is_export(data):
        return "export"
    if _is_cgw_list(data):
        return "cgw"
    if isinstance(data, dict) and isinstance(data.get("data"), list):
        items = [item for item in data["data"] if isinstance(item, dict)]
        if items and all(item.get("type") == "config" for item in items):
            return "config"
    return None


def _is_export(data):
    if not isinstance(data, dict) or not isinstance(data.get("objects"), list):
        return False
    types = {item.get("type") for item in data["objects"] if isinstance(item, dict)}
    markers = {"passwordpolicy", "sshaccesscomponent", "snmpcomponent", "admin", "cgw"}
    return bool(types & markers) and (data.get("type") == "full" or "hwserial" in data)


def _is_cgw_list(data):
    if isinstance(data, dict) and isinstance(data.get("data"), list):
        items = data["data"]
    elif isinstance(data, list):
        items = data
    else:
        return False
    return any(isinstance(item, dict) and item.get("hwserial") and item.get("update_version") for item in items)


def load_json_bytes(raw):
    if raw is None:
        return None
    if isinstance(raw, (dict, list)):
        return raw
    try:
        text = raw.decode("utf-8-sig") if isinstance(raw, (bytes, bytearray)) else raw
        return json.loads(text)
    except (UnicodeError, ValueError, TypeError):
        return None


def cgw_nodes(document):
    data = document
    if isinstance(document, dict) and isinstance(document.get("data"), list):
        data = document["data"]
    if not isinstance(data, list):
        raise Continent4Error("ответ /cgw не список узлов")
    nodes = []
    for item in data:
        if isinstance(item, dict) and item.get("hwserial"):
            nodes.append(item)
    if not nodes:
        raise Continent4Error("в ответе /cgw нет узлов с hwserial")
    return nodes


def select_node(nodes, hwserial):
    wanted = str(hwserial).strip() if hwserial else ""
    if wanted:
        matched = [node for node in nodes if str(node.get("hwserial")) == wanted]
        if len(matched) != 1:
            known = ", ".join("{0} ({1})".format(one_line(node.get("name")), node.get("hwserial")) for node in nodes)
            raise Continent4Error("узел hwserial {0} не найден среди: {1}".format(wanted, known))
        return matched[0]
    if len(nodes) == 1:
        return nodes[0]
    known = ", ".join("{0} ({1})".format(one_line(node.get("name")), node.get("hwserial")) for node in nodes)
    raise Continent4Error("на ЦУС несколько узлов ({0}); укажите hwserial в файле цели".format(known))


def _objects(export):
    objects = export.get("objects") if isinstance(export, dict) else None
    if not isinstance(objects, list):
        raise Continent4Error("в выгрузке УБ нет списка objects")
    live = []
    for item in objects:
        if isinstance(item, dict) and not item.get("is_deleted"):
            live.append(item)
    return live


def _by_type(objects):
    found = {}
    for item in objects:
        found.setdefault(item.get("type"), []).append(item)
    return found


def _platform_name(node):
    platform = node.get("platform") if isinstance(node, dict) else None
    if isinstance(platform, dict):
        return one_line(platform.get("platform") or platform.get("version"))
    return one_line(platform)


def render_version(node, export):
    export_nodes = _by_type(_objects(export)).get("cgw") or []
    export_node = export_nodes[0] if export_nodes else {}
    hwserial = node.get("hwserial") or export.get("hwserial") or export_node.get("hwserial") or ""
    lines = [
        "product: continent",
        "hwserial: {0}".format(one_line(hwserial)),
        "name: {0}".format(one_line(node.get("name") or export_node.get("name"))),
    ]
    version = one_line(node.get("update_version"))
    if version:
        lines.append("update_version: {0}".format(version))
    lines.append("mode: {0}".format(one_line(node.get("mode") or export_node.get("mode"))))
    platform = _platform_name(node) or _platform_name(export_node)
    if platform:
        lines.append("platform: {0}".format(platform))
    return "\n".join(lines) + "\n"


def _policies(by_type):
    return [item for item in by_type.get("passwordpolicy") or [] if isinstance(item, dict)]


def render_password(by_type):
    policies = _policies(by_type)
    if not policies:
        return "object: passwordpolicy\nmissing: yes\n"
    lengths = [_int(item.get("min_length")) for item in policies]
    counts = [_int(item.get("wrong_try_count")) for item in policies]
    blocks = [_int(item.get("wrong_try_block")) for item in policies]
    days = [_int(item.get("blocked_days")) for item in policies]
    # Несколько политик: берём самую слабую длину и считаем блокировку включённой,
    # только если она включена в каждой (иначе одна мягкая политика прячется за строгой).
    lockout = all(count >= 1 and (block > 0 or day > 0) for count, block, day in zip(counts, blocks, days))
    lines = [
        "object: passwordpolicy",
        "min_length: {0}".format(min(lengths) if lengths else 0),
        "wrong_try_count: {0}".format(min(counts) if counts else 0),
        "wrong_try_block: {0}".format(min(blocks) if blocks else 0),
        "blocked_days: {0}".format(min(days) if days else 0),
        "lockout: {0}".format("on" if lockout else "off"),
    ]
    return "\n".join(lines) + "\n"


def _roles_for(objects):
    by_uuid = {item.get("uuid"): item for item in objects if item.get("uuid")}
    roles = {}
    for item in objects:
        if item.get("type") != "link" or item.get("linkname") != "adminrole":
            continue
        role = by_uuid.get(item.get("right_uuid")) or {}
        name = one_line(role.get("name"))
        if name:
            roles.setdefault(item.get("left_uuid"), []).append(name)
    return roles


def render_admins(objects):
    roles = _roles_for(objects)
    admins = [item for item in objects if item.get("type") == "admin"]
    admins.sort(key=lambda item: (not item.get("primary"), one_line(item.get("login"))))
    if not admins:
        return "missing: yes\n"
    blocks = []
    for item in admins:
        role = ", ".join(roles.get(item.get("uuid")) or [])
        blocks.append("\n".join([
            "login: {0}".format(one_line(item.get("login"))),
            "  enabled: {0}".format("yes" if item.get("is_enabled") else "no"),
            "  primary: {0}".format("yes" if item.get("primary") else "no"),
            "  autocreated: {0}".format("yes" if item.get("is_autocreated") else "no"),
            "  role: {0}".format(role),
        ]))
    return "\n\n".join(blocks) + "\n"


def _address_any(netobj):
    if not isinstance(netobj, dict):
        return True
    for field in ("ip", "name", "subnet"):
        if one_line(netobj.get(field)).lower() in _ANY_ADDRESS:
            return True
    return False


def _linked_netobjects(component, objects):
    by_uuid = {item.get("uuid"): item for item in objects if item.get("uuid")}
    found = []
    for item in objects:
        if item.get("type") != "link" or item.get("left_uuid") != component.get("uuid"):
            continue
        right = by_uuid.get(item.get("right_uuid"))
        right_type = str(item.get("right_type") or "")
        if right_type.endswith("netobject") or (isinstance(right, dict) and right.get("type") == "netobject"):
            if isinstance(right, dict):
                found.append(right)
    return found


def _ssh_state(components, objects):
    enabled = [item for item in components if item.get("is_enabled")]
    if not enabled:
        return _SSH_OFF, 0
    limited = True
    total = 0
    for item in enabled:
        addresses = _linked_netobjects(item, objects)
        total += len(addresses)
        if not addresses or any(_address_any(addr) for addr in addresses):
            limited = False
    if limited:
        return _SSH_LIMITED, total
    return _SSH_OPEN, total


def render_ssh(objects):
    components = [item for item in objects if item.get("type") == "sshaccesscomponent"]
    if not components:
        return "missing: yes\n"
    state, total = _ssh_state(components, objects)
    enabled = any(item.get("is_enabled") for item in components)
    return "\n".join([
        "is_enabled: {0}".format("yes" if enabled else "no"),
        "permitted_addresses: {0}".format(total),
        "state: {0}".format(state),
    ]) + "\n"


def _snmp_one(item):
    if not item.get("is_enabled"):
        return _SNMP_OFF
    protocol = str(item.get("protocol") or "").strip().lower()
    auth = str(item.get("auth_type") or "").strip().upper()
    enc = str(item.get("enc_type") or "").strip().upper()
    if protocol in _V3 and auth in _SHA and enc.startswith("AES"):
        return _SNMP_GOOD
    if protocol in _V3:
        return _SNMP_WEAK
    return _SNMP_V2


def _snmp_state(components):
    enabled = [item for item in components if item.get("is_enabled")]
    if not enabled:
        return _SNMP_OFF
    rank = {_SNMP_GOOD: 1, _SNMP_WEAK: 2, _SNMP_V2: 3}
    worst = _SNMP_GOOD
    for item in enabled:
        state = _snmp_one(item)
        if rank.get(state, 3) > rank.get(worst, 0):
            worst = state
    return worst


def render_snmp(objects):
    components = [item for item in objects if item.get("type") == "snmpcomponent"]
    if not components:
        return "missing: yes\n"
    state = _snmp_state(components)
    sample = components[0]
    return "\n".join([
        "is_enabled: {0}".format("yes" if any(item.get("is_enabled") for item in components) else "no"),
        "protocol: {0}".format(one_line(sample.get("protocol")) or "-"),
        "auth_type: {0}".format(one_line(sample.get("auth_type")) or "-"),
        "enc_type: {0}".format(one_line(sample.get("enc_type")) or "-"),
        "state: {0}".format(state),
    ]) + "\n"


def _remote_syslog(objects):
    for item in objects:
        kind = str(item.get("type") or "")
        if kind != "logserverremoteuplink" and "syslog" not in kind and not kind.endswith("remoteuplink"):
            continue
        if not item.get("is_enabled"):
            continue
        host = one_line(item.get("host") or item.get("ip") or item.get("address"))
        if host:
            return True
    return False


def render_syslog(objects):
    return "remote: {0}\n".format("yes" if _remote_syslog(objects) else "no")


def render_commands(export, node):
    """Текст команд show continent … из уже очищенной выгрузки. Секреты в текст не входят."""
    export = sanitize(export)
    node = sanitize(node or {})
    objects = _objects(export)
    by_type = _by_type(objects)
    text = {
        CMD_VERSION: render_version(node, export),
        CMD_PASSWORD: render_password(by_type),
        CMD_ADMINS: render_admins(objects),
        CMD_SSH: render_ssh(objects),
        CMD_SNMP: render_snmp(objects),
        CMD_SYSLOG: render_syslog(objects),
    }
    for command, body in text.items():
        if "REDACTED" in body or is_secret_key(body.split(":", 1)[0]):
            raise Continent4Error("внутренняя ошибка: в выводе {0} оказалось секретное поле".format(command))
    return text


def node_from_export(export, hwserial=None):
    """Узел из самой выгрузки, если отдельного ответа /cgw нет. update_version там не бывает."""
    objects = _objects(export)
    nodes = [item for item in objects if item.get("type") == "cgw"]
    serial = str(hwserial or export.get("hwserial") or "")
    if serial:
        for item in nodes:
            if str(item.get("hwserial") or "") == serial:
                return dict(item)
    if nodes:
        node = dict(nodes[0])
    else:
        node = {}
    if not node.get("hwserial") and export.get("hwserial"):
        node["hwserial"] = export.get("hwserial")
    return node


def merge_node(cgw_node, export):
    """Версия ПО — только update_version из /cgw. Имя можно взять и из выгрузки."""
    node = dict(cgw_node or {})
    fallback = node_from_export(export, node.get("hwserial"))
    for field in ("name", "mode", "platform", "hwserial"):
        if not node.get(field) and fallback.get(field):
            node[field] = fallback[field]
    return node


def judge(value, op, expected):
    """Тот же смысл, что у assert пака, для живого скрипта без сервера."""
    if value is None or (isinstance(value, str) and not str(value).strip()):
        return "error"

    def norm(item):
        return str(item).strip().lower()

    if op == "eq":
        return "pass" if norm(value) == norm(expected) else "fail"
    if op == "gte":
        try:
            return "pass" if float(value) >= float(expected) else "fail"
        except (TypeError, ValueError):
            return "error"
    if op == "in":
        options = {norm(item) for item in expected}
        return "pass" if norm(value) in options else "fail"
    return "error"


def parse_http_response(raw):
    """Ответ HTTP/1.x → (status, body). Поддерживаются Content-Length и chunked."""
    if not raw:
        raise Continent4Error("пустой ответ HTTP")
    head, sep, body = raw.partition(b"\r\n\r\n")
    if not sep:
        head, sep, body = raw.partition(b"\n\n")
    if not sep:
        raise Continent4Error("ответ HTTP без заголовков")
    lines = head.replace(b"\r\n", b"\n").split(b"\n")
    parts = lines[0].split(None, 2)
    if len(parts) < 2 or not parts[0].startswith(b"HTTP/"):
        raise Continent4Error("ответ не похож на HTTP")
    try:
        status = int(parts[1])
    except ValueError:
        raise Continent4Error("ответ HTTP без кода")
    headers = {}
    for line in lines[1:]:
        if b":" not in line:
            continue
        name, value = line.split(b":", 1)
        headers[name.decode("ascii", "replace").strip().lower()] = value.decode("latin1", "replace").strip()
    if "chunked" in headers.get("transfer-encoding", "").lower():
        body = _decode_chunks(body)
    elif "content-length" in headers:
        try:
            length = int(headers["content-length"])
        except ValueError:
            length = len(body)
        body = body[:length]
    if status in (301, 302, 303, 307, 308):
        raise Continent4Error("перенаправление HTTP запрещено")
    return status, body


def _decode_chunks(body):
    out = []
    rest = body
    while rest:
        line, sep, rest = rest.partition(b"\r\n")
        if not sep:
            break
        size_text = line.split(b";", 1)[0].strip()
        try:
            size = int(size_text, 16)
        except ValueError:
            break
        if size == 0:
            break
        if len(rest) < size:
            raise Continent4Error("обрезанный chunked-ответ")
        out.append(rest[:size])
        rest = rest[size:]
        if rest.startswith(b"\r\n"):
            rest = rest[2:]
    return b"".join(out)


def _client_protocol():
    return getattr(ssl, "PROTOCOL_TLS_CLIENT", ssl.PROTOCOL_TLS)


def _ssl_context(ciphers):
    context = ssl.SSLContext(_client_protocol())
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    # ЦУС отвергает TLS 1.3. maximum_version есть с Python 3.7; на 3.6 остаётся то, что умеет OpenSSL.
    if hasattr(ssl, "TLSVersion"):
        try:
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.maximum_version = ssl.TLSVersion.TLSv1_2
        except (ValueError, AttributeError):
            pass
    try:
        context.set_ciphers(ciphers)
    except ssl.SSLError as exc:
        raise TlsUnavailable("набор шифров {0} недоступен: {1}".format(ciphers, exc))
    return context


def _request_bytes(host, port, path, user, password):
    token = base64.b64encode("{0}:{1}".format(user, password).encode("utf-8")).decode("ascii")
    host_header = host if port in (443, 80) else "{0}:{1}".format(host, port)
    text = (
        "GET {path} HTTP/1.1\r\n"
        "Host: {host}\r\n"
        "Authorization: Basic {token}\r\n"
        "Accept: application/json\r\n"
        "User-Agent: hardening-agent\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).format(path=path, host=host_header, token=token)
    return text.encode("ascii")


def http_get(host, port, path, user, password, timeout, connect_timeout, ciphers=_GOST_CIPHERS):
    """Один GET по TLS. Сертификат не проверяется цепочкой (у ЦУС он самоподписанный ГОСТ);
    сверка отпечатка — снаружи. Возвращает (status, body, der)."""
    try:
        sock = socket.create_connection((host, port), connect_timeout)
    except socket.timeout:
        raise Continent4Error("таймаут соединения с {0}:{1}".format(host, port))
    except OSError as exc:
        if _network_down(exc):
            raise Continent4Error("нет соединения с {0}:{1}: {2}".format(host, port, exc))
        raise TlsUnavailable(str(exc))
    sock.settimeout(connect_timeout)
    try:
        context = _ssl_context(ciphers)
        try:
            tls = context.wrap_socket(sock, server_hostname=host)
        except ssl.SSLError as exc:
            raise TlsUnavailable("рукопожатие TLS: {0}".format(exc))
        except OSError as exc:
            raise TlsUnavailable("рукопожатие TLS: {0}".format(exc))
        try:
            der = tls.getpeercert(True)
            tls.settimeout(timeout)
            tls.sendall(_request_bytes(host, port, path, user, password))
            raw = _read_bounded(tls, timeout)
        finally:
            try:
                tls.close()
            except Exception:
                pass
    finally:
        try:
            sock.close()
        except Exception:
            pass
    status, body = parse_http_response(raw)
    return status, body, der


def _read_bounded(tls, timeout):
    chunks = []
    total = 0
    deadline = time.time() + timeout
    while total < _MAX_BODY:
        if time.time() > deadline:
            raise Continent4Error("таймаут чтения ответа ЦУС")
        try:
            piece = tls.recv(65536)
        except socket.timeout:
            raise Continent4Error("таймаут чтения ответа ЦУС")
        except ssl.SSLError as exc:
            raise TlsUnavailable("обрыв TLS при чтении: {0}".format(exc))
        if not piece:
            break
        chunks.append(piece)
        total += len(piece)
        blob = b"".join(chunks)
        if _headers_done(blob) and _body_done(blob):
            break
    else:
        raise Continent4Error("ответ ЦУС больше {0} байт".format(_MAX_BODY))
    return b"".join(chunks)


def _headers_done(blob):
    return b"\r\n\r\n" in blob or b"\n\n" in blob


def _body_done(blob):
    head, sep, body = blob.partition(b"\r\n\r\n")
    if not sep:
        head, sep, body = blob.partition(b"\n\n")
    if not sep:
        return False
    text = head.decode("latin1", "replace").lower()
    if "transfer-encoding:" in text and "chunked" in text.split("transfer-encoding:", 1)[1].split("\n", 1)[0]:
        return b"\r\n0\r\n\r\n" in body or body.endswith(b"\n0\r\n\r\n")
    match = re.search(r"content-length:\s*(\d+)", text)
    if match:
        return len(body) >= int(match.group(1))
    return False


def _network_down(exc):
    if isinstance(exc, socket.gaierror):
        return True
    text = str(exc).lower()
    return "connection refused" in text or "no route" in text or "network is unreachable" in text or "name or service not known" in text


def _pem_leaf_der(blob):
    text = blob.decode("latin1", "replace")
    match = re.search(
        r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----",
        text,
        re.DOTALL,
    )
    if not match:
        return None
    try:
        return base64.b64decode(re.sub(r"\s+", "", match.group(1)))
    except (ValueError, TypeError):
        return None


def check_secret_file(path):
    """Файл пароля существует, это не ссылка, и на POSIX его не читает группа и остальные."""
    if os.path.islink(path) or not os.path.isfile(path):
        raise ValueError("нет файла пароля {0} (нужен обычный файл, не ссылка)".format(path))
    if os.name != "nt":
        mode = os.stat(path).st_mode
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise ValueError("файл пароля {0} доступен не только владельцу — нужны права 0600".format(path))


def read_password(path):
    check_secret_file(path)
    with open(path, encoding="utf-8") as handle:
        lines = handle.read().splitlines()
    if not lines or not lines[0]:
        raise ValueError("файл пароля {0} пуст".format(path))
    return lines[0]


def load_config(path):
    """JSON цели. Пароля в нём быть не должно: только путь к файлу с правами 0600."""
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError) as exc:
        raise ValueError("файл цели Континент 4 не читается: {0}".format(exc)) from exc
    if not isinstance(data, dict):
        raise ValueError("файл цели Континент 4: ожидается объект JSON")
    if any(key in data for key in ("password", "pass", "secret")):
        raise ValueError("пароль не храните в файле цели — укажите password_file с правами 0600")
    host = data.get("host")
    if not isinstance(host, str) or not probes._HOST_RE.match(host):
        raise ValueError("в файле цели недопустимое поле host")
    user = data.get("user")
    if not isinstance(user, str) or not probes._USER_RE.match(user):
        raise ValueError("в файле цели недопустимое поле user")
    password_file = data.get("password_file")
    if not isinstance(password_file, str) or not password_file or password_file.startswith("-"):
        raise ValueError("в файле цели нужен password_file — путь к файлу пароля")
    check_secret_file(password_file)
    hostname = data.get("hostname")
    if hostname is not None and (not isinstance(hostname, str) or not probes._HOST_RE.match(hostname)):
        raise ValueError("в файле цели недопустимое поле hostname")
    hwserial = data.get("hwserial")
    if hwserial is not None and not _SERIAL_RE.match(str(hwserial)):
        raise ValueError("hwserial: буквы, цифры, _ и -")
    order = data.get("tls") or list(_TLS_ORDER)
    if not isinstance(order, list) or not order or any(item not in _TLS_ORDER for item in order):
        raise ValueError("tls: непустой список из in-process, python, curl, openssl")

    def port(name, default, upper=65535):
        value = data.get(name, default)
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= upper:
            raise ValueError("{0}: целое 1–{1}".format(name, upper))
        return value

    try:
        pin = parse_pin(data.get("pin_sha256"))
    except ValueError as exc:
        raise ValueError(str(exc))
    engine = data.get("gost_engine")
    conf = data.get("openssl_conf")
    for label, item in (("gost_engine", engine), ("openssl_conf", conf)):
        if item is not None and (not isinstance(item, str) or not item or item.startswith("-") or "\n" in item):
            raise ValueError("{0}: путь к файлу".format(label))
    return {
        "host": host,
        "port": port("port", 444),
        "user": user,
        "hostname": hostname,
        "password_file": password_file,
        "hwserial": str(hwserial) if hwserial else "",
        "pin_sha256": pin,
        "timeout": port("timeout", 90, 600),
        "connect_timeout": port("connect_timeout", 10, 120),
        "tls": list(order),
        "gost_engine": engine,
        "openssl_conf": conf,
    }


def _file_meta(path, label):
    st = os.stat(path)
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        raw = handle.read(_MAX_BODY + 1)
    if len(raw) > _MAX_BODY:
        raise ValueError("файл {0} больше {1} байт".format(os.path.basename(path), _MAX_BODY))
    digest.update(raw)
    return {
        "command": label,
        "file": os.path.basename(path),
        "sha256": digest.hexdigest(),
        "modified": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(st.st_mtime)),
        "raw": raw,
    }


def _read_offline_tree(directory):
    if not os.path.isdir(directory):
        raise ValueError("нет каталога выгрузки {0}".format(directory))
    found = []
    for name in sorted(os.listdir(directory)):
        path = os.path.join(directory, name)
        if not name.endswith(".json") or os.path.islink(path) or not os.path.isfile(path):
            continue
        meta = _file_meta(path, name)
        data = load_json_bytes(meta["raw"])
        kind = classify_document(data) if data is not None else None
        if kind:
            meta["kind"] = kind
            meta["data"] = data
            found.append(meta)
    return found


def directory_has_export(directory):
    try:
        items = _read_offline_tree(directory)
    except (OSError, ValueError):
        return False
    return any(item["kind"] in ("export", "bundle") for item in items)


def documents_from_items(items):
    """Список классифицированных JSON → (export, node или None, метаданные файлов)."""
    export = None
    pool = []
    metas = []
    for item in items:
        kind = item["kind"]
        data = sanitize(item["data"])
        metas.append({key: item[key] for key in ("command", "file", "sha256", "modified")})
        if kind == "bundle":
            if _is_export(data.get("export")):
                if export is not None:
                    raise ValueError("в выгрузке два файла export-config-for-cgw")
                export = data["export"]
            if _is_cgw_list(data.get("cgw")):
                pool.extend(cgw_nodes(data["cgw"]))
        elif kind == "export":
            if export is not None:
                raise ValueError("в выгрузке два файла export-config-for-cgw")
            export = data
        elif kind == "cgw":
            pool.extend(cgw_nodes(data))
        # config — признак ЦУС, для проверок не нужен
    if export is None:
        raise ValueError("в выгрузке Континент 4 нет export-config-for-cgw (JSON c4_config_exporter или ЛМ)")
    node = select_node(pool, export.get("hwserial")) if pool else None
    return export, node, metas


class Continent4Transport:
    """Транспорт паков ssh: те же пробы cli_config, источник — ЦУС или JSON-выгрузка.

    name для живого опроса — ssh (подходят сетевые паки). Для выгрузки — offline-config,
    чтобы снимок был помечен как проверка файла, а не живого узла.
    """

    pack_transport = "ssh"
    platform = "network"

    def __init__(self, config=None, export=None, node=None, files=None, runner=None, http_get=None):
        self.config = config
        self._export = export
        self._node = node
        self._files = files
        self._runner = runner or _run_process
        self._http_get = http_get or http_get_default
        self._allowed = []
        self._bound = False
        self._cache = None
        self._rendered = None
        self._password = None
        self._tls_name = None
        self._peer_sha256 = ""
        self._reported = False
        self._load_error = None  # ошибка чтения ЦУС: повторять GET на каждую проверку нельзя
        self._workdir = None
        self.missing = set()
        if config:
            self.host = config["host"]
            self.name = "ssh"
            self.asset_hostname = config.get("hostname") or config["host"]
            self.asset_ip = config["host"] if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", config["host"]) else None
        else:
            self.host = None
            self.name = "offline-config"
            self.asset_hostname = None
            self.asset_ip = None
            self._rendered = render_commands(export, merge_node(node, export) if node else node_from_export(export))
            if node and node.get("name"):
                self.asset_hostname = one_line(node.get("name"))
            elif self._rendered:
                match = re.search(r"(?m)^name:\s*(\S+)", self._rendered[CMD_VERSION])
                if match:
                    self.asset_hostname = match.group(1)

    @classmethod
    def from_directory(cls, directory):
        items = _read_offline_tree(directory)
        if not any(item["kind"] in ("export", "bundle") for item in items):
            raise ValueError("в каталоге нет JSON export-config-for-cgw")
        export, node, metas = documents_from_items(items)
        return cls(export=export, node=node, files=metas)

    @classmethod
    def from_uploads(cls, files):
        """files — {имя: байты} загрузки через интерфейс. None, если это не JSON ЦУС."""
        items = []
        other = False
        for name, raw in files.items():
            data = load_json_bytes(raw)
            kind = classify_document(data) if data is not None else None
            if not kind:
                other = True
                continue
            digest = hashlib.sha256(raw).hexdigest()
            items.append({
                "command": kind,
                "file": os.path.basename(str(name)) or kind + ".json",
                "sha256": digest,
                "modified": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "kind": kind,
                "data": data,
            })
        if not items:
            return None
        if other:
            raise ValueError("в одной загрузке смешаны JSON Континент 4 и другие файлы")
        export, node, metas = documents_from_items(items)
        return cls(export=export, node=node, files=metas)

    def bind_manifests(self, manifests):
        """Белый список путей — из подписанных манифестов, пересечённый с набором агента."""
        declared = []
        for manifest in manifests or []:
            declared.extend(manifest.get("c4_paths") or [])
        allowed = []
        for path in C4_READONLY_PATHS:
            if path in declared and path not in allowed:
                allowed.append(path)
        self._allowed = allowed
        self._bound = True

    def bind_builtin(self):
        """Живой скрипт без манифеста: потолок — тот же зашитый список из трёх GET."""
        self._allowed = list(C4_READONLY_PATHS)
        self._bound = True

    def close(self):
        self._password = None
        if self._workdir:
            shutil.rmtree(self._workdir, ignore_errors=True)
            self._workdir = None

    def describe(self):
        if not self._files:
            return None
        return {"source": "offline-config", "files": list(self._files)}

    def run_cli(self, command):
        if not probes.is_readonly_cli(command):
            raise Continent4Error("допустимы только команды на чтение: {0!r}".format(command))
        if command not in COMMANDS:
            raise Continent4Error("команда {0!r} не читается из API ЦУС".format(command))
        self._ensure_rendered()
        text = self._rendered.get(command) or ""
        if not text.strip():
            raise Continent4Error("пустой вывод {0}".format(command))
        return probes.CmdOutput(text if text.endswith("\n") else text + "\n", "", 0)

    def run(self, argv):
        return self.run_cli(" ".join(argv))

    def read_file(self, path):
        raise Continent4Error("файловые пробы недоступны на ЦУС Континент 4")

    def stat_file(self, path):
        raise Continent4Error("file_stat недоступна на ЦУС Континент 4")

    def read_registry(self, key, name):
        raise Continent4Error("реестр недоступен на ЦУС Континент 4")

    def secpol(self):
        raise Continent4Error("политика безопасности Windows недоступна на ЦУС Континент 4")

    def auditpol(self):
        raise Continent4Error("политика аудита Windows недоступна на ЦУС Континент 4")

    def _ensure_rendered(self):
        # Успех и ошибка кэшируются: иначе каждая проверка заново делает три GET.
        # Повторный 401 блокирует IP агента на ЦУС (лимит неверных входов — три).
        if self._load_error is not None:
            raise self._load_error
        if self._rendered is not None:
            return
        try:
            self._load_rendered()
        except Continent4Error as exc:
            message = scrub_text(str(exc), [self._password])
            self._load_error = Continent4Error(message)
            self._report(message)
            raise self._load_error
        finally:
            self._password = None

    def _load_rendered(self):
        if not self._bound:
            raise Continent4Error("белый список путей ЦУС не задан манифестом пака")
        for path in C4_READONLY_PATHS:
            if path not in self._allowed:
                raise Continent4Error("пак не разрешает чтение {0}".format(path))
        self._password = read_password(self.config["password_file"])
        config_body = self._get_json("/api-v1-objects/config")
        if classify_document(config_body) != "config":
            raise Continent4Error("ответ /api-v1-objects/config не похож на список конфигураций ЦУС")
        cgw_body = self._get_json("/api-v1-objects/config/active/cgw")
        node = select_node(cgw_nodes(cgw_body), self.config.get("hwserial"))
        serial = str(node.get("hwserial"))
        export_path = _EXPORT_PREFIX + serial + "?view=full"
        export = self._get_json(export_path)
        if not _is_export(export):
            raise Continent4Error("ответ export-config-for-cgw не похож на выгрузку УБ")
        export = sanitize(export)
        node = sanitize(merge_node(node, export))
        self._rendered = render_commands(export, node)
        if not self.config.get("hostname") and node.get("name"):
            self.asset_hostname = one_line(node.get("name"))
        self._node = node

    def _report(self, message):
        if not self._reported:
            self._reported = True
            print("Континент 4 {0}: {1}".format(self.host, message), file=sys.stderr)

    def _get_json(self, path):
        body = self._get(path)
        try:
            data = json.loads(body.decode("utf-8-sig"))
        except (UnicodeError, ValueError):
            raise Continent4Error("ответ {0} не JSON".format(path.split("?", 1)[0]))
        return data

    def _get(self, path):
        template = _template_for(path)
        if template not in C4_READONLY_PATHS or template not in self._allowed:
            raise Continent4Error("путь не в белом списке чтения ЦУС: {0}".format(path.split("?", 1)[0]))
        errors = []
        for name in self.config.get("tls") or _TLS_ORDER:
            try:
                status, body, digest = self._call_tls(name, path)
            except Continent4Error as exc:
                if isinstance(exc, TlsUnavailable):
                    errors.append("{0}: {1}".format(name, scrub_text(str(exc), [self._password])))
                    continue
                raise
            self._peer_sha256 = (digest or "").lower()
            self._check_pin(digest)
            if status in (401, 403):
                # Пароль или роль не подошли. Это не сбой ГОСТ: следующий способ
                # отправил бы тот же Basic и добил бы лимит неверных входов на ЦУС.
                raise Continent4Error(
                    "ЦУС ответил HTTP {0} на {1} — неверный логин, пароль или роль. "
                    "Повторная попытка не выполняется.".format(status, path.split("?", 1)[0])
                )
            if status != 200:
                raise Continent4Error("ЦУС ответил HTTP {0} на {1}".format(status, path.split("?", 1)[0]))
            if len(body) > _MAX_BODY:
                raise Continent4Error("ответ ЦУС больше {0} байт".format(_MAX_BODY))
            if self._tls_name is None:
                self._tls_name = name
                self._report("ГОСТ TLS через {0}".format(name))
            return body
        self._raise_tls_exhausted(errors)

    def _raise_tls_exhausted(self, errors):
        detail = "; ".join(errors) if errors else "ни один способ не вызван"
        pin_only = errors and all("не сверяет отпечаток" in item for item in errors)
        if pin_only:
            raise Continent4Error(
                "Подключение не выполнено: {0} "
                "Это не отсутствие движка ГОСТ. Укажите --tls python или --tls openssl "
                "(либо python,openssl), чтобы сверить pin_sha256.".format(detail)
            )
        raise Continent4Error("нет ГОСТ TLS к {0}:{1}. {2} Попытки: {3}".format(
            self.host, self.config.get("port") or 444, _GOST_HINT, detail,
        ))

    def _check_pin(self, digest):
        expected = self.config.get("pin_sha256") or ""
        if not expected:
            return
        if not digest:
            raise Continent4Error("не удалось получить сертификат ЦУС для сверки pin_sha256")
        if digest.lower() != expected.lower():
            raise Continent4Error(
                "отпечаток сертификата ЦУС не совпал с pin_sha256 (получен {0}, ожидался {1})".format(
                    digest.lower(), expected.lower(),
                )
            )

    def _call_tls(self, name, path):
        if name == "in-process":
            return self._tls_inprocess(path)
        if name == "python":
            return self._tls_python(path)
        if name == "curl":
            return self._tls_curl(path)
        if name == "openssl":
            return self._tls_openssl(path)
        raise TlsUnavailable("неизвестный способ {0}".format(name))

    def _tls_inprocess(self, path):
        if not _process_has_gost():
            raise TlsUnavailable(
                "в этом процессе нет шифра ГОСТ (OPENSSL_CONF с gost.so нужно задать до запуска агента)"
            )
        status, body, der = self._http_get(
            self.host, self.config["port"], path, self.config["user"], self._password,
            self.config["timeout"], self.config["connect_timeout"], _GOST_CIPHERS,
        )
        return status, body, cert_sha256(der)

    def _tls_python(self, path):
        conf = self._prepare_conf()
        if not conf:
            raise TlsUnavailable("нет openssl.cnf с движком ГОСТ (пакет libengine-gost-openssl или поле gost_engine)")
        script = os.path.join(self._ensure_workdir(), "tls_worker.py")
        if not os.path.exists(script):
            with open(script, "w", encoding="utf-8") as handle:
                handle.write(_WORKER_SCRIPT)
            os.chmod(script, 0o700)
        env = _child_env(conf)
        job = json.dumps({
            "host": self.host,
            "port": self.config["port"],
            "path": path,
            "user": self.config["user"],
            "password": self._password,
            "timeout": self.config["timeout"],
            "connect_timeout": self.config["connect_timeout"],
        }).encode("utf-8")
        code, out, err = self._runner(
            [sys.executable, script], env, job, self.config["timeout"] + self.config["connect_timeout"] + 5,
        )
        if code != 0:
            message = scrub_text((err or out or b"").decode("utf-8", "replace").strip(), [self._password])[:400]
            # Код 2 — только «нет ГОСТ». Сеть, HTTP и прочие ошибки не перебирают следующий способ:
            # иначе connection refused выглядит как отсутствие движка и запрос уходит в curl.
            if code == 2:
                raise TlsUnavailable(message or "нет ГОСТ TLS в подпроцессе Python")
            raise Continent4Error(message or "подпроцесс Python завершился с кодом {0}".format(code))
        try:
            payload = json.loads(out.decode("utf-8"))
        except ValueError:
            raise TlsUnavailable("подпроцесс Python вернул не JSON")
        try:
            body = base64.b64decode(payload.get("body_b64") or "")
        except (TypeError, ValueError):
            raise TlsUnavailable("подпроцесс Python вернул тело не в base64")
        return int(payload.get("status") or 0), body, str(payload.get("cert_sha256") or "")

    def _tls_curl(self, path):
        if self.config.get("pin_sha256"):
            raise TlsUnavailable(
                "curl не сверяет отпечаток сертификата ЦУС (pin_sha256 задан); нужен python или openssl s_client"
            )
        if shutil.which("curl") is None:
            raise TlsUnavailable("curl не установлен")
        conf = self._prepare_conf()
        if not conf:
            raise TlsUnavailable("нет openssl.cnf с движком ГОСТ")
        url = "https://{0}:{1}{2}".format(self.host, self.config["port"], path)
        conf_file = os.path.join(self._ensure_workdir(), "curl.cnf")
        # Пароль в файле 0600, не в argv. Файл перезаписывается на каждый запрос и удаляется в close().
        text = 'user = "{0}:{1}"\nurl = "{2}"\n'.format(
            _curl_quote(self.config["user"]), _curl_quote(self._password), _curl_quote(url),
        )
        with open(conf_file, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.chmod(conf_file, 0o600)
        argv = [
            "curl", "-sS", "--tlsv1.2", "--tls-max", "1.2",
            "--ciphers", _GOST_CIPHERS, "-k",
            "--connect-timeout", str(self.config["connect_timeout"]),
            "--max-time", str(self.config["timeout"]),
            "-K", conf_file,
            "-o", "-",
            "-w", "__C4_%{http_code}",
        ]
        env = _child_env(conf)
        code, out, err = self._runner(argv, env, None, self.config["timeout"] + 5)
        try:
            os.remove(conf_file)
        except OSError:
            pass
        if code != 0:
            message = err.decode("utf-8", "replace").strip()
            if code in (6, 7, 28):
                raise Continent4Error("curl: {0}".format(scrub_text(message, [self._password])[:200] or "код {0}".format(code)))
            raise TlsUnavailable(scrub_text(message, [self._password])[:400] or "код {0}".format(code))
        marker = b"__C4_"
        if marker not in out:
            raise TlsUnavailable("curl не сообщил код HTTP")
        blob, _, status_line = out.rpartition(marker)
        try:
            status = int(status_line.strip() or b"0")
        except ValueError:
            raise TlsUnavailable("curl не сообщил код HTTP")
        return status, blob, ""

    def _tls_openssl(self, path):
        if shutil.which("openssl") is None:
            raise TlsUnavailable("openssl не установлен")
        conf = self._prepare_conf()
        if not conf:
            raise TlsUnavailable("нет openssl.cnf с движком ГОСТ")
        argv = [
            "openssl", "s_client",
            "-connect", "{0}:{1}".format(self.host, self.config["port"]),
            "-servername", self.host,
            "-tls1_2",
            "-cipher", _GOST_CIPHERS,
            "-showcerts",
        ]
        request = _request_bytes(self.host, self.config["port"], path, self.config["user"], self._password)
        env = _child_env(conf)
        out, err = _openssl_exchange(argv, env, request, self.config["timeout"], self._runner)
        der = _pem_leaf_der(out)
        http_at = out.find(b"HTTP/")
        if http_at < 0:
            message = err.decode("utf-8", "replace").strip()
            low = message.lower()
            if "refused" in low or "no route" in low or "timed out" in low:
                raise Continent4Error("openssl: {0}".format(scrub_text(message, [self._password])[:200]))
            raise TlsUnavailable(scrub_text(message or "openssl s_client не вернул HTTP", [self._password])[:400])
        status, body = parse_http_response(out[http_at:])
        return status, body, cert_sha256(der)

    def _prepare_conf(self):
        explicit = self.config.get("openssl_conf")
        if explicit:
            if not os.path.isfile(explicit):
                raise Continent4Error("нет файла openssl_conf {0}".format(explicit))
            if not conf_mentions_gost(explicit):
                raise Continent4Error(
                    "файл openssl_conf {0} не подключает движок ГОСТ. "
                    "Укажите cnf с gost.so или уберите openssl_conf — агент найдёт движок сам.".format(explicit)
                )
            return explicit
        env_conf = os.environ.get("OPENSSL_CONF")
        # Чужой OPENSSL_CONF (без ГОСТ) не должен прятать установленный gost.so.
        if (
            env_conf and os.path.isfile(env_conf) and conf_mentions_gost(env_conf)
            and not self.config.get("gost_engine")
        ):
            return env_conf
        try:
            engine = find_gost_engine(self.config.get("gost_engine"))
        except ValueError as exc:
            raise Continent4Error(str(exc))
        if not engine:
            if env_conf and os.path.isfile(env_conf) and not conf_mentions_gost(env_conf):
                raise TlsUnavailable(
                    "OPENSSL_CONF={0} не подключает движок ГОСТ, и gost.so не найден "
                    "(пакет libengine-gost-openssl). Уберите OPENSSL_CONF или укажите gost_engine.".format(env_conf)
                )
            return None
        path = os.path.join(self._ensure_workdir(), "openssl-gost.cnf")
        if not os.path.exists(path):
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(openssl_conf_text(engine))
            os.chmod(path, 0o600)
        return path

    def _ensure_workdir(self):
        if self._workdir is None:
            self._workdir = tempfile.mkdtemp(prefix="hardening-c4-")
            os.chmod(self._workdir, 0o700)
        return self._workdir


def http_get_default(host, port, path, user, password, timeout, connect_timeout, ciphers):
    return http_get(host, port, path, user, password, timeout, connect_timeout, ciphers)


def _process_has_gost():
    try:
        context = ssl.SSLContext(_client_protocol())
        context.set_ciphers("GOST2012-KUZNYECHIK-KUZNYECHIKOMAC")
        return True
    except ssl.SSLError:
        return False
    except Exception:
        return False


def _template_for(path):
    if not isinstance(path, str) or not path.startswith("/") or "\\" in path or ".." in path.split("/"):
        raise Continent4Error("недопустимый путь API ЦУС")
    if any(char in path for char in " \r\n\t"):
        raise Continent4Error("недопустимый путь API ЦУС")
    base, mark, query = path.partition("?")
    if base in ("/api-v1-objects/config", "/api-v1-objects/config/active/cgw"):
        if mark:
            raise Continent4Error("путь не в белом списке чтения ЦУС: {0}".format(base))
        return base
    if base.startswith(_EXPORT_PREFIX) and query == "view=full":
        serial = base[len(_EXPORT_PREFIX):]
        if not _SERIAL_RE.match(serial):
            raise Continent4Error("hwserial в пути export-config-for-cgw недопустим")
        return "/api-v1-server/config/active/export-config-for-cgw"
    raise Continent4Error("путь не в белом списке чтения ЦУС: {0}".format(base[:120]))


def _child_env(openssl_conf):
    env = os.environ.copy()
    env["OPENSSL_CONF"] = openssl_conf
    env.pop("PYTHONWARNINGS", None)
    return env


def _curl_quote(value):
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def _run_process(argv, env, input_bytes, timeout):
    try:
        proc = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
        )
    except OSError as exc:
        raise TlsUnavailable("не удалось запустить {0}: {1}".format(argv[0], exc))
    try:
        out, err = proc.communicate(input_bytes, timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        raise TlsUnavailable("таймаут {0}".format(argv[0]))
    return proc.returncode, out, err


def _openssl_exchange(argv, env, request, timeout, runner):
    """s_client не закрываем по EOF stdin: выгрузка ЦУС занимает около 10 с, а EOF оборвал бы TLS.
    runner в тестах подменяет процесс целиком и возвращает (code, stdout, stderr)."""
    if runner is not _run_process:
        code, out, err = runner(argv, env, request, timeout)
        if code not in (0, None) and not out:
            raise TlsUnavailable((err or b"").decode("utf-8", "replace")[:400] or "код {0}".format(code))
        return out, err
    try:
        proc = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
        )
    except OSError as exc:
        raise TlsUnavailable("не удалось запустить openssl: {0}".format(exc))
    out_chunks = []
    err_chunks = []

    def _pump(stream, sink):
        try:
            while True:
                piece = stream.read(65536)
                if not piece:
                    break
                sink.append(piece)
        except Exception:
            pass

    import threading

    readers = [
        threading.Thread(target=_pump, args=(proc.stdout, out_chunks)),
        threading.Thread(target=_pump, args=(proc.stderr, err_chunks)),
    ]
    for thread in readers:
        thread.daemon = True
        thread.start()
    try:
        proc.stdin.write(request)
        proc.stdin.flush()
    except OSError as exc:
        proc.kill()
        raise TlsUnavailable("openssl stdin: {0}".format(exc))
    deadline = time.time() + timeout
    while time.time() < deadline:
        blob = b"".join(out_chunks)
        if b"HTTP/" in blob and _body_done(blob[blob.find(b"HTTP/"):]):
            break
        if proc.poll() is not None:
            break
        time.sleep(0.05)
    try:
        proc.stdin.close()
    except OSError:
        pass
    if proc.poll() is None:
        proc.kill()
    proc.wait()
    for thread in readers:
        thread.join(timeout=1)
    return b"".join(out_chunks), b"".join(err_chunks)


# Рабочий процесс: OPENSSL_CONF уже в окружении на старте, поэтому import ssl подхватывает ГОСТ.
# Пароль приходит в stdin и в argv не записывается. Модуль continent4 здесь не импортируется:
# родитель уже мог загрузить ssl без движка, а этот файл тянет probes.
_WORKER_SCRIPT = r'''
import base64, json, os, socket, ssl, sys, time, re

MAX_BODY = 8 * 1024 * 1024

def fail(message, code=2):
    # 2 — нет ГОСТ (следующий способ ещё можно пробовать). 3 — сеть или обрыв уже после
    # рукопожатия: это не «нет движка», родитель не должен звать curl.
    sys.stderr.write(message[:500])
    raise SystemExit(code)

def main():
    try:
        job = json.loads(sys.stdin.buffer.read().decode("utf-8"))
    except Exception as exc:
        fail("задание не прочитано: {0}".format(exc), 4)
    host, port, path = job["host"], int(job["port"]), job["path"]
    user, password = job["user"], job["password"]
    timeout, connect_timeout = int(job["timeout"]), int(job["connect_timeout"])
    try:
        sock = socket.create_connection((host, port), connect_timeout)
    except socket.timeout:
        fail("таймаут соединения", 3)
    except OSError as exc:
        fail(str(exc), 3)
    sock.settimeout(connect_timeout)
    protocol = getattr(ssl, "PROTOCOL_TLS_CLIENT", ssl.PROTOCOL_TLS)
    ctx = ssl.SSLContext(protocol)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if hasattr(ssl, "TLSVersion"):
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        except Exception:
            pass
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError as exc:
        fail("шифры ГОСТ недоступны: {0}".format(exc))
    try:
        tls = ctx.wrap_socket(sock, server_hostname=host)
    except ssl.SSLError as exc:
        fail("рукопожатие TLS: {0}".format(exc))
    try:
        der = tls.getpeercert(True)
        tls.settimeout(timeout)
        token = base64.b64encode("{0}:{1}".format(user, password).encode("utf-8")).decode("ascii")
        host_header = host if port in (443, 80) else "{0}:{1}".format(host, port)
        request = (
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Basic {token}\r\n"
            "Accept: application/json\r\nConnection: close\r\n\r\n"
        ).format(path=path, host=host_header, token=token)
        tls.sendall(request.encode("ascii"))
        chunks, total = [], 0
        while total < MAX_BODY:
            piece = tls.recv(65536)
            if not piece:
                break
            chunks.append(piece)
            total += len(piece)
        raw = b"".join(chunks)
    except socket.timeout:
        fail("таймаут чтения", 3)
    except ssl.SSLError as exc:
        fail("обрыв TLS: {0}".format(exc), 3)
    except OSError as exc:
        fail(str(exc), 3)
    finally:
        try:
            tls.close()
        except Exception:
            pass
    head, sep, body = raw.partition(b"\r\n\r\n")
    if not sep:
        fail("ответ без HTTP", 4)
    parts = head.split(None, 2)
    try:
        status = int(parts[1])
    except (IndexError, ValueError):
        fail("нет кода HTTP", 4)
    headers = {}
    for line in head.replace(b"\r\n", b"\n").split(b"\n")[1:]:
        if b":" in line:
            name, value = line.split(b":", 1)
            headers[name.decode("latin1").strip().lower()] = value.decode("latin1").strip()
    if "content-length" in headers:
        try:
            body = body[:int(headers["content-length"])]
        except ValueError:
            pass
    result = {
        "status": status,
        "cert_sha256": __import__("hashlib").sha256(der).hexdigest() if der else "",
        "body_b64": base64.b64encode(body).decode("ascii"),
    }
    sys.stdout.buffer.write(json.dumps(result).encode("ascii"))

if __name__ == "__main__":
    main()
'''


def evaluate_rendered(transport):
    """Список {id, status, value, error} по пробам пака. Секретов в value нет: их нет в тексте."""
    rows = []
    for item in CHECKS:
        result = probes.run_probe(transport, item["probe"])
        if result.get("error") or not result.get("found"):
            status, value = "error", None
        else:
            value = result.get("value")
            status = judge(value, item["op"], item["value"])
        rows.append({
            "id": item["id"],
            "status": status,
            "value": value,
            "error": result.get("error"),
        })
    version = probes.run_probe(transport, VERSION_PROBE)
    return rows, version


def _print_rows(rows, version, node_line):
    if node_line:
        print(node_line)
    if version.get("found") and version.get("value"):
        print("update_version: {0}".format(version["value"]))
    else:
        print("update_version: (нет в ответе /cgw — для БДУ нужен этот ответ рядом с выгрузкой)")
    width = max(len(item["id"]) for item in rows)
    for item in rows:
        shown = item["error"] if item["status"] == "error" else item["value"]
        print("{0}  {1}  {2}".format(item["id"].ljust(width), item["status"].ljust(5), shown))


def _live_transport(args):
    pin = parse_pin(args.pin_sha256) if args.pin_sha256 else ""
    config = {
        "host": args.host,
        "port": args.port,
        "user": args.user,
        "hostname": None,
        "password_file": args.password_file,
        "hwserial": args.hwserial or "",
        "pin_sha256": pin,
        "timeout": args.timeout,
        "connect_timeout": args.connect_timeout,
        "tls": parse_tls_list(args.tls),
        "gost_engine": args.gost_engine,
        "openssl_conf": args.openssl_conf,
    }
    if not probes._HOST_RE.match(config["host"]):
        raise ValueError("недопустимый адрес ЦУС")
    if not probes._USER_RE.match(config["user"]):
        raise ValueError("недопустимое имя пользователя")
    check_secret_file(config["password_file"])
    transport = Continent4Transport(config)
    transport.bind_builtin()
    return transport


def _build_parser():
    import argparse

    parser = argparse.ArgumentParser(
        description="Проверка Континент 4 по API ЦУС (только три GET). Пароль — из файла, в вывод не попадает.",
    )
    parser.add_argument("--host", required=True, help="Адрес ЦУС")
    parser.add_argument("--user", required=True, help="Учётная запись только на чтение (роль «Аудитор»)")
    parser.add_argument("--password-file", required=True, help="Файл пароля, права 0600, одна строка")
    parser.add_argument("--port", type=int, default=444)
    parser.add_argument("--hwserial", default="", help="Серийный номер УБ, если на ЦУС их несколько")
    parser.add_argument("--pin-sha256", default="", help="SHA-256 сертификата ЦУС (hex или sha256//base64)")
    parser.add_argument("--timeout", type=int, default=90)
    parser.add_argument("--connect-timeout", type=int, default=10)
    parser.add_argument("--gost-engine", default=None, help="Путь к gost.so, если пакет лежит не в стандартном каталоге")
    parser.add_argument("--openssl-conf", default=None, help="Готовый OPENSSL_CONF с движком ГОСТ")
    parser.add_argument(
        "--tls", default="",
        help="Способы ГОСТ TLS через запятую: in-process,python,curl,openssl. По умолчанию все четыре по порядку",
    )
    parser.add_argument("--show-pin", action="store_true", help="Только напечатать отпечаток сертификата и выйти")
    return parser


def main(argv=None):
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        transport = _live_transport(args)
    except ValueError as exc:
        print("Ошибка: {0}".format(exc), file=sys.stderr)
        return 2
    try:
        if args.show_pin:
            transport._password = read_password(args.password_file)
            transport._get("/api-v1-objects/config")
            if not transport._peer_sha256:
                print("Ошибка: сертификат ЦУС не получен", file=sys.stderr)
                return 2
            print(transport._peer_sha256)
            return 0
        rows, version = evaluate_rendered(transport)
    except Continent4Error as exc:
        print("Ошибка: {0}".format(scrub_text(str(exc))), file=sys.stderr)
        return 2
    finally:
        transport.close()
    if transport._load_error is not None:
        # Уже напечатано один раз из транспорта. Строки проверок и пустой hwserial не дублируют её.
        return 2
    node = transport._node or {}
    line = "node: {0}  hwserial: {1}  tls: {2}".format(
        one_line(node.get("name")) or transport.asset_hostname or args.host,
        one_line(node.get("hwserial")),
        transport._tls_name or "-",
    )
    _print_rows(rows, version, line)
    if any(item["status"] == "error" for item in rows):
        return 2
    if any(item["status"] == "fail" for item in rows):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
