"""Доступ агента к UserGate NGFW: XML-RPC, SSH exec и интерактивный SSH.

Устройство проверяет обычный агент с хоста в сети заказчика (не сервер). Учётка Admin
по ключу не пускает, а одна команда `ssh` с закрытым stdin возвращает пустой вывод —
так устроен CLI UserGate 7.4. Пароль остаётся в файле на хосте агента и в процесс ssh
не передаётся аргументом.

Порядок по умолчанию: XML-RPC (порт 4040, структурированные данные и версия из ответа
login), затем SSH exec (одна команда на соединение, stdin открыт, пока не придёт вывод),
затем интерактивный `ssh -tt` (приглашение, `configure`, листание `--more--`).
Способ, который не смог отдать команду, не отменяет остальные: версия, например,
в exec-режиме configure не читается (`show system version` → `Error:`), и тогда
её берёт XML-RPC или интерактивный сеанс.

Зависимости — только стандартная библиотека Python 3.6+. Методы XML-RPC вызываются
лишь если они есть и в белом списке агента, и в подписанном манифесте пака.
"""
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import xmlrpc.client

import probes

# Совпадает с USERGATE_XMLRPC_READONLY в app/services/packs/models.py.
# Сюда нельзя добавлять методы записи (add/update/delete/set/…): пак их объявить не сможет,
# а агент не вызовет метод вне этого набора, даже если подпись манифеста его содержит.
USERGATE_READONLY_METHODS = frozenset({
    "v2.core.login",
    "v2.core.logout",
    "v2.core.license.info",
    "v2.core.administrator.config.get",
    "v1.netmanager.zones.list",
    "v1.firewall.rules.list",
    "v1.dos.profiles.list",
})
_WRITE_METHOD = re.compile(r"(^|\.)(add|update|delete|set|remove|start|stop|create|edit|import|execute)(\.|$)")

# Имена сервисов зоны по service_id. Снято с заводской 7.4.1: CLI перечисляет включённые
# сервисы в порядке service_id, и этот порядок однозначно совпал с v1.netmanager.zones.list
# на всех восьми зонах стенда. Неизвестный id не подменяется угаданным именем.
SERVICE_NAMES = {
    1: "Any ICMP",
    2: "SNMP",
    4: "reponse_pages",
    5: "rpc",
    6: "ha",
    8: "Admin Console",
    9: "DNS",
    10: "HTTP Proxy",
    11: "Authorization agent",
    12: "SMTP Proxy",
    13: "POP3 Proxy",
    14: "CLI over SSH",
    17: "SCADA",
    33: "Endpoint connect",
    34: "HTTPS RPC",
}

_ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07]*(?:\x07|\x1b\\)|\x1b[@-_]")
_CPR = "WARNING: your terminal doesn't support cursor position requests (CPR)."
_MORE = "--more--"
# Приглашение целиком на строке: `Admin@host>` или `#`, иногда продублированное перерисовкой.
_PROMPT_LINE = re.compile(r"^(?:\S+@\S+[>#] ?)+$")
_ECHO_LINE = re.compile(r"^(?P<prompt>\S+@\S+[>#])(?P<cmd>.+?)(?P=prompt) ?(?P=cmd)\s*$")
_METHOD_CALLS = {
    "show settings administrators general": "v2.core.administrator.config.get",
    "show network zone": "v1.netmanager.zones.list",
    "show network-policy firewall": "v1.firewall.rules.list",
}
_ZONE_CMD = re.compile(r"^show network zone(?: (.+))?$")
_SCHEMES = ("http", "https")
_DEFAULT_ORDER = ("xmlrpc", "ssh-exec", "ssh-interactive")


class UserGateError(probes.ProbeError):
    """Команда или канал UserGate не дали данных. Для проб это тот же отказ, что ProbeError."""


def scrub(text, secrets):
    """Убирает пароль и токен сессии из текста, который может попасть в журнал или свидетельство."""
    out = text or ""
    for secret in secrets:
        if secret and len(secret) >= 4:
            out = out.replace(secret, "***")
    return out


def clean_stream(text):
    """Поток терминала без ANSI, CR и предупреждения CPR. `--more--` остаётся: по нему шлётся пробел."""
    text = _ANSI.sub("", text.replace("\r", ""))
    return text.replace(_CPR, "")


def clean_terminal(text):
    """Законченный вывод: то же, что clean_stream, плюс вырезанный маркер листания."""
    return clean_stream(text).replace(_MORE, "")


def command_failed(text):
    """Первая непустая строка `Error:` — команда не выполнилась (код ssh при этом всё равно 255)."""
    for line in (text or "").splitlines():
        if line.strip():
            return line.strip().startswith("Error:")
    return False


def normalize_exec_output(data):
    """Вывод одного SSH exec: байты фикстуры или устройства → текст без ANSI и без пустой первой строки."""
    if isinstance(data, bytes):
        text = data.decode("utf-8", "replace")
    else:
        text = data
    text = clean_terminal(text)
    if text.startswith("\n"):
        text = text[1:]
    return text


def _prompt_mode(line):
    marks = list(re.finditer(r"[>#]", line))
    return marks[-1].group(0) if marks else None


def extract_command_output(chunk, command):
    """Текст ответа между эхом команды и следующим приглашением.

    UserGate перерисовывает строку: `Admin@h#cmdAdmin@h# cmd`, затем тело, затем приглашение.
    Эхо и приглашение в результат не входят."""
    lines = clean_terminal(chunk).splitlines()
    while lines and (not lines[-1].strip() or _PROMPT_LINE.match(lines[-1].strip())):
        lines.pop()
    while lines:
        stripped = lines[0].strip()
        if not stripped or _PROMPT_LINE.match(stripped):
            lines.pop(0)
            continue
        echo = _ECHO_LINE.match(stripped)
        if echo and echo.group("cmd") == command:
            lines.pop(0)
            continue
        if stripped.endswith(command) and "@" in stripped:
            lines.pop(0)
            continue
        break
    body = "\n".join(lines)
    return (body + "\n") if body else ""


def iter_session_commands(text):
    """Пары (команда, тело) из уже очищенного транскрипта интерактивного сеанса."""
    lines = clean_terminal(text).splitlines()
    found = []
    for index, line in enumerate(lines):
        match = _ECHO_LINE.match(line.strip())
        if match:
            found.append((index, match.group("cmd")))
    for number, (index, command) in enumerate(found):
        end = found[number + 1][0] if number + 1 < len(found) else len(lines)
        body = []
        for line in lines[index + 1:end]:
            if _PROMPT_LINE.match(line.strip()):
                continue
            body.append(line)
        yield command, "\n".join(body).strip("\n")


def _on(value):
    return "on" if value in (True, 1, "1", "on", "true", "True") else "off"


def _addresses(allowed):
    """Пустой список в XML-RPC на заводской 7.4.1 — это `Any` в CLI, а не «никому»."""
    if not allowed:
        return "Any"
    parts = []
    for item in allowed:
        if isinstance(item, (list, tuple)):
            parts.append(":".join(str(part) for part in item))
        else:
            parts.append(str(item))
    return ", ".join(parts)


def _service_name(service_id):
    return SERVICE_NAMES.get(service_id, "service-{0}".format(service_id))


def render_version(version):
    version = str(version or "").strip()
    if not version:
        return ""
    return "UGOS NGFW {0}\n".format(version)


def render_admin(config):
    """v2.core.administrator.config.get → текст как у `show settings administrators general`."""
    fields = (
        ("strong_pwd", "strong-password", _on),
        ("block_time", "block-time", str),
        ("min_length", "min-length", str),
        ("min_uppercase", "min-uppercase", str),
        ("min_lowercase", "min-lowercase", str),
        ("min_digit", "min-digits", str),
        ("min_special", "spec-characters", str),
        ("max_char_repetition", "char-repetition", str),
        ("n_of_invalid_auth", "num-auth-attempts", str),
    )
    lines = []
    for key, label, convert in fields:
        if key in config and config[key] is not None:
            lines.append("{0}: {1}".format(label, convert(config[key])))
    return ("\n".join(lines) + "\n") if lines else ""


def _dos_block(profiles, kind):
    found = next((item for item in profiles or [] if item.get("kind") == kind), {})
    return (
        "dos-protection-{0}:\n"
        "    enabled: {1}\n"
        "    aggregate: {2}\n"
        "    alert-threshold: {3}\n"
        "    drop-threshold: {4}"
    ).format(kind, _on(found.get("enabled")), _on(found.get("aggregate")),
             found.get("alert_threshold", 0), found.get("drop_threshold", 0))


def render_zone_body(zone):
    services = [item for item in zone.get("services_access") or [] if item.get("enabled")]
    services.sort(key=lambda item: item.get("service_id") or 0)
    lines = [
        "name: {0}".format(zone.get("name", "")),
        "antispoof-enable: {0}".format(_on(zone.get("enable_antispoof"))),
        "antispoof-negate: {0}".format(_on(zone.get("antispoof_invert"))),
    ]
    for kind in ("syn", "udp", "icmp"):
        lines.append(_dos_block(zone.get("dos_profiles"), kind))
    lines.append("services-access:")
    for item in services:
        lines.append("    service: {0}".format(_service_name(item.get("service_id"))))
        lines.append("    allowed-addresses: {0}".format(_addresses(item.get("allowed_ips"))))
        lines.append("    enabled: on")
    return "\n".join(lines)


def render_zones(zones, name=None):
    """Список зон → вывод `show network zone` или одной зоны.

    Все зоны — с заголовком (имя на колонке 0, поля с отступом): так устроен вывод без
    аргумента, и по отступам считает cli_blocks. Одна зона — поля с первой колонки, как
    `show network zone Untrusted` на устройстве."""
    if name:
        for zone in zones:
            if zone.get("name") == name:
                return render_zone_body(zone) + "\n"
        return "Error: zone {0}\n".format(name)
    parts = []
    for zone in zones:
        title = str(zone.get("name") or "")
        body = "\n".join("    " + line if line else "" for line in render_zone_body(zone).splitlines())
        parts.append(title + "\n" + body)
    return ("\n".join(parts) + "\n") if parts else ""


def _zone_value(names):
    if len(names) == 1:
        return '"{0}"'.format(names[0]) if re.search(r"\s", names[0]) else names[0]
    return "(" + ", ".join(names) + ")"


def render_firewall(rules, zones):
    """v1.firewall.rules.list → текст как у `show network-policy firewall` (PASS/DENY, не accept/drop)."""
    by_id = {zone.get("id"): zone.get("name") or str(zone.get("id")) for zone in zones}
    blocks = []
    for index, rule in enumerate(rules, start=1):
        action = "PASS" if str(rule.get("action") or "").lower() in ("accept", "pass") else "DENY"
        lines = ["% ----------------- {0} -----------------".format(index), action + " \\"]
        for key, field in (("src.zone", "src_zones"), ("dst.zone", "dst_zones")):
            ids = rule.get(field) or []
            if ids:
                lines.append("    {0} = {1} \\".format(key, _zone_value([by_id.get(item, str(item)) for item in ids])))
        if rule.get("src_ips"):
            lines.append("    src.ip = restricted \\")
        if rule.get("dst_ips"):
            lines.append("    dst.ip = restricted \\")
        if rule.get("services"):
            lines.append("    service = restricted \\")
        enabled = "true" if rule.get("enabled") else "false"
        lines.append("    enabled({0}) \\".format(enabled))
        title = str(rule.get("name") or "").replace('"', "'")
        lines.append('    name("{0}")'.format(title))
        blocks.append("\n".join(lines))
    return ("\n".join(blocks) + "\n") if blocks else ""


def allowed_methods(declared):
    """Пересечение объявленного паком списка с белым списком агента. Методы записи отбрасываются."""
    allowed = []
    for name in declared or []:
        if name in USERGATE_READONLY_METHODS and not _WRITE_METHOD.search(name) and name not in allowed:
            allowed.append(name)
    return allowed


def load_config(path):
    """JSON цели. Пароля в нём быть не должно: только путь к файлу с правами 0600."""
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError) as exc:
        raise ValueError("файл цели UserGate не читается: {0}".format(exc)) from exc
    if not isinstance(data, dict):
        raise ValueError("файл цели UserGate: ожидается объект JSON")
    if any(key in data for key in ("password", "pass", "secret")):
        raise ValueError("пароль не храните в файле цели — укажите password_file с правами 0600")
    host = data.get("host")
    if not isinstance(host, str) or not probes._HOST_RE.match(host):
        raise ValueError("в файле цели недопустимое поле host")
    user = data.get("user") or "Admin"
    if not probes._USER_RE.match(user):
        raise ValueError("в файле цели недопустимое поле user")
    password_file = data.get("password_file")
    if not isinstance(password_file, str) or not password_file or password_file.startswith("-"):
        raise ValueError("в файле цели нужен password_file — путь к файлу пароля")
    check_secret_file(password_file)
    scheme = data.get("xmlrpc_scheme") or "http"
    if scheme not in _SCHEMES:
        raise ValueError("xmlrpc_scheme: http или https")
    order = data.get("methods") or list(_DEFAULT_ORDER)
    if not isinstance(order, list) or not order or any(item not in _DEFAULT_ORDER for item in order):
        raise ValueError("methods: непустой список из xmlrpc, ssh-exec, ssh-interactive")
    known_hosts = data.get("known_hosts")
    if known_hosts is not None and (not isinstance(known_hosts, str) or "\n" in known_hosts or known_hosts.startswith("-")):
        raise ValueError("known_hosts: путь к файлу ключей хостов")
    hostname = data.get("hostname")
    if hostname is not None and (not isinstance(hostname, str) or not probes._HOST_RE.match(hostname)):
        raise ValueError("в файле цели недопустимое поле hostname")

    def port(name, default):
        value = data.get(name, default)
        if not isinstance(value, int) or not 1 <= value <= 65535:
            raise ValueError("{0}: порт 1–65535".format(name))
        return value

    return {
        "host": host,
        "user": user,
        "hostname": hostname or host,
        "password_file": password_file,
        "ssh_port": port("ssh_port", 2200),
        "xmlrpc_port": port("xmlrpc_port", 4040),
        "xmlrpc_scheme": scheme,
        "known_hosts": known_hosts,
        "methods": list(order),
        "connect_timeout": port("connect_timeout", 10) if "connect_timeout" in data else 10,
        "command_timeout": port("command_timeout", 30) if "command_timeout" in data else 30,
    }


def check_secret_file(path):
    """Файл пароля существует, это не ссылка, и на POSIX его не читает группа и остальные."""
    if os.path.islink(path) or not os.path.isfile(path):
        raise ValueError("нет файла пароля {0} (нужен обычный файл, не ссылка)".format(path))
    if os.name != "nt":
        mode = os.stat(path).st_mode
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise ValueError("файл пароля {0} доступен не только владельцу — нужны права 0600".format(path))


def _read_password(path):
    check_secret_file(path)
    with open(path, encoding="utf-8") as handle:
        lines = handle.read().splitlines()
    if not lines or not lines[0]:
        raise ValueError("файл пароля {0} пуст".format(path))
    return lines[0]


class _TimeoutTransport(xmlrpc.client.Transport):
    def __init__(self, timeout):
        xmlrpc.client.Transport.__init__(self)
        self._timeout = timeout

    def make_connection(self, host):
        connection = xmlrpc.client.Transport.make_connection(self, host)
        connection.timeout = self._timeout
        return connection


class PipeReader:
    """Чтение канала в фоне: select() на Windows не работает с трубами ssh.

    BufferedReader.read(n) у трубы subprocess ждёт n байт или EOF. Короткое приглашение
    `ssh -tt` (канал не закрывается) так не приходит никогда, и сеанс отваливается по таймауту.
    read1 делает один read() сырого fd и отдаёт то, что уже есть."""

    def __init__(self, stream):
        self.stream = stream
        self.buf = b""
        self.eof = False
        self.cv = threading.Condition()
        self.thread = threading.Thread(target=self._run)
        self.thread.daemon = True
        self.thread.start()

    def _run(self):
        try:
            while True:
                # Фейковые трубы тестов отдают кусок из read(); у настоящего Popen есть read1.
                data = self.stream.read1(65536) if hasattr(self.stream, "read1") else self.stream.read(65536)
                with self.cv:
                    if not data:
                        self.eof = True
                        self.cv.notify_all()
                        return
                    self.buf += data
                    self.cv.notify_all()
        except Exception:
            with self.cv:
                self.eof = True
                self.cv.notify_all()

    def read_available(self, timeout):
        with self.cv:
            if not self.buf and not self.eof:
                self.cv.wait(timeout)
            data, self.buf = self.buf, b""
            return data, self.eof


def read_ssh_stdout(proc, idle=1.5, overall=30):
    """Читает stdout, не закрывая stdin, пока сервер сам не закроет канал.

    Закрытый сразу stdin UserGate воспринимает как конец команды до того, как она
    успеет ответить, и отдаёт пустой вывод (код 255). stdin закрывается только если
    байты уже пошли и дальше тишина дольше idle — тогда дочитывается хвост.
    """
    out_reader = PipeReader(proc.stdout)
    err_reader = PipeReader(proc.stderr) if proc.stderr is not None else None
    started = time.monotonic()
    last_change = None
    last_len = 0
    chunks = []
    while True:
        data, eof = out_reader.read_available(0.1)
        if data:
            chunks.append(data)
        size = sum(len(part) for part in chunks)
        now = time.monotonic()
        if size != last_len:
            last_len = size
            last_change = now
        if eof:
            break
        if last_change is not None and now - last_change >= idle:
            _close_stdin(proc)
            rest, _eof = out_reader.read_available(max(0.2, overall - (now - started)))
            if rest:
                chunks.append(rest)
            break
        if now - started > overall:
            _terminate(proc)
            break
    err = b""
    if err_reader is not None:
        err, _eof = err_reader.read_available(0.2)
    try:
        proc.wait(timeout=3)
    except Exception:
        _terminate(proc)
    return b"".join(chunks), err


def _close_stdin(proc):
    try:
        if proc.stdin is not None and not proc.stdin.closed:
            proc.stdin.close()
    except Exception:
        pass


def _terminate(proc):
    try:
        proc.kill()
    except Exception:
        pass
    try:
        proc.wait(timeout=2)
    except Exception:
        pass


def _askpass_script(directory, password_file):
    """Программа для SSH_ASKPASS. Пароль читается из файла, в argv и в окружение ssh он не попадает."""
    if os.name == "nt":
        path = os.path.join(directory, "hardening-askpass.cmd")
        body = (
            "@echo off\r\n"
            "\"{py}\" -c \"import os,sys; lines=open(os.environ['HARDENING_SSH_PASS_FILE'],encoding='utf-8').read().splitlines(); "
            "sys.stdout.write((lines[0] if lines else '')+'\\n')\"\r\n"
        ).format(py=sys.executable)
    else:
        path = os.path.join(directory, "hardening-askpass")
        body = "#!/bin/sh\nIFS= read -r pw < \"$HARDENING_SSH_PASS_FILE\" || exit 1\nprintf '%s\\n' \"$pw\"\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o700)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(body)
    os.chmod(path, 0o700)
    return path


class InteractiveSession:
    """Сеанс `ssh -tt`: строка уходит только после приглашения, `--more--` листается пробелом."""

    def __init__(self, proc, timeout):
        self.proc = proc
        self.timeout = timeout
        self.reader = PipeReader(proc.stdout)
        self.buf = ""
        self.mode = None

    def wait_prompt(self, after=0):
        """Ждёт приглашение, которое начинается не раньше `after`.

        Иначе сразу после отправки команды буфер ещё кончается предыдущим приглашением,
        и ответ устройства мы бы не дождались."""
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            if self._consume_more():
                continue
            span = self._prompt_span()
            if span and span[0] >= after:
                self.mode = span[1]
                return
            remaining = deadline - time.monotonic()
            data, eof = self.reader.read_available(min(0.2, max(0.01, remaining)))
            if data:
                self.buf += clean_stream(data.decode("utf-8", "replace"))
            elif eof and not (span and span[0] >= after):
                break
        raise UserGateError("нет приглашения CLI UserGate")

    def _consume_more(self):
        if _MORE not in self.buf:
            return False
        self.buf = self.buf.replace(_MORE, "")
        self._write(" ")
        return True

    def _prompt_span(self):
        """(индекс начала, режим) приглашения в конце буфера, либо None."""
        if not self.buf:
            return None
        if self.buf.endswith("\n"):
            body = self.buf.rstrip("\n")
            start = body.rfind("\n") + 1
            line = body[start:]
        else:
            start = self.buf.rfind("\n") + 1
            line = self.buf[start:]
        if line.strip() and _PROMPT_LINE.match(line.strip()):
            return start, _prompt_mode(line.strip())
        return None

    def _write(self, text):
        self.proc.stdin.write(text.encode("utf-8"))
        self.proc.stdin.flush()

    def _ensure(self, want):
        if self.mode == want:
            return
        mark = len(self.buf)
        self._write(("configure" if want == "#" else "exit") + "\n")
        self.wait_prompt(after=mark)
        if self.mode != want:
            raise UserGateError("не удалось переключить режим CLI UserGate")

    def run(self, command):
        if self.mode is None:
            self.wait_prompt()
        # `show system version` живёт только в операционном режиме (`>`); остальные show — после configure.
        self._ensure(">" if command == "show system version" else "#")
        mark = len(self.buf)
        self._write(command + "\n")
        self.wait_prompt(after=mark)
        text = extract_command_output(self.buf[mark:], command)
        if command_failed(text):
            first = next(line.strip() for line in text.splitlines() if line.strip())
            raise UserGateError("устройство вернуло ошибку: {0}".format(first[:200]))
        if not text.strip():
            raise UserGateError("пустой вывод команды {0}".format(command))
        return text


class UserGateTransport:
    """Транспорт паков `ssh`: те же пробы cli_config, источник — живой UserGate.

    name остаётся `ssh`, чтобы подошли сетевые паки. Учётные данные в отчёт не попадают.
    """

    name = "ssh"
    platform = "network"

    def __init__(self, config, popen=None, rpc_call=None):
        self.config = config
        self.host = config["host"]
        self.user = config["user"]
        self.destination = "{0}@{1}".format(config["user"], config["host"])
        self.asset_hostname = config.get("hostname") or config["host"]
        self.asset_ip = config["host"] if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", config["host"]) else None
        self.order = list(config.get("methods") or _DEFAULT_ORDER)
        self.connect_timeout = config.get("connect_timeout", 10)
        self.command_timeout = config.get("command_timeout", 30)
        self._popen = popen or subprocess.Popen
        self._rpc_call = rpc_call
        self._password = None
        self._allowed = []
        self._bound = False
        self._mode = None
        self._errors = []
        self._cache = {}
        self._version = None
        self._token = None
        self._zone_list = None
        self._rules = None
        self._proxy = None
        self._session = None
        self._proc = None
        self._askpass_dir = None
        self._reported = False

    def bind_manifests(self, manifests):
        """Белый список методов — из подписанных манифестов, пересечённый с набором агента."""
        declared = []
        for manifest in manifests or []:
            declared.extend(manifest.get("xmlrpc_methods") or [])
        self._allowed = allowed_methods(declared)
        self._bound = True

    def close(self):
        if self._token and "v2.core.logout" in self._allowed:
            try:
                self._call("v2.core.logout", (self._token,))
            except Exception:
                pass
        self._token = None
        if self._proc is not None:
            try:
                if self._session is not None and self._proc.stdin and not self._proc.stdin.closed:
                    self._proc.stdin.write(b"exit\n")
                    self._proc.stdin.flush()
            except Exception:
                pass
            _terminate(self._proc)
            self._proc = None
        if self._askpass_dir:
            shutil.rmtree(self._askpass_dir, ignore_errors=True)
            self._askpass_dir = None
        self._password = None

    def run_cli(self, command):
        if not probes.is_readonly_cli(command):
            raise UserGateError("по SSH допустимы только команды на чтение: {0!r}".format(command))
        if command in self._cache:
            return self._cache[command]
        self._ensure_mode()
        if command in self._cache:
            return self._cache[command]
        errors = []
        modes = [self._mode] + [mode for mode in self.order if mode != self._mode]
        for mode in modes:
            if mode == "xmlrpc" and not self._rpc_supports(command):
                continue
            try:
                text = self._run(mode, command)
            except UserGateError as exc:
                errors.append("{0}: {1}".format(mode, scrub(str(exc), self._secrets())))
                continue
            if not str(text).strip():
                errors.append("{0}: пустой вывод".format(mode))
                continue
            output = probes.CmdOutput(text if text.endswith("\n") else text + "\n", "", 0)
            self._cache[command] = output
            return output
        raise UserGateError("команда {0!r} не выполнилась: {1}".format(command, "; ".join(errors) or "нет способа доступа"))

    def run(self, argv):
        return self.run_cli(" ".join(argv))

    def read_file(self, path):
        raise UserGateError("файловые пробы недоступны на UserGate")

    def stat_file(self, path):
        raise UserGateError("file_stat недоступна на UserGate")

    def read_registry(self, key, name):
        raise UserGateError("реестр недоступен на UserGate")

    def secpol(self):
        raise UserGateError("политика безопасности Windows недоступна на UserGate")

    def auditpol(self):
        raise UserGateError("политика аудита Windows недоступна на UserGate")

    def _secrets(self):
        return [item for item in (self._password, self._token) if item]

    def _ensure_mode(self):
        if self._mode:
            return
        errors = []
        for mode in self.order:
            try:
                self._probe(mode)
            except UserGateError as exc:
                errors.append("{0}: {1}".format(mode, scrub(str(exc), self._secrets())))
                continue
            self._mode = mode
            if not self._reported:
                self._reported = True
                print("UserGate {0}: способ доступа {1}".format(self.host, mode), file=sys.stderr)
            return
        raise UserGateError("UserGate {0}: ни один способ доступа не сработал: {1}".format(self.host, "; ".join(errors)))

    def _probe(self, mode):
        if mode == "xmlrpc":
            self._connect_xmlrpc()
            return
        if mode == "ssh-exec":
            text = self._run_exec("show settings administrators general")
            if command_failed(text) or not text.strip():
                raise UserGateError("SSH exec не вернул конфигурацию")
            self._cache["show settings administrators general"] = probes.CmdOutput(text, "", 0)
            return
        if mode == "ssh-interactive":
            self._connect_interactive()
            return
        raise UserGateError("неизвестный способ {0}".format(mode))

    def _run(self, mode, command):
        if mode == "xmlrpc":
            return self._run_xmlrpc(command)
        if mode == "ssh-exec":
            text = self._run_exec(command)
            if command_failed(text):
                first = next(line.strip() for line in text.splitlines() if line.strip())
                raise UserGateError("устройство вернуло ошибку: {0}".format(first[:200]))
            return text
        if mode == "ssh-interactive":
            self._connect_interactive()
            return self._session.run(command)
        raise UserGateError("неизвестный способ {0}".format(mode))

    def _rpc_supports(self, command):
        if not self._bound or "v2.core.login" not in self._allowed:
            return False
        if command == "show system version":
            return True
        if command in _METHOD_CALLS:
            return _METHOD_CALLS[command] in self._allowed
        match = _ZONE_CMD.match(command)
        return bool(match) and "v1.netmanager.zones.list" in self._allowed

    def _connect_xmlrpc(self):
        if self._token:
            return
        if not self._bound:
            raise UserGateError("белый список XML-RPC не задан манифестом пака")
        if "v2.core.login" not in self._allowed or "v2.core.logout" not in self._allowed:
            raise UserGateError("пак не разрешает v2.core.login и v2.core.logout")
        if self._password is None:
            self._password = _read_password(self.config["password_file"])
        try:
            result = self._call("v2.core.login", (self.user, self._password, {"origin": "hardening-agent"}))
        except UserGateError:
            raise
        except Exception as exc:
            raise UserGateError("XML-RPC login: {0}".format(scrub(str(exc), self._secrets()))) from exc
        if not isinstance(result, dict) or not result.get("auth_token"):
            raise UserGateError("XML-RPC login не вернул сессию")
        self._token = str(result["auth_token"])
        self._version = str(result.get("version") or "").strip()
        if not self._version and "v2.core.license.info" in self._allowed:
            info = self._call("v2.core.license.info", (self._token,))
            if isinstance(info, dict):
                self._version = str(info.get("version") or "").strip()

    def _call(self, method, args):
        if method not in self._allowed or method not in USERGATE_READONLY_METHODS or _WRITE_METHOD.search(method):
            raise UserGateError("метод XML-RPC не в белом списке чтения: {0}".format(method))
        try:
            if self._rpc_call is not None:
                return self._rpc_call(method, args)
            proxy = self._proxy
            if proxy is None:
                url = "{0}://{1}:{2}/rpc".format(
                    self.config.get("xmlrpc_scheme") or "http", self.host, self.config.get("xmlrpc_port") or 4040)
                transport = _TimeoutTransport(self.connect_timeout)
                proxy = xmlrpc.client.ServerProxy(url, transport=transport, allow_none=True)
                self._proxy = proxy
            target = proxy
            for part in method.split("."):
                target = getattr(target, part)
            return target(*args)
        except xmlrpc.client.Fault as exc:
            raise UserGateError("XML-RPC {0}: {1}".format(method, scrub(str(exc.faultString), self._secrets()))) from exc
        except UserGateError:
            raise
        except Exception as exc:
            raise UserGateError("XML-RPC {0}: {1}".format(method, scrub(str(exc), self._secrets()))) from exc

    def _load_zones(self):
        if self._zone_list is None:
            data = self._call("v1.netmanager.zones.list", (self._token,))
            if not isinstance(data, list):
                raise UserGateError("XML-RPC zones.list вернул не список")
            self._zone_list = data
        return self._zone_list

    def _firewall(self):
        if self._rules is not None:
            return self._rules
        items = []
        start = 0
        while start < 1000:
            page = self._call("v1.firewall.rules.list", (self._token, start, 100, {}))
            if isinstance(page, dict):
                batch = page.get("items") or []
                total = page.get("count", len(batch))
            elif isinstance(page, list):
                batch, total = page, len(page)
            else:
                raise UserGateError("XML-RPC firewall.rules.list вернул неожиданный ответ")
            items.extend(batch)
            start += 100
            if not batch or start >= total:
                break
        self._rules = items
        return items

    def _run_xmlrpc(self, command):
        self._connect_xmlrpc()
        if command == "show system version":
            text = render_version(self._version)
            if not text.strip():
                raise UserGateError("XML-RPC login не вернул версию ПО")
            return text
        if command == "show settings administrators general":
            data = self._call("v2.core.administrator.config.get", (self._token,))
            if not isinstance(data, dict):
                raise UserGateError("XML-RPC administrator.config.get вернул не объект")
            return render_admin(data)
        match = _ZONE_CMD.match(command)
        if match and command.startswith("show network zone"):
            zones = self._load_zones()
            text = render_zones(zones, match.group(1))
            if text.startswith("Error:"):
                raise UserGateError(text.strip()[:200])
            return text
        if command == "show network-policy firewall":
            return render_firewall(self._firewall(), self._load_zones())
        raise UserGateError("команда не сопоставлена с методом XML-RPC только на чтение")

    def _ssh_env(self):
        check_secret_file(self.config["password_file"])
        if self._askpass_dir is None:
            self._askpass_dir = tempfile.mkdtemp(prefix="hardening-ug-")
            os.chmod(self._askpass_dir, 0o700)
            self._askpass = _askpass_script(self._askpass_dir, self.config["password_file"])
        env = os.environ.copy()
        env["SSH_ASKPASS"] = self._askpass
        env["SSH_ASKPASS_REQUIRE"] = "force"
        env["HARDENING_SSH_PASS_FILE"] = self.config["password_file"]
        env.setdefault("DISPLAY", ":0")
        # Пароль в окружение не кладётся: askpass читает файл сам.
        return env

    def _ssh_argv(self, command, tty):
        argv = ["ssh", "-tt" if tty else "-T",
                "-o", "StrictHostKeyChecking=yes",
                "-o", "PreferredAuthentications=keyboard-interactive,password",
                "-o", "NumberOfPasswordPrompts=1",
                "-o", "PubkeyAuthentication=no",
                "-o", "ConnectTimeout={0}".format(self.connect_timeout),
                "-p", str(self.config.get("ssh_port") or 2200)]
        if self.config.get("known_hosts"):
            argv += ["-o", "UserKnownHostsFile={0}".format(self.config["known_hosts"])]
        argv += ["--", self.destination]
        if command is not None:
            argv.append(command)
        return argv

    def _popen_ssh(self, command, tty):
        try:
            return self._popen(
                self._ssh_argv(command, tty),
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=self._ssh_env(),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise UserGateError("SSH не запустился: {0}".format(exc)) from exc

    def _run_exec(self, command):
        proc = self._popen_ssh(command, tty=False)
        try:
            stdout, stderr = read_ssh_stdout(proc, idle=1.5, overall=self.command_timeout)
        except Exception as exc:
            _terminate(proc)
            raise UserGateError("SSH exec: {0}".format(exc)) from exc
        text = normalize_exec_output(stdout)
        if text.strip():
            return text
        err = normalize_exec_output(stderr).strip()
        raise UserGateError(scrub(err[:200] or "пустой вывод SSH (соединение закрыто до ответа)", self._secrets()))

    def _connect_interactive(self):
        if self._session is not None:
            return
        proc = self._popen_ssh(None, tty=True)
        self._proc = proc
        self._session = InteractiveSession(proc, self.command_timeout)
        try:
            self._session.wait_prompt()
        except UserGateError:
            _terminate(proc)
            self._proc = None
            self._session = None
            raise

