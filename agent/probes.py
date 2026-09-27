"""Движок проб агента «Харденинг»: выполняет пробы из манифеста пака.

Зависимости: только стандартная библиотека Python 3.9+ (как и collector.py).

Агент — последний рубеж защиты и не доверяет манифесту слепо, даже подписанному:
  * выполняются только типы проб из закрытого списка PROBES, и только на чтение;
  * локальные команды — только из белого списка LOCAL_COMMAND_POLICY, без shell (argv);
  * файловые пробы не читают секреты (DENIED_PATH_PATTERNS), символические ссылки
    разворачиваются до проверки; права файла проверяются через file_stat без чтения содержимого;
  * по SSH выполняются только команды на чтение (is_readonly_cli);
  * подпись манифеста (HMAC-SHA256) проверяется до выполнения чего-либо.

Ограничение подписи: ключ симметричный, им же проверяет агент, поэтому компрометация
хоста с агентом раскрывает ключ подписи. Ключ подписи должен быть отдельным от ключа
агента и своим на организацию; при желании схема заменяется на асимметричную
(Ed25519) без изменения формата манифеста.
"""
from __future__ import annotations

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
MAX_FILE_BYTES = 2_000_000
COMMAND_TIMEOUT = 15
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
    expected = hmac.new(key.encode("utf-8"), canonical_json(manifest), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature or "")


def load_verified_manifests(response: dict, key: str) -> list[dict]:
    """Проверяет подпись каждого манифеста из ответа сервера. Любая подделка — ManifestError:
    это событие безопасности, а не повод молча пропустить один пак."""
    verified = []
    for item in response.get("manifests", []):
        manifest, signature = item.get("manifest"), item.get("signature")
        if not isinstance(manifest, dict) or not verify_manifest(manifest, signature, key):
            name = manifest.get("pack") if isinstance(manifest, dict) else "?"
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
    # Windows: состояние службы (sc query <имя>); вывод sc не локализуется, состояние — числом и константой
    "sc": re.compile(r"^query [A-Za-z0-9_.-]+$"),
    # только список запущенных контейнеров и одно поле inspect по конкретному id из закрытого списка
    # полей (docker.yaml, проверки СКО.1.2/1.3/1.5/1.6 по методике ФСТЭК); run/exec/rm и т.п. — отказ
    "docker": re.compile(
        r"^(ps -q|inspect --format \{\{(\.HostConfig\.Privileged|\.HostConfig\.Binds|\.Config\.User"
        r"|\.HostConfig\.Memory|\.HostConfig\.NanoCpus|\.HostConfig\.NetworkMode|\.HostConfig\.PidMode)"
        r"\}\} [a-f0-9]{6,64})$"
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


CLI_FILTERS = ("include", "exclude", "begin", "section", "count", "match", "except")
_CLI_SEGMENT = re.compile(r"^[A-Za-z0-9 _./^:\-]+$")
_CLI_READONLY = re.compile(r"^(show|display) [A-Za-z0-9 _./^:\-]+$|^/export( [A-Za-z0-9 _./=\-]+)?$|^/[a-z0-9/ -]+ print( [A-Za-z0-9 _./=\-]+)?$")
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
        self._secpol = self._auditpol = None  # кэш на прогон: экспорт дорогой и одинаков для всех проверок

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

    def glob(self, pattern: str) -> list[str]:
        """Файлы по маске в лексическом порядке; запрещённые политикой пути в выдачу не попадают."""
        found = sorted(glob.glob(pattern))[:MAX_INCLUDE_FILES]
        return [p for p in found if not any(d.search(p) or d.search(os.path.realpath(p)) for d in DENIED_PATH_PATTERNS)]

    def run(self, argv: list[str]) -> CmdOutput:
        policy = LOCAL_COMMAND_POLICY.get(argv[0]) if argv else None
        if policy is None or not policy.match(" ".join(argv[1:])):
            raise ProbeError(f"команда вне белого списка агента: {' '.join(argv)}")
        return self._execute(argv)

    def _execute(self, argv: list[str]) -> CmdOutput:
        """Запуск без shell из системного каталога. Команды из манифеста попадают сюда только через run()
        (белый список); secedit и auditpol с фиксированными аргументами агент вызывает сам."""
        search = WINDOWS_SYSTEM32 if IS_WINDOWS else SAFE_PATH
        exe = shutil.which(argv[0], path=search)
        if exe is None:
            raise ProbeError(f"команда {argv[0]} не найдена")
        env = ({"SystemRoot": os.environ.get("SystemRoot", r"C:\Windows"), "PATH": WINDOWS_SYSTEM32,
                "TEMP": tempfile.gettempdir(), "TMP": tempfile.gettempdir()}
               if IS_WINDOWS else {"PATH": SAFE_PATH, "LANG": "C", "LC_ALL": "C"})
        try:
            proc = subprocess.run(
                [exe, *argv[1:]], capture_output=True, text=True, timeout=COMMAND_TIMEOUT,
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
        fd, path = tempfile.mkstemp(prefix="hardening-", suffix=".tmp")
        os.close(fd)
        try:
            out = self._execute(build_argv(path))
            if out.code != 0:
                raise ProbeError(f"{what}: код {out.code} (нужны права администратора?) {out.text.strip()[:150]}")
            raw = open(path, "rb").read()
        finally:
            try:
                os.remove(path)
            except OSError:
                pass
        for encoding in ("utf-16", "utf-8-sig", "cp1251"):
            try:
                return raw.decode(encoding)
            except UnicodeDecodeError:
                continue
        raise ProbeError(f"{what}: не удалось прочитать результат")

    def secpol(self) -> dict:
        if self._secpol is None:
            self._secpol = parse_secedit(self._export(
                lambda path: ["secedit", "/export", "/cfg", path, "/areas", "SECURITYPOLICY", "/quiet"],
                "экспорт политики безопасности"))
        return self._secpol

    def auditpol(self) -> dict:
        if self._auditpol is None:
            self._auditpol = parse_auditpol_backup(self._export(
                lambda path: ["auditpol", "/backup", f"/file:{path}"], "резервная копия политики аудита"))
        return self._auditpol

    def run_cli(self, command: str) -> CmdOutput:
        raise ProbeError("cli_config недоступна на локальном транспорте")


class SshTransport:
    """Внешний сбор с сетевого устройства по SSH. Учётка на устройстве — только на чтение,
    ключ/пароль вне пака. Проверка ключа хоста включена и не отключается: устройство должно
    быть в known_hosts (иначе это подмена устройства, а не повод продолжать)."""

    name = "ssh"

    def __init__(self, host: str, user: str | None = None, port: int = 22, key_path: str | None = None,
                 connect_timeout: int = 10, command_timeout: int = 30, runner=None):
        if not _HOST_RE.match(host) or (user is not None and not _USER_RE.match(user)):
            raise ValueError("недопустимое имя хоста или пользователя SSH")
        self.destination = f"{user}@{host}" if user else host
        self.port, self.key_path = port, key_path
        self.connect_timeout, self.command_timeout = connect_timeout, command_timeout
        self._runner = runner or subprocess.run

    def _ssh_argv(self, command: str) -> list[str]:
        argv = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                "-o", f"ConnectTimeout={self.connect_timeout}", "-p", str(self.port)]
        if self.key_path:
            argv += ["-i", self.key_path]
        return argv + ["--", self.destination, command]

    def run_cli(self, command: str) -> CmdOutput:
        if not is_readonly_cli(command):
            raise ProbeError(f"по SSH допустимы только команды на чтение: {command!r}")
        try:
            proc = self._runner(self._ssh_argv(command), capture_output=True, text=True,
                                timeout=self.command_timeout, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            raise ProbeError(f"SSH-команда не выполнилась: {exc}") from exc
        if proc.returncode == 255:  # код самого ssh: соединение/аутентификация/ключ хоста
            raise ProbeError(f"ssh: {(proc.stderr or '').strip()[:200] or 'ошибка соединения'}")
        return CmdOutput(proc.stdout, proc.stderr, proc.returncode)

    def run(self, argv: list[str]) -> CmdOutput:
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


# --- пробы -----------------------------------------------------------------------

def _ok(value, evidence: str | None = None) -> dict:
    return {"found": True, "value": value, "evidence": redact(evidence) if evidence else None}


def _search(pattern: str, text: str) -> tuple[str | None, str | None]:
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


def probe_cli_config(t, p: dict) -> dict:
    """Строка/раздел конфигурации устройства. Ответ устройства проверяется ДО разбора: при нехватке прав
    IOS отвечает `% Invalid input…` вместо конфигурации, и все проверки «параметра нет» ложно прошли бы
    на пустом выводе. Поэтому строка-ошибка `% …` — отказ пробы, а `require` (необязательно) задаёт признак
    настоящего вывода (например, завершающий `end` running-config)."""
    text = t.run_cli(p["cmd"]).stdout
    first = next((line for line in text.splitlines() if line.strip()), "")
    if re.match(r"\s*%\s", first):
        raise ProbeError(f"устройство вернуло ошибку: {first.strip()[:120]}")
    if p.get("require") and not re.search(p["require"], text, re.MULTILINE):
        raise ProbeError("вывод команды не похож на ожидаемый (нет прав на просмотр конфигурации или неверная команда)")
    lines = text.splitlines()
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
            return _ok(m.group(1) if m.groups() else line.strip(), line)
    return _ok(None)


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


def probe_service_state(t, p: dict) -> dict:
    if getattr(t, "platform", "posix") == "windows":
        return _windows_service_state(t, p)
    verb = "is-enabled" if p.get("field") == "enabled" else "is-active"
    out = t.run(["systemctl", verb, p["service"]])
    state = out.stdout.strip() or out.stderr.strip()
    if not state:
        raise ProbeError(f"systemctl не вернул состояние службы {p['service']}")
    return _ok(state.splitlines()[0])


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
    "service_state": probe_service_state,
    "pkg_version": probe_pkg_version,
    "first_of": probe_first_of,
    "reg_value": probe_reg_value,
    "win_secpol": probe_win_secpol,
    "win_auditpol": probe_win_auditpol,
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

def matches_detect(transport, detect_rules: list[dict]) -> bool:
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


def select_manifests(transport, manifests: list[dict]) -> list[dict]:
    return [m for m in manifests if m.get("transport") == transport.name and matches_detect(transport, m["detect"])]


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
