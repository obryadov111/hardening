"""Разбор одной выгрузки сетевого устройства на выводы команд пака.

Без зависимостей, кроме стандартной библиотеки: модуль грузит и агент (Python 3.6+),
и бэкенд. Ничего не исполняет и не ходит в сеть. Архивы только читаются, с отказом
на пути с ``..``, абсолютные имена и символические ссылки.

Форматы:
  * журнал сессии с приглашениями ``host#``, ``host>``, ``user@host:~$``;
  * бэкап Oxidized (``! Command: ...``) и RANCID (``!RANCID-CONTENT-TYPE:``);
  * один ``show running-config`` или вывод команды распознавания;
  * zip / tar / tar.gz с файлами ``offline_file_name``;
  * JSON выводов команд или JSON ЦУС Континент 4.
"""
from __future__ import print_function

import gzip
import io
import json
import os
import re
import stat
import tarfile
import zipfile

MAX_TEXT_BYTES = 5000000
MAX_ARCHIVE_ENTRIES = 30
MAX_MEMBER_BYTES = 5000000
MAX_UNPACKED_BYTES = 20000000

_KIND_LABEL = {
    "session": "журнал терминальной сессии",
    "oxidized": "бэкап Oxidized",
    "rancid": "бэкап RANCID",
    "archive": "архив файлов выгрузки",
    "json": "JSON Континент 4",
    "json-commands": "JSON с выводами команд",
    "blob": "один вывод команды или конфигурация",
    "fallback": "файл целиком как одна команда",
}

# (pack, command, all-of patterns, none-of patterns). More specific packs first.
_CONFIG_FINGERPRINTS = (
    ("s-terra-gate", "show running-config",
     (r"(?m)^[ \t]*version[ \t]+\d", r"(?m)^[ \t]*crypto isakmp policy[ \t]", r"(?i)gost"),
     ()),
    ("cisco-ios", "show running-config",
     (r"(?m)^[ \t]*version[ \t]+\d+\.\d+", r"(?m)^[ \t]*end[ \t]*$"),
     (r"(?m)^[ \t]*crypto isakmp policy[ \t]", r"(?i)gost")),
    ("eltex-esr", "show running-config",
     (r"(?m)^#!/usr/bin/clish",),
     ()),
    ("eltex-mes", "show running-config",
     (r"(?m)^[ \t]*passwords complexity enable\b",),
     ()),
    ("dionis-nx", "show running-config",
     (r"(?m)^[ \t]*service ssh[ \t]*$", r"(?m)^[ \t]*hostname[ \t]+\S"),
     ()),
    ("infowatch-arma-ngfw", "show configuration commands",
     (r"(?m)^[ \t]*set system login password minimum-length\b", r"(?m)^[ \t]*set service[ \t]"),
     ()),
)

# A whole file that is already the detect command's output, not a config.
_DETECT_BLOBS = (
    ("s-terra-gate", "show version", r"(?m)^S-Terra\s+\S+"),
    ("cisco-ios", "show version", r"(?im)^Cisco IOS(?: XE)? Software"),
    ("qtech-qsw", "show version", r"(?m)^[ \t]*QSW-\S+[ \t]+Device,[ \t]+Compiled"),
    ("snr-switch", "show version", r"(?m)^[ \t]*SNR-\S+[ \t]+Device,[ \t]+Compiled"),
    ("eltex-esr", "show system", r"System type:\s+Eltex\s+v?ESR"),
    ("eltex-mes", "show system", r"System Description:\s+MES"),
    ("dionis-nx", "show version", r"(?m)^[ \t]*Platform ID:\s*[0-9A-F]{4}(?:-[0-9A-F]{4}){4}\s*$"),
    ("infowatch-arma-ngfw", "show version", r"(?m)^Version:\s*NGFWOS"),
    ("vipnet-coordinator", "version", r"(?m)^Product:\s*ViPNet"),
    ("pt-ngfw", "show version", r"(?m)^[ \t]*Model:\s*pt-ngfw"),
    ("usergate-ngfw", "show system version", r"UGOS(?:\s+NGFW)?\s+\d+\.\d+"),
    ("usergate-ngfw", "show settings administrators general", r"(?m)^[ \t]*num-auth-attempts[ \t]*:"),
)

_AMBIGUOUS = (
    (("qtech-qsw", "snr-switch"), "show running-config",
     (r"(?m)^[ \t]*no telnet-server enable\b", r"(?m)^[ \t]*authentication securityip[ \t]"),
     "конфигурация похожа на Qtech или SNR: по одному файлу модель не выбрать, подтвердите пак"),
)

_PROMPT_RE = re.compile(
    r"(?:"
    r"\[[^\[\]\n]{1,80}\][$#]"
    r"|[A-Za-z0-9_.-]{1,32}@[A-Za-z0-9_.-]{1,64}:[^\s\n$#]{0,80}[$#]"
    r"|[A-Za-z0-9][A-Za-z0-9_.@()-]{0,78}[>#]"
    r")"
)
_MARKER_RE = re.compile(r"(?im)^[ \t]*[!#][ \t]*command:[ \t]*(.+?)\s*$")
_BRACKET_RE = re.compile(r"(?m)^\[([^\]\n]{1,200})\][ \t]*$")
_RANCID_RE = re.compile(r"(?m)^[ \t]*!RANCID-CONTENT-TYPE:[ \t]*(\S+)")
_MORE_LINE = re.compile(r"(?i)^[ \t]*-{2,}[ \t]*\(?[ \t]*more[ \t]*\)?[ \t]*-{2,}[ \t]*$")
_MORE_INLINE = re.compile(r"(?i)-{2,}[ \t]*\(?[ \t]*more[ \t]*\)?[ \t]*-{2,}")


class SplitError(Exception):
    """Файл нельзя разобрать: текст уже на русском и годится оператору."""


class SplitResult(object):
    def __init__(self, kind, mode, files, found, recognized_pack, ambiguous_packs, notes):
        self.kind = kind
        self.mode = mode
        self.files = files
        self.found = list(found)
        self.recognized_pack = recognized_pack
        self.ambiguous_packs = list(ambiguous_packs or [])
        self.notes = list(notes or [])

    def label(self):
        return _KIND_LABEL.get(self.kind, self.kind)


def offline_file_name(command):
    """То же имя, что ``probes.offline_file_name``: ``show running-config`` → ``show_running-config.txt``."""
    return re.sub(r"[^A-Za-z0-9.-]+", "_", command).strip("_") + ".txt"


def commands_in_manifests(manifests):
    """Команды detect, firmware и проверок из манифестов агента, без повторов."""
    commands = []

    def add(cmd):
        if isinstance(cmd, str) and cmd and cmd not in commands:
            commands.append(cmd)

    for manifest in manifests or []:
        for rule in manifest.get("detect") or []:
            add((rule.get("probe") or {}).get("cmd"))
        firmware = manifest.get("firmware") or {}
        for key in ("version_probe", "product_probe"):
            probe = firmware.get(key) or {}
            if isinstance(probe, dict):
                add(probe.get("cmd"))
        for check in manifest.get("checks") or []:
            add((check.get("probe") or {}).get("cmd"))
    return commands


def choose_declared(split, explicit, manifests):
    """Какой пак передать в select_manifests как declared.

    Возвращает ``(pack_or_None, recognized_by)``. ``recognized_by == "config"`` значит,
    что платформа узнана по тексту конфигурации и вывода команды detect в файле нет:
    вызывающий не должен помечать снимок как «пак наугад». Явный пак, который
    противоречит узнанной конфигурации, — ошибка.
    """
    detect = {}
    for manifest in manifests or []:
        cmds = []
        for rule in manifest.get("detect") or []:
            cmd = (rule.get("probe") or {}).get("cmd")
            if isinstance(cmd, str):
                cmds.append(cmd)
        detect[manifest.get("pack")] = cmds

    def present(pack):
        return any(cmd in split.files for cmd in detect.get(pack) or [])

    recog = split.recognized_pack if split.mode == "commands" else None
    known = {manifest.get("pack") for manifest in manifests or []}
    if recog not in known:
        recog = None
    if explicit and recog and explicit != recog and not present(recog):
        raise SplitError("по тексту конфигурации это {0}, а не {1}".format(recog, explicit))
    if explicit:
        # Пак назван оператором и тем же паком читается сама конфигурация — это не догадка.
        if recog and explicit == recog and not present(recog):
            return explicit, "config"
        return explicit, None
    if recog and not present(recog):
        return recog, "config"
    return None, None


def write_directory(split, directory, name_for_command):
    """Кладёт результат разбора в каталог для OfflineConfigTransport или Continent4Transport."""
    if split.mode == "json":
        for name, data in split.files.items():
            base = os.path.basename(str(name).replace("\\", "/"))
            if not base or base in (".", ".."):
                raise SplitError("в выгрузке небезопасное имя файла")
            _write(os.path.join(directory, base), data)
        return
    for command, data in split.files.items():
        _write(os.path.join(directory, name_for_command(command)), data)


def split_bytes(raw, commands, filename="", fallback_command=None):
    """Один файл → выводы команд (``mode=commands``) или JSON ЦУС (``mode=json``)."""
    if not isinstance(raw, (bytes, bytearray)):
        raise SplitError("файл выгрузки пустой")
    raw = bytes(raw)
    if len(raw) > MAX_TEXT_BYTES:
        raise SplitError("файл больше {0} байт".format(MAX_TEXT_BYTES))
    if not raw.strip():
        raise SplitError("файл пустой")
    filename = filename or ""
    return _split(raw, list(commands or []), filename, fallback_command, 0)


def match_command(typed, commands):
    """Сокращение Cisco (``sh run``, ``sh ver``) → каноническая команда из списка.

    Неоднозначное сокращение не угадывается. Хвост после ``|`` (``| no-more``) отбрасывается.
    """
    typed = _normalize_typed(typed)
    if not typed or not commands:
        return None
    tokens = typed.split()
    candidates = []
    for canon in commands:
        ctoks = canon.split()
        if len(tokens) > len(ctoks):
            continue
        if all(ctoks[i].lower().startswith(tokens[i].lower()) for i in range(len(tokens))):
            candidates.append(canon)
    if not candidates:
        return None
    same = [item for item in candidates if len(item.split()) == len(tokens)]
    pool = same or candidates
    if len(pool) == 1:
        return pool[0]
    exact = [item for item in pool if item.lower() == typed.lower()]
    if len(exact) == 1:
        return exact[0]
    return None


# --- разбор -------------------------------------------------------------------

def _split(raw, commands, filename, fallback_command, depth):
    if _is_archive(raw):
        return _split_archive(raw, commands, filename, fallback_command, depth)
    stripped = raw.lstrip()
    if stripped[:1] in (b"{", b"["):
        return _split_json(raw, commands)
    if _looks_binary(raw):
        raise SplitError("файл похож на двоичный: нужна текстовая выгрузка или архив zip/tar")
    text = _decode(raw)
    text = _clean_terminal(text)
    if not text.strip():
        raise SplitError("файл пустой")
    return _split_text(text, commands, fallback_command)


def _split_text(text, commands, fallback_command):
    marked = _split_markers(text, commands)
    if marked is not None:
        files, found = marked
        pack, ambiguous, notes = _recognize(files)
        return _result("oxidized", "commands", files, found, pack, ambiguous, notes)

    rancid = _split_rancid(text, commands)
    if rancid is not None:
        files, found = rancid
        pack, ambiguous, notes = _recognize(files)
        notes = ["бэкап RANCID, тело файла принято как конфигурация"] + notes
        return _result("rancid", "commands", files, found, pack, ambiguous, notes)

    session = _split_session(text, commands)
    if session is not None:
        files, found, saw_prompt = session
        if files:
            pack, ambiguous, notes = _recognize(files)
            return _result("session", "commands", files, found, pack, ambiguous, notes)
        if saw_prompt:
            raise SplitError("в журнале сессии не найдено известных команд пака")

    peeled = _split_oxidized_comments(text, commands)
    if peeled is not None:
        files, found = peeled
        pack, ambiguous, notes = _recognize(files)
        return _result("oxidized", "commands", files, found, pack, ambiguous, notes)

    blob = _split_blob(text, commands)
    if blob is not None:
        files, found, pack, ambiguous, notes = blob
        return _result("blob", "commands", files, found, pack, ambiguous, notes)

    if fallback_command and (not commands or fallback_command in commands) and text.strip():
        body = _as_file(text)
        note = "файл принят целиком как вывод команды «{0}»: пак задан явно, приглашений команд в тексте нет".format(
            fallback_command)
        return _result("fallback", "commands", {fallback_command: body}, [fallback_command], None, [], [note])

    raise SplitError(
        "в файле не найдено выводов команд: нужен журнал сессии, бэкап Oxidized или RANCID, "
        "конфигурация, JSON или архив файлов выгрузки"
    )


def _result(kind, mode, files, found, pack, ambiguous, notes):
    encoded = {}
    for key, value in files.items():
        encoded[key] = value if isinstance(value, bytes) else _as_file(value)
    return SplitResult(kind, mode, encoded, found, pack, ambiguous, notes)


def _normalize_typed(typed):
    typed = " ".join(str(typed or "").replace("\t", " ").split())
    if "|" in typed:
        typed = typed.split("|", 1)[0].strip()
    return typed


def _as_file(text):
    body = text.strip("\n")
    if not body.strip():
        return b""
    if not body.endswith("\n"):
        body += "\n"
    return body.encode("utf-8")


def _known(commands, command):
    return not commands or command in commands


def _command_error(body):
    """Повтор команды в configure/privilege иногда даёт Error/% — не затираем им удачный вывод."""
    text = body.decode("utf-8", "replace") if isinstance(body, bytes) else body
    head = "\n".join(text.lstrip().splitlines()[:4])
    return re.match(r"(?i)^(error\b|% |unknown command\b|invalid input\b)", head) is not None


def _store(files, found, canon, body):
    if isinstance(body, str):
        body = body.strip("\n")
    if not canon or not str(body).strip():
        return
    previous = files.get(canon)
    if previous is not None and _command_error(body) and not _command_error(previous):
        return
    files[canon] = body
    if canon not in found:
        found.append(canon)


# --- терминал -----------------------------------------------------------------

class _Screen(object):
    def __init__(self):
        self.lines = [""]
        self.row = 0
        self.col = 0

    def write_char(self, ch):
        if ch == "\n":
            self.row += 1
            self.col = 0
            while self.row >= len(self.lines):
                self.lines.append("")
            return
        if ch == "\r":
            self.col = 0
            return
        if ch in ("\b", "\x7f"):
            if self.col:
                self.col -= 1
            return
        line = self.lines[self.row] if self.row < len(self.lines) else ""
        while self.row >= len(self.lines):
            self.lines.append("")
            line = ""
        if self.col > len(line):
            line = line + (" " * (self.col - len(line)))
        if self.col < len(line):
            self.lines[self.row] = line[:self.col] + ch + line[self.col + 1:]
        else:
            self.lines[self.row] = line + ch
        self.col += 1

    def back(self, n):
        self.col = self.col - n if self.col > n else 0

    def forward(self, n):
        self.col += n

    def erase_eol(self):
        while self.row >= len(self.lines):
            self.lines.append("")
        line = self.lines[self.row]
        if self.col < len(line):
            self.lines[self.row] = line[:self.col]

    def erase_display(self, mode):
        if mode >= 2:
            self.lines = [""]
            self.row = 0
            self.col = 0
            return
        if mode == 0:
            self.erase_eol()
            self.lines = self.lines[:self.row + 1]
            return
        if self.row < len(self.lines):
            self.lines = [self.lines[self.row][self.col:]]
        else:
            self.lines = [""]
        self.row = 0
        self.col = 0


def _clean_terminal(text):
    screen = _Screen()
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "\x1b":
            i = _skip_escape(text, i, screen)
            continue
        if ch == "\x9b":
            i = _consume_csi(text, i + 1, screen)
            continue
        screen.write_char(ch)
        i += 1
    lines = []
    for line in "\n".join(screen.lines).splitlines():
        line = _MORE_INLINE.sub("", line).rstrip()
        if not line.strip():
            lines.append("")
            continue
        if _MORE_LINE.match(line):
            continue
        if "cursor position requests" in line:
            continue
        lines.append(line)
    return "\n".join(lines).strip("\n")


def _skip_escape(text, i, screen):
    n = len(text)
    if i + 1 >= n:
        return n
    nxt = text[i + 1]
    if nxt == "[":
        return _consume_csi(text, i + 2, screen)
    if nxt == "]":
        j = i + 2
        while j < n:
            if text[j] == "\x07":
                return j + 1
            if text[j] == "\x1b" and j + 1 < n and text[j + 1] == "\\":
                return j + 2
            j += 1
        return n
    if nxt in "()":
        return i + 3 if i + 3 < n else n
    return i + 2


def _consume_csi(text, i, screen):
    n = len(text)
    start = i
    while i < n:
        code = ord(text[i])
        if 64 <= code <= 126:
            _apply_csi(screen, text[start:i], text[i])
            return i + 1
        i += 1
    return n


def _csi_num(params, default):
    digits = []
    for ch in params:
        if ch.isdigit():
            digits.append(ch)
        elif digits:
            break
    if not digits:
        return default
    return int("".join(digits))


def _apply_csi(screen, params, final):
    if final == "D":
        screen.back(max(1, _csi_num(params, 1)))
    elif final == "C":
        screen.forward(max(1, _csi_num(params, 1)))
    elif final == "G":
        screen.col = max(0, _csi_num(params, 1) - 1)
    elif final == "K":
        screen.erase_eol()
    elif final == "J":
        screen.erase_display(_csi_num(params, 0))


# --- сессия, маркеры, один файл ----------------------------------------------

def _prompt_command(line):
    matches = list(_PROMPT_RE.finditer(line))
    if not matches:
        return None
    if line[:matches[0].start()].strip():
        return None
    return line[matches[-1].end():].strip()


def _split_session(text, commands):
    lines = text.splitlines()
    events = []
    for index, line in enumerate(lines):
        cmd = _prompt_command(line)
        if cmd is None:
            continue
        events.append((index, cmd))
    if not events:
        return None
    files = {}
    found = []
    for pos, (line_i, cmd) in enumerate(events):
        end = events[pos + 1][0] if pos + 1 < len(events) else len(lines)
        if not cmd:
            continue
        canon = match_command(cmd, commands)
        if not canon:
            continue
        _store(files, found, canon, "\n".join(lines[line_i + 1:end]))
    return files, found, True


def _split_markers(text, commands):
    matches = list(_MARKER_RE.finditer(text))
    if not matches:
        matches = list(_BRACKET_RE.finditer(text))
        if len(matches) < 2:
            return None
    files, found = _sections(text, matches, commands)
    if not files:
        return None
    return files, found


def _sections(text, matches, commands):
    files = {}
    found = []
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        canon = match_command(match.group(1), commands)
        _store(files, found, canon, text[match.end():end])
    return files, found


def _split_rancid(text, commands):
    match = _RANCID_RE.search(text)
    if not match:
        return None
    body = text[match.end():].strip()
    if not body:
        return None
    command = "show running-config"
    if not _known(commands, command):
        finger = _fingerprint(body)
        command = finger[1] if finger else None
    if not command or not _known(commands, command):
        return None
    return {command: body}, [command]


def _split_oxidized_comments(text, commands):
    lines = text.splitlines()
    index = 0
    comment = []
    while index < len(lines) and (lines[index].startswith("! ") or lines[index].strip() == "!"):
        comment.append(lines[index][2:] if lines[index].startswith("! ") else "")
        index += 1
    if not comment or index >= len(lines):
        return None
    comment_text = "\n".join(comment).strip()
    detected = _detect_blob(comment_text)
    if not detected:
        return None
    pack, command = detected
    if not _known(commands, command):
        return None
    rest = "\n".join(lines[index:]).strip()
    files = {command: comment_text}
    found = [command]
    if rest:
        finger = _fingerprint(rest)
        config_cmd = finger[1] if finger else ("show running-config" if _known(commands, "show running-config") else None)
        if config_cmd and _known(commands, config_cmd) and config_cmd != command:
            files[config_cmd] = rest
            found.append(config_cmd)
        elif command not in files:
            files[command] = rest
    _ = pack
    return files, found


def _split_blob(text, commands):
    finger = _fingerprint(text)
    detected = _detect_blob(text)
    ambiguous = _ambiguous(text)
    # Конфигурация важнее случайного совпадения строки версии внутри неё.
    if finger and _known(commands, finger[1]):
        pack, command = finger
        notes = ["платформа {0} узнана по тексту конфигурации, отдельного вывода версии нет".format(pack)]
        return {command: text}, [command], pack, [], notes
    if detected and _known(commands, detected[1]):
        pack, command = detected
        return {command: text}, [command], pack, [], []
    if ambiguous and _known(commands, ambiguous[1]):
        packs, command, note = ambiguous
        return {command: text}, [command], None, list(packs), [note]
    return None


def _fingerprint(text):
    for pack, command, required, forbidden in _CONFIG_FINGERPRINTS:
        if all(re.search(pattern, text) for pattern in required) and not any(
            re.search(pattern, text) for pattern in forbidden
        ):
            return pack, command
    return None


def _detect_blob(text):
    for pack, command, pattern in _DETECT_BLOBS:
        if re.search(pattern, text):
            return pack, command
    return None


def _ambiguous(text):
    for packs, command, required, note in _AMBIGUOUS:
        if all(re.search(pattern, text) for pattern in required):
            return packs, command, note
    return None


def _recognize(files):
    """Пак по уже нарезанным выводам: сначала команда detect, иначе отпечаток конфигурации."""
    for command, payload in files.items():
        text = payload.decode("utf-8", "replace") if isinstance(payload, bytes) else payload
        detected = _detect_blob(text)
        if detected and detected[1] == command:
            return detected[0], [], []
    for command, payload in files.items():
        text = payload.decode("utf-8", "replace") if isinstance(payload, bytes) else payload
        finger = _fingerprint(text)
        if finger and finger[1] == command:
            pack = finger[0]
            note = "платформа {0} узнана по тексту конфигурации, отдельного вывода версии нет".format(pack)
            if not any(_detect_blob(item.decode("utf-8", "replace") if isinstance(item, bytes) else item)
                       for item in files.values()):
                return pack, [], [note]
    for command, payload in files.items():
        text = payload.decode("utf-8", "replace") if isinstance(payload, bytes) else payload
        ambiguous = _ambiguous(text)
        if ambiguous and ambiguous[1] == command:
            return None, list(ambiguous[0]), [ambiguous[2]]
    return None, [], []


# --- JSON ---------------------------------------------------------------------

def _split_json(raw, commands):
    try:
        text = raw.decode("utf-8-sig")
        data = json.loads(text)
    except (UnicodeDecodeError, ValueError):
        raise SplitError("файл похож на JSON, но не разбирается")
    if isinstance(data, dict) and data and all(isinstance(value, str) for value in data.values()):
        files = {}
        found = []
        for key, value in data.items():
            if not str(value).strip():
                continue
            canon = match_command(key, commands) if commands else (key.strip() or None)
            if not canon:
                continue
            files[canon] = value
            if canon not in found:
                found.append(canon)
        if files:
            pack, ambiguous, notes = _recognize(files)
            return _result("json-commands", "commands", files, found, pack, ambiguous, notes)
        raise SplitError("JSON не похож на выгрузку команд или на JSON Континент 4")
    if _looks_continent(data):
        return SplitResult("json", "json", {"bundle.json": bytes(raw)}, [], "kontinent-4", [], [
            "JSON ЦУС Континент 4: проверки читают export-config-for-cgw, версия прошивки — из cgw, если он в том же файле или архиве",
        ])
    raise SplitError("JSON не похож на выгрузку команд или на JSON Континент 4")


def _looks_continent(data):
    if isinstance(data, dict) and ("export" in data or "cgw" in data):
        export = data.get("export")
        cgw = data.get("cgw")
        if isinstance(export, (dict, list)) or isinstance(cgw, (dict, list)):
            return True
    if isinstance(data, dict) and isinstance(data.get("objects"), list):
        types = set()
        for item in data["objects"]:
            if isinstance(item, dict) and item.get("type"):
                types.add(item.get("type"))
        markers = {"passwordpolicy", "sshaccesscomponent", "snmpcomponent", "admin", "cgw"}
        if types.intersection(markers) and (data.get("type") == "full" or "hwserial" in data):
            return True
    items = None
    if isinstance(data, dict) and isinstance(data.get("data"), list):
        items = data["data"]
    elif isinstance(data, list):
        items = data
    if items and any(isinstance(item, dict) and item.get("hwserial") and item.get("update_version") for item in items):
        return True
    return False


# --- архивы -------------------------------------------------------------------

def _is_archive(raw):
    if raw[:2] == b"PK" or raw[:2] == b"\x1f\x8b":
        return True
    return len(raw) > 262 and raw[257:262] == b"ustar"


def _split_archive(raw, commands, filename, fallback_command, depth):
    if depth > 1:
        raise SplitError("архив внутри архива не разбирается")
    members = _unpack(raw)
    mapped = {}
    json_members = []
    other = []
    names = {command: offline_file_name(command).lower() for command in commands}
    for name, data in members:
        command = None
        low = name.lower()
        for canon, fname in names.items():
            if low == fname or low == fname[:-4]:
                command = canon
                break
        if command:
            if command in mapped:
                raise SplitError("в архиве два файла команды «{0}»".format(command))
            mapped[command] = data
        elif low.endswith(".json"):
            json_members.append((name, data))
        else:
            other.append((name, data))
    if mapped and json_members:
        raise SplitError("в архиве смешаны JSON Континент 4 и файлы команд")
    if mapped:
        notes = []
        if other or json_members:
            notes.append("часть файлов архива не совпала с командами пака и пропущена")
        pack, ambiguous, extra = _recognize(mapped)
        return _result("archive", "commands", mapped, list(mapped), pack, ambiguous, notes + extra)
    if json_members:
        if len(json_members) == 1 and _looks_continent(_json_or_none(json_members[0][1])):
            return SplitResult("json", "json", {json_members[0][0]: json_members[0][1]}, [], "kontinent-4", [], [
                "архив с JSON ЦУС Континент 4",
            ])
        files = {}
        for name, data in json_members:
            if name in files:
                raise SplitError("в архиве два файла с именем {0}".format(name))
            files[name] = data
        return SplitResult("archive", "json", files, [], "kontinent-4" if any(
            _looks_continent(_json_or_none(item[1])) for item in json_members
        ) else None, [], ["архив с JSON-файлами выгрузки"])
    if len(members) == 1:
        inner = _split(members[0][1], commands, members[0][0], fallback_command, depth + 1)
        inner.kind = "archive" if inner.kind not in ("json", "json-commands") else inner.kind
        inner.notes.insert(0, "архив с одним файлом «{0}»".format(members[0][0]))
        return inner
    raise SplitError("в архиве нет файлов выгрузки: имена должны совпадать с командами пака, например show_running-config.txt")


def _json_or_none(raw):
    try:
        return json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError, AttributeError):
        return None


def _unpack(raw):
    if raw[:2] == b"PK":
        return _unpack_zip(raw)
    if raw[:2] == b"\x1f\x8b":
        try:
            opened = tarfile.open(fileobj=io.BytesIO(raw), mode="r:*")
        except (tarfile.TarError, OSError, EOFError, ValueError):
            return [("file.txt", _gunzip(raw))]
        return _read_tar(opened)
    if len(raw) > 262 and raw[257:262] == b"ustar":
        try:
            opened = tarfile.open(fileobj=io.BytesIO(raw), mode="r:*")
        except (tarfile.TarError, OSError, EOFError, ValueError):
            raise SplitError("архив повреждён или это не zip/tar")
        return _read_tar(opened)
    raise SplitError("архив повреждён или это не zip/tar")


def _member_name(name):
    name = str(name or "").replace("\\", "/").strip()
    if not name or "\x00" in name:
        raise SplitError("архив содержит небезопасный путь")
    parts = []
    for part in name.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            raise SplitError("архив содержит небезопасный путь")
        parts.append(part)
    if not parts:
        return None
    return parts[-1]


def _unpack_zip(raw):
    try:
        zf = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipfile:
        raise SplitError("архив повреждён или это не zip/tar")
    found = []
    total = 0
    try:
        infos = [info for info in zf.infolist() if not info.is_dir() and not info.filename.endswith("/")]
        if len(infos) > MAX_ARCHIVE_ENTRIES:
            raise SplitError("в архиве слишком много файлов (больше {0})".format(MAX_ARCHIVE_ENTRIES))
        for info in infos:
            if info.flag_bits & 0x1:
                raise SplitError("архив зашифрован: нужен zip без пароля")
            mode = info.external_attr >> 16
            if mode and stat.S_ISLNK(mode):
                raise SplitError("архив содержит символическую ссылку")
            base = _member_name(info.filename)
            if not base:
                continue
            if info.file_size > MAX_MEMBER_BYTES:
                raise SplitError("файл {0} в архиве больше {1} байт".format(base, MAX_MEMBER_BYTES))
            total += info.file_size
            if total > MAX_UNPACKED_BYTES:
                raise SplitError("распакованный архив слишком большой")
            data = zf.read(info)
            if len(data) > MAX_MEMBER_BYTES or len(data) > MAX_UNPACKED_BYTES:
                raise SplitError("распакованный архив слишком большой")
            found.append((base, data))
    finally:
        zf.close()
    if not found:
        raise SplitError("архив пустой")
    return found


def _read_tar(tf):
    found = []
    total = 0
    count = 0
    try:
        for member in tf:
            if member.issym() or member.islnk():
                raise SplitError("архив содержит символическую ссылку")
            if not member.isfile():
                continue
            count += 1
            if count > MAX_ARCHIVE_ENTRIES:
                raise SplitError("в архиве слишком много файлов (больше {0})".format(MAX_ARCHIVE_ENTRIES))
            base = _member_name(member.name)
            if not base:
                continue
            if member.size > MAX_MEMBER_BYTES:
                raise SplitError("файл {0} в архиве больше {1} байт".format(base, MAX_MEMBER_BYTES))
            total += member.size
            if total > MAX_UNPACKED_BYTES:
                raise SplitError("распакованный архив слишком большой")
            handle = tf.extractfile(member)
            if handle is None:
                raise SplitError("архив содержит символическую ссылку")
            data = handle.read(MAX_MEMBER_BYTES + 1)
            if len(data) > MAX_MEMBER_BYTES:
                raise SplitError("распакованный архив слишком большой")
            found.append((base, data))
    finally:
        tf.close()
    if not found:
        raise SplitError("архив пустой")
    return found


def _gunzip(raw):
    try:
        decoder = gzip.GzipFile(fileobj=io.BytesIO(raw))
    except (OSError, EOFError, ValueError):
        raise SplitError("архив повреждён или это не zip/tar")
    chunks = []
    total = 0
    try:
        while True:
            block = decoder.read(1024 * 256)
            if not block:
                break
            total += len(block)
            if total > MAX_UNPACKED_BYTES:
                raise SplitError("распакованный архив слишком большой")
            chunks.append(block)
    finally:
        decoder.close()
    return b"".join(chunks)


def _looks_binary(raw):
    if b"\x00" in raw:
        return True
    sample = raw[:8000]
    if not sample:
        return False
    bad = 0
    for byte in sample:
        if byte < 9 or (13 < byte < 32 and byte != 27):
            bad += 1
    return bad * 5 > len(sample)


def _decode(raw):
    for encoding in ("utf-8-sig", "cp1251"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    raise SplitError("файл не в кодировке UTF-8 или Windows-1251")


def _write(path, data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    with open(path, "wb") as handle:
        handle.write(data)
