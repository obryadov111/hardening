"""Формат пака и его валидация (pydantic).

Пак — данные, а не код: агент выполняет только пробы из закрытого списка ниже,
утверждения сравниваются на сервере. Валидация здесь — первый рубеж защиты:
пак с командой вне белого списка или с путём вне абсолютных не загрузится.
Агент дополнительно применяет собственные ограничения (agent/probes.py) —
он последний рубеж и не доверяет манифесту слепо.
"""
import re
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.services.packs.assertions import (
    LIST_OPERATORS,
    NUMERIC_OPERATORS,
    OPERATORS,
    VALUELESS_OPERATORS,
)

PACK_ID_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
CHECK_ID_RE = re.compile(r"^[a-z0-9_]+(\.[a-z0-9_]+)+$")
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")
SERVICE_NAME_RE = re.compile(r"^[A-Za-z0-9_.@:-]+$")
PACKAGE_NAME_RE = re.compile(r"^[A-Za-z0-9_.+:-]+$")
EXECUTABLE_RE = re.compile(r"^[a-z0-9_-]+$")
# Только чтение: show/display или /export и «… print» у RouterOS. Без ; & $ ` кавычек и переводов строк.
CLI_READONLY_RE = re.compile(
    r"^(show|display) [A-Za-z0-9 _./|^:\-]+$"
    r"|^/export( [A-Za-z0-9 _./=\-]+)?$"
    r"|^/[a-z0-9/ -]+ print( [A-Za-z0-9 _./=\-]+)?$"
)

Severity = Literal["critical", "high", "medium", "low", "info"]
# inventory — только обнаружение платформы; draft — проверки написаны по документации и НЕ подтверждены на
# реальном оборудовании; baseline и выше — подтверждены (обязателен verified_on: на чём именно проверено).
Maturity = Literal["inventory", "draft", "baseline", "full", "certified"]
Transport = Literal["local", "ssh"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _validate_absolute_path(path: str) -> str:
    if not path.startswith("/") or ".." in path.split("/") or "\x00" in path:
        raise ValueError(f"путь должен быть абсолютным и без '..': {path!r}")
    return path


def _validate_regex(pattern: str) -> str:
    try:
        re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"некорректное регулярное выражение {pattern!r}: {exc}") from exc
    return pattern


class FileKvProbe(StrictModel):
    """Значение параметра из конфигурационного файла вида `ключ значение` или `ключ=значение`."""

    type: Literal["file_kv"]
    path: str
    key: str
    separator: Literal["whitespace", "equals"] = "whitespace"
    default: str | None = None
    match: Literal["first", "last"] = "first"
    ignore_case: bool = True
    follow_include: bool = False  # раскрывать директивы Include (sshd_config.d/*.conf); только в пределах каталога файла

    _path = field_validator("path")(_validate_absolute_path)


class FileRegexProbe(StrictModel):
    """Первое совпадение регулярного выражения в файле (группа 1, если она есть)."""

    type: Literal["file_regex"]
    path: str
    pattern: str

    _path = field_validator("path")(_validate_absolute_path)
    _pattern = field_validator("pattern")(_validate_regex)


class FileStatProbe(StrictModel):
    """Права/владелец файла без чтения его содержимого (годится и для /etc/shadow)."""

    type: Literal["file_stat"]
    path: str
    field: Literal["mode", "owner", "group", "uid", "gid"] = "mode"

    _path = field_validator("path")(_validate_absolute_path)


class CmdForeachProbe(StrictModel):
    """Команда-список, затем команда по каждому элементу; результат — число элементов, вывод которых
    подходит под pattern (например, docker: id контейнеров -> privileged каждого). Пустой список — 0."""

    type: Literal["cmd_foreach"]
    list_cmd: list[str] = Field(min_length=1)
    item_cmd: list[str] = Field(min_length=1)  # элемент списка добавляется последним аргументом
    pattern: str
    max_items: int = Field(default=100, ge=1, le=200)

    _pattern = field_validator("pattern")(_validate_regex)

    @field_validator("list_cmd", "item_cmd")
    @classmethod
    def _argv(cls, cmd: list[str]) -> list[str]:
        if not EXECUTABLE_RE.match(cmd[0]):
            raise ValueError(f"исполняемый файл указывается по имени, без пути: {cmd[0]!r}")
        if any(("\n" in arg or "\x00" in arg) for arg in cmd):
            raise ValueError("аргументы команды не могут содержать перевод строки")
        return cmd


class CmdRegexProbe(StrictModel):
    """Вывод локальной команды (без shell, argv) и регулярное выражение по нему."""

    type: Literal["cmd_regex"]
    cmd: list[str] = Field(min_length=1)
    pattern: str

    _pattern = field_validator("pattern")(_validate_regex)

    @field_validator("cmd")
    @classmethod
    def _cmd_argv(cls, cmd: list[str]) -> list[str]:
        if not EXECUTABLE_RE.match(cmd[0]):
            raise ValueError(f"исполняемый файл указывается по имени, без пути: {cmd[0]!r}")
        if any(("\n" in arg or "\x00" in arg) for arg in cmd):
            raise ValueError("аргументы команды не могут содержать перевод строки")
        return cmd


class CliConfigProbe(StrictModel):
    """Строка/раздел конфигурации сетевого устройства, полученные командой только на чтение."""

    type: Literal["cli_config"]
    cmd: str
    match: str
    section: str | None = None
    require: str | None = None  # признак настоящего вывода; нет в ответе — проба не выполнилась (нет прав и т. п.)

    _match = field_validator("match")(_validate_regex)

    @field_validator("require")
    @classmethod
    def _require_regex(cls, require: str | None) -> str | None:
        return _validate_regex(require) if require is not None else None

    @field_validator("cmd")
    @classmethod
    def _cmd_readonly(cls, cmd: str) -> str:
        if len(cmd) > 200 or not CLI_READONLY_RE.match(cmd):
            raise ValueError(f"допустимы только команды на чтение (show/display, /export, … print): {cmd!r}")
        return cmd

    @field_validator("section")
    @classmethod
    def _section_regex(cls, section: str | None) -> str | None:
        return _validate_regex(section) if section is not None else None


class ServiceStateProbe(StrictModel):
    """Состояние службы systemd: активна / включена в автозапуск."""

    type: Literal["service_state"]
    service: str
    field: Literal["active", "enabled"] = "active"

    @field_validator("service")
    @classmethod
    def _service(cls, service: str) -> str:
        if not SERVICE_NAME_RE.match(service):
            raise ValueError(f"недопустимое имя службы: {service!r}")
        return service


class PkgVersionProbe(StrictModel):
    """Версия установленного пакета (dpkg/rpm); пусто — пакет не установлен."""

    type: Literal["pkg_version"]
    package: str

    @field_validator("package")
    @classmethod
    def _package(cls, package: str) -> str:
        if not PACKAGE_NAME_RE.match(package):
            raise ValueError(f"недопустимое имя пакета: {package!r}")
        return package


# ---------- Windows ----------
# Источники, не зависящие от языка системы: на русской Windows `net accounts`, `auditpol /get`, `netsh`
# выводят русский текст, и регулярные выражения по нему ломаются. Поэтому — реестр, экспорт политики
# безопасности (ключи вида MinimumPasswordLength) и резервная копия политики аудита (GUID и числа).

# Кусты с секретами (хэши паролей, секреты LSA) агенту недоступны в принципе.
REG_DENIED_RE = re.compile(r"^HKLM\\(SAM|SECURITY)(\\|$)", re.IGNORECASE)
REG_KEY_RE = re.compile(r"^HKLM(\\[A-Za-z0-9 _.(){}\-]+)+$")
REG_VALUE_RE = re.compile(r"^[A-Za-z0-9 _.\-]+$")
SECPOL_KEY_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")
AUDIT_GUID_RE = re.compile(r"^\{[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\}$")


class RegValueProbe(StrictModel):
    """Значение реестра Windows (только HKLM). Нет ключа или значения — «не задано» (default), это не
    ошибка: большинство параметров безопасности задаются только при отклонении от умолчания Windows."""

    type: Literal["reg_value"]
    key: str
    value: str
    default: str | None = None

    @field_validator("key")
    @classmethod
    def _key(cls, key: str) -> str:
        if not REG_KEY_RE.match(key):
            raise ValueError(f"ключ реестра — HKLM\\путь без специальных символов: {key!r}")
        if REG_DENIED_RE.match(key):
            raise ValueError(f"кусты SAM и SECURITY агенту недоступны: {key!r}")
        return key

    @field_validator("value")
    @classmethod
    def _value(cls, value: str) -> str:
        if not REG_VALUE_RE.match(value):
            raise ValueError(f"недопустимое имя значения реестра: {value!r}")
        return value


class WinSecpolProbe(StrictModel):
    """Параметр локальной политики безопасности из `secedit /export` (пароли, блокировка, гостевая учётка).
    Ключи не зависят от языка системы. Нужны права администратора."""

    type: Literal["win_secpol"]
    section: Literal["System Access"] = "System Access"
    key: str
    default: str | None = None

    @field_validator("key")
    @classmethod
    def _key(cls, key: str) -> str:
        if not SECPOL_KEY_RE.match(key):
            raise ValueError(f"недопустимый ключ политики: {key!r}")
        return key


class WinAuditpolProbe(StrictModel):
    """Подкатегория расширенной политики аудита по GUID (`auditpol /backup`): 0 — нет, 1 — успех,
    2 — отказ, 3 — успех и отказ. GUID и числа не зависят от языка системы. Нужны права администратора."""

    type: Literal["win_auditpol"]
    subcategory: str

    @field_validator("subcategory")
    @classmethod
    def _guid(cls, guid: str) -> str:
        if not AUDIT_GUID_RE.match(guid):
            raise ValueError(f"подкатегория аудита — GUID в фигурных скобках: {guid!r}")
        return guid.upper()


LeafProbe = (
    FileKvProbe | FileRegexProbe | FileStatProbe | CmdRegexProbe | CmdForeachProbe | CliConfigProbe | ServiceStateProbe
    | PkgVersionProbe | RegValueProbe | WinSecpolProbe | WinAuditpolProbe
)


class FirstOfProbe(StrictModel):
    """Несколько источников одного и того же значения по порядку: берётся первый, нашедший значение
    (например, состояние ufw: сначала `ufw status`, затем файл конфигурации). Вложенность — один уровень."""

    type: Literal["first_of"]
    probes: list[Annotated[LeafProbe, Field(discriminator="type")]] = Field(min_length=2, max_length=5)


Probe = Annotated[LeafProbe | FirstOfProbe, Field(discriminator="type")]


def leaf_probes(probe) -> list:
    """Пробы без составной обёртки: для проверок, которые должны видеть каждую реальную пробу."""
    return list(probe.probes) if probe.type == "first_of" else [probe]

SSH_PROBE_TYPES = {"cli_config", "cmd_regex"}


class Assertion(StrictModel):
    op: str
    value: Any = None

    @model_validator(mode="after")
    def _check(self) -> "Assertion":
        if self.op not in OPERATORS:
            raise ValueError(f"неизвестный оператор {self.op!r}; допустимы: {', '.join(OPERATORS)}")
        if self.op in VALUELESS_OPERATORS:
            if self.value is not None:
                raise ValueError(f"оператор {self.op} не принимает value")
        elif self.value is None:
            raise ValueError(f"оператору {self.op} нужно value")
        if self.op in LIST_OPERATORS and (not isinstance(self.value, list) or not self.value):
            raise ValueError(f"оператору {self.op} нужен непустой список")
        if self.op in NUMERIC_OPERATORS and (isinstance(self.value, bool) or not isinstance(self.value, int | float)):
            raise ValueError(f"оператору {self.op} нужно число")
        if self.op == "between" and not (
            isinstance(self.value, list) and len(self.value) == 2
            and all(isinstance(v, int | float) and not isinstance(v, bool) for v in self.value)
            and self.value[0] <= self.value[1]
        ):
            raise ValueError("оператору between нужен список [min, max] из двух чисел, min <= max")
        if self.op == "regex":
            _validate_regex(str(self.value))
        if self.op == "mode_within" and not (isinstance(self.value, str) and re.fullmatch(r"[0-7]{3,4}", self.value)):
            # В YAML число 0640 читается как восьмеричное 416, а 640 — как десятичное: только строка в кавычках.
            raise ValueError('mode_within: восьмеричная строка в кавычках, например "640"')
        return self


class Reference(StrictModel):
    source: str
    id: str | None = None


class Check(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    id: str
    title: str
    probe: Probe
    assertion: Assertion = Field(alias="assert")
    severity: Severity = "medium"
    remediation: str | None = None
    refs: list[Reference] = Field(default_factory=list)
    control: str | None = None

    @field_validator("id")
    @classmethod
    def _id(cls, check_id: str) -> str:
        if not CHECK_ID_RE.match(check_id):
            raise ValueError(f"id проверки вида 'категория.ключ' (a-z, 0-9, _): {check_id!r}")
        return check_id


class DetectRule(StrictModel):
    """Условие принадлежности хоста платформе: значение пробы равно `equals` либо подходит под `regex`."""

    probe: Probe
    equals: str | None = None
    regex: str | None = None

    @model_validator(mode="after")
    def _one_condition(self) -> "DetectRule":
        if (self.equals is None) == (self.regex is None):
            raise ValueError("в detect нужно ровно одно из: equals, regex")
        if self.regex is not None:
            _validate_regex(self.regex)
        return self


class Pack(StrictModel):
    pack: str
    version: str
    maturity: Maturity
    verified_on: list[str] = Field(default_factory=list)
    tags: list[str] = Field(min_length=1)
    transport: Transport
    asset_type: str | None = None
    detect: list[DetectRule] = Field(min_length=1)
    checks: list[Check] = Field(default_factory=list)

    @field_validator("pack")
    @classmethod
    def _pack_id(cls, pack_id: str) -> str:
        if not PACK_ID_RE.match(pack_id):
            raise ValueError(f"id пака: строчные латинские буквы, цифры и дефис: {pack_id!r}")
        return pack_id

    @field_validator("version")
    @classmethod
    def _version(cls, version: str) -> str:
        if not SEMVER_RE.match(version):
            raise ValueError(f"версия в формате MAJOR.MINOR.PATCH: {version!r}")
        return version

    @model_validator(mode="after")
    def _consistency(self) -> "Pack":
        ids = [check.id for check in self.checks]
        duplicates = sorted({i for i in ids if ids.count(i) > 1})
        if duplicates:
            raise ValueError(f"повторяются id проверок: {', '.join(duplicates)}")

        if self.maturity != "inventory" and not self.checks:
            raise ValueError(f"maturity={self.maturity} требует проверок; пустой пак — только inventory")
        if self.maturity in ("baseline", "full", "certified") and not self.verified_on:
            raise ValueError(
                f"maturity={self.maturity} требует verified_on (на каком оборудовании/версиях проверено); "
                "проверки, не подтверждённые на оборудовании, — maturity=draft"
            )
        if self.maturity == "inventory" and self.checks:
            raise ValueError("maturity=inventory — только обнаружение платформы, без проверок (проверки — draft или выше)")

        if self.transport == "ssh":
            probes = [
                leaf
                for probe in [check.probe for check in self.checks] + [rule.probe for rule in self.detect]
                for leaf in leaf_probes(probe)
            ]
            wrong = sorted({p.type for p in probes if p.type not in SSH_PROBE_TYPES})
            if wrong:
                raise ValueError(f"транспорт ssh допускает только cli_config и cmd_regex, найдено: {', '.join(wrong)}")
            for probe in probes:
                if probe.type == "cmd_regex" and not CLI_READONLY_RE.match(" ".join(probe.cmd)):
                    raise ValueError(f"по ssh допустимы только команды на чтение: {' '.join(probe.cmd)!r}")
        return self

    @property
    def version_tuple(self) -> tuple[int, int, int]:
        major, minor, patch = self.version.split(".")
        return int(major), int(minor), int(patch)
