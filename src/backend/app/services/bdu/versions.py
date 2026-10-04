"""Версии: установленный пакет (dpkg) и выражения версий из БДУ ФСТЭК.

В БДУ версии уязвимого ПО — свободный текст: «от 9.0.0 до 9.0.12 включительно», «до 7.1p2»,
«3.7.2». Надёжно разбираются диапазоны и точные версии (~490 тыс. из 834 тыс. записей); остальное
(«-», релизы дистрибутивов вроде «22.04 LTS» или «1.7 «Смоленск»») по версии пакета не сопоставить —
такие записи при импорте пропускаются.

Версия пакета Ubuntu/Debian приводится к версии исходного проекта: без эпохи («1:»), без ревизии
сборки («-3ubuntu13.19»), с учётом подмены «+really» (xz-utils 5.6.1+really5.4.5 — на деле 5.4.5).
ВАЖНО: дистрибутив переносит исправления в старую версию, не меняя её номер, поэтому совпадение
версии с уязвимым диапазоном означает «потенциально уязвим», а не «уязвим».
"""
import re
from dataclasses import dataclass

_TOKEN = re.compile(r"\d+|[a-z]+", re.I)
# Хвосты, которые не входят в версию исходного проекта.
_DEB_SUFFIX = re.compile(r"(\+dfsg\d*|\+ds\d*|\.dfsg\d*|~\S*|\+repack\d*|\+git\S*|\+nmu\d*)$", re.I)


# Метки предварительных версий: 2.0rc1 < 2.0 (= 2.0.0).
_PRE_RELEASE = {"alpha", "a", "beta", "b", "rc", "pre", "preview", "dev"}


def version_key(version: str) -> tuple:
    """Ключ сравнения: числа сравниваются как числа; буквы после числа — более поздняя версия
    («7.1p2»: 7.1 < 7.1p1 < 7.1p2 < 7.2, как у OpenSSH и Sudo), кроме меток предварительных версий
    (alpha, beta, rc, …), которые идут раньше релиза: 2.0rc1 < 2.0.0.
    """
    key = []
    for token in _TOKEN.findall(version.lower()):
        if token.isdigit():
            key.append((0, int(token), ""))
        else:
            key.append((-1 if token in _PRE_RELEASE else 1, 0, token))
    return tuple(key)


def compare(a: str, b: str) -> int:
    ka, kb = version_key(a), version_key(b)
    # Недостающие хвостовые нули не различают версии: 1.2 == 1.2.0.
    width = max(len(ka), len(kb))
    pad = (0, 0, "")
    ka += (pad,) * (width - len(ka))
    kb += (pad,) * (width - len(kb))
    return (ka > kb) - (ka < kb)


def upstream_version(deb_version: str) -> str:
    """Версия dpkg → версия исходного проекта: «1:9.6p1-3ubuntu13.19» → «9.6p1»."""
    version = deb_version.strip()
    if ":" in version:
        version = version.split(":", 1)[1]
    if "+really" in version:
        version = version.split("+really", 1)[1]
    if "-" in version:
        version = version.rsplit("-", 1)[0]
    previous = None
    while previous != version:
        previous, version = version, _DEB_SUFFIX.sub("", version)
    return version


@dataclass(frozen=True)
class VersionRange:
    lo: str | None
    lo_incl: bool
    hi: str | None
    hi_incl: bool

    def contains(self, version: str) -> bool:
        if self.lo is not None:
            c = compare(version, self.lo)
            if c < 0 or (c == 0 and not self.lo_incl):
                return False
        if self.hi is not None:
            c = compare(version, self.hi)
            if c > 0 or (c == 0 and not self.hi_incl):
                return False
        return True


_RANGE = re.compile(
    r"^(?:от\s+(?:версии\s+)?(?P<lo>\d[\w.\-+~]*?)\s+)?до\s+(?:версии\s+)?(?P<hi>\d[\w.\-+~]*?)(?P<incl>\s+включительно)?$",
    re.I,
)
_EXACT = re.compile(r"^(?:версия\s+)?(?P<v>\d[\w.\-+~]*)$", re.I)


def parse_bdu_version(expression: str) -> VersionRange | None:
    """Выражение версии из БДУ → диапазон; None — выражение не про версию (пропускается).

    «от A до B» — верхняя граница не включается, как и пишет БДУ («до B включительно» — включается);
    нижняя граница «от A» включается.
    """
    text = " ".join((expression or "").split())
    if m := _RANGE.match(text):
        return VersionRange(m["lo"], True, m["hi"], bool(m["incl"]))
    if m := _EXACT.match(text):
        return VersionRange(m["v"], True, m["v"], True)
    return None


# ---------- сравнение версий пакетов Debian/Ubuntu (правила dpkg) ----------

def _dpkg_order(char: str) -> int:
    if char == "~":
        return -1  # «~» раньше всего, даже конца строки: 1.0~rc1 < 1.0
    if char.isdigit():
        return 0
    if char.isalpha():
        return ord(char)
    return ord(char) + 256


def _verrevcmp(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _dpkg_order(a[i]) if i < len(a) else 0
            bc = _dpkg_order(b[j]) if j < len(b) else 0
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        first_diff = 0
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def _split_deb(version: str) -> tuple[int, str, str]:
    version = version.strip()
    epoch = 0
    if ":" in version:
        head, version = version.split(":", 1)
        epoch = int(head) if head.isdigit() else 0
    upstream, _, revision = version.rpartition("-") if "-" in version else (version, "", "")
    return epoch, upstream, revision


def compare_deb(a: str, b: str) -> int:
    """Сравнение версий пакетов по правилам dpkg (эпоха, версия, ревизия; «~» раньше релиза).

    1:9.6p1-3ubuntu13.19 > 1:9.6p1-3ubuntu13.3 — так определяется, установлено ли исправление Ubuntu.
    """
    ea, ua, ra = _split_deb(a)
    eb, ub, rb = _split_deb(b)
    if ea != eb:
        return (ea > eb) - (ea < eb)
    c = _verrevcmp(ua, ub)
    if c:
        return (c > 0) - (c < 0)
    c = _verrevcmp(ra, rb)
    return (c > 0) - (c < 0)
