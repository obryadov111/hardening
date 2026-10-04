"""Уровень критичности уязвимости по методике ФСТЭК России от 30.06.2025.

V = Icvss × Iinfr × (Iat + Iimp)

- Icvss — базовая оценка CVSS 3.1 вендора (из БДУ). Нет CVSS 3 — берётся CVSS 2 с пометкой.
- Iinfr = 0,5·K + 0,2·L + 0,3·P: K — тип компонента (по типу актива), L — доля активов организации
  с этой уязвимостью, P — доступность актива из интернета.
- Iat — возможность эксплуатации (по полям БДУ «эксплуатация в атаках» и «наличие эксплойта»).
- Iimp — последствия эксплуатации (по формулировке названия уязвимости в БДУ).

Уровни: V > 8 — критический, 5 ≤ V ≤ 8 — высокий, 2 ≤ V < 5 — средний, V < 2 — низкий.

Значения коэффициентов взяты из текста методики на pravo.ppt.ru (вторичный источник); перед защитой
сверить с официальным текстом ФСТЭК. Последствия (Iimp) определяются по словам в названии
уязвимости — это эвристика: формализованного поля «последствия» в выгрузке БДУ нет.
"""
import re
from dataclasses import dataclass

# K — тип компонента ИС.
COMPONENT_K = {
    "network-device": 0.9,
    "firewall": 0.9,
    "linux-server": 0.7,
    "windows-server": 0.7,
    "server": 0.7,
    "windows-client": 0.5,
    "workstation": 0.5,
    "storage": 0.4,
}
COMPONENT_K_DEFAULT = 0.1  # «иные компоненты»

# Iimp — последствия; первое совпадение в порядке убывания тяжести.
IMPACTS: list[tuple[str, float, re.Pattern]] = [
    (label, value, re.compile(pattern, re.I))
    for label, value, pattern in [
        ("выполнение произвольного кода", 0.5, r"выполн\w*\s+произвольн|полный контроль"),
        ("повышение привилегий", 0.5, r"повыси\w*\s+(свои\s+)?привилеги"),
        ("обход механизмов безопасности", 0.4, r"обойти"),
        ("внедрение кода", 0.34, r"внедр|инъекц"),
        ("получение защищаемой информации", 0.3, r"раскрыть|конфиденциальн|получить\s+(несанкционированный\s+)?доступ|на чтение|ssrf"),
        ("нарушение целостности", 0.3, r"целостност|на изменение"),
        ("отказ в обслуживании", 0.26, r"отказ в обслуживании|доступност"),
        ("перезапись произвольных файлов", 0.22, r"перезаписать"),
        ("запись локальных файлов", 0.2, r"записать"),
        ("чтение локальных файлов", 0.18, r"прочитать|прочесть"),
        ("подмена интерфейса", 0.12, r"спуфинг|подмен"),
        ("межсайтовый скриптинг", 0.1, r"межсайтов|скриптинг|xss"),
    ]
]
IMPACT_UNKNOWN = ("последствия не распознаны", 0.3)


def impact_of(name: str) -> tuple[str, float]:
    for label, value, pattern in IMPACTS:
        if pattern.search(name or ""):
            return label, value
    return IMPACT_UNKNOWN


def exploitation_of(exploit_status: str | None, incident: str | None) -> tuple[str, float]:
    if (incident or "").strip().lower() == "да":
        return "эксплуатируется в атаках", 0.6
    if (exploit_status or "").strip().lower().startswith("существует"):
        return "есть эксплойт", 0.3
    return "сведений об эксплуатации нет", 0.1


def share_l(affected: int, total: int) -> float:
    share = affected / total if total else 1.0
    if share > 0.7:
        return 1.0
    if share >= 0.5:
        return 0.8
    if share >= 0.1:
        return 0.6
    return 0.5


def level_of(v: float) -> str:
    if v > 8.0:
        return "critical"
    if v >= 5.0:
        return "high"
    if v >= 2.0:
        return "medium"
    return "low"


@dataclass(frozen=True)
class Criticality:
    v: float
    level: str
    icvss: float
    cvss_version: str
    iinfr: float
    iat: float
    iimp: float
    impact: str
    exploitation: str


def criticality(
    *, cvss3: float | None, cvss2: float | None, asset_type: str | None, affected_assets: int, total_assets: int,
    internet_facing: bool, exploit_status: str | None, incident: str | None, name: str,
) -> Criticality | None:
    """None — у уязвимости нет оценки CVSS, V не рассчитать."""
    if cvss3 is not None:
        icvss, cvss_version = cvss3, "3"
    elif cvss2 is not None:
        icvss, cvss_version = cvss2, "2"
    else:
        return None
    k = COMPONENT_K.get((asset_type or "").lower(), COMPONENT_K_DEFAULT)
    iinfr = 0.5 * k + 0.2 * share_l(affected_assets, total_assets) + 0.3 * (1.1 if internet_facing else 0.6)
    exploitation, iat = exploitation_of(exploit_status, incident)
    impact, iimp = impact_of(name)
    v = round(icvss * iinfr * (iat + iimp), 2)
    return Criticality(v, level_of(v), icvss, cvss_version, round(iinfr, 3), iat, iimp, impact, exploitation)
