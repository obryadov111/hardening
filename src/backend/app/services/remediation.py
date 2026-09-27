"""Сроки и обязательность устранения нарушений по уровню критичности.

Та же таблица, что во фронтенде (src/utils/remediation.js): бэкенду она нужна для выгрузок отчёта.

Источники:
  * «Методика анализа защищённости ИС», ФСТЭК России, 25.11.2025, п. 3.4.4 — критический и высокий
    уровень устраняются обязательно; п. 3.4.5 — средний и низкий после экспертной оценки;
  * «Методика оценки уровня критичности уязвимостей программных, программно-аппаратных средств»,
    ФСТЭК России, 30.06.2025 — сроки устранения по уровням.

Уровень берётся из пака (экспертная оценка автора пака), а не рассчитывается по формуле V
методики, поэтому срок — ориентир. Подробно — README паков.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class Remediation:
    deadline: str
    mandatory: bool
    order: int

    @property
    def procedure(self) -> str:
        return "Обязательно (п. 3.4.4)" if self.mandatory else "После экспертной оценки (п. 3.4.5)"


REMEDIATION_BY_SEVERITY = {
    "critical": Remediation("до 24 часов", True, 0),
    "high": Remediation("до 7 дней", True, 1),
    "medium": Remediation("до 4 недель", False, 2),
    "low": Remediation("до 4 месяцев", False, 3),
}

SOURCE_NOTE = (
    "Сроки — ориентир по методике оценки уровня критичности уязвимостей ФСТЭК от 30.06.2025; "
    "«обязательно» — п. 3.4.4 методики анализа защищённости от 25.11.2025. Уровень — оценка пака, "
    "а не рассчитанный по методике показатель V."
)


def get_remediation(status: str | None, severity: str | None) -> Remediation | None:
    """None — устранять нечего (не fail) или уровень неизвестен."""
    if status != "fail":
        return None
    return REMEDIATION_BY_SEVERITY.get((severity or "").lower())
