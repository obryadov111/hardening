"""Движок сравнения «факт vs политика» — ядро проекта «Харденинг».

Берёт сырые факты, собранные агентом на активе (`facts`, JSON вида
{"<категория>": {"<ключ>": "<значение>"}}), сравнивает их с активными
правилами из `hardening_rules` (rule_code вида "<категория>.<ключ>",
expected_value — ожидаемое значение) и возвращает результат по каждому
правилу: pass/fail/error.

`error` — правило применимо к типу актива, но агент не прислал факт для
этого ключа (нечего сравнивать). Правила с product_type, не совпадающим
с типом актива, пропускаются (не попадают в результат вовсе).

Проверки контент-паков оцениваются отдельно (app/services/packs/evaluate.py),
результат в том же формате CheckResult.
"""
from dataclasses import dataclass

from app.models.hardening import HardeningRule
from app.services.packs.assertions import normalize_value as _normalize


@dataclass
class CheckResult:
    rule_id: str | None
    rule_code: str | None
    actual_value: str | None
    expected_value: str | None
    status: str  # pass | fail | error
    # Заполняются только для проверок контент-пака (у правил из hardening_rules — None).
    check_id: str | None = None
    pack_id: str | None = None
    pack_version: str | None = None
    evidence: str | None = None
    title: str | None = None
    severity: str | None = None
    remediation: str | None = None
    # Принятый риск (app/services/risk_exceptions.py): только у fail, в score такое нарушение не входит.
    risk_exception_id: str | None = None

    @property
    def accepted(self) -> bool:
        return self.status == "fail" and self.risk_exception_id is not None


def _lookup_fact(facts: dict, rule_code: str) -> tuple[object | None, bool]:
    """Возвращает (значение, найдено_ли). rule_code = 'category.key'."""
    if not rule_code or "." not in rule_code:
        return None, False
    category, key = rule_code.split(".", 1)
    bucket = facts.get(category)
    if not isinstance(bucket, dict) or key not in bucket:
        return None, False
    return bucket[key], True


def evaluate_asset(
    facts: dict,
    rules: list[HardeningRule],
    asset_type: str | None,
    platform_tags: list[str] | None = None,
) -> list[CheckResult]:
    """Прогоняет факты одного актива против набора правил.

    Правило применяется, если rule.product_type пуст (общее для всех типов
    активов) либо совпадает с asset_type или одним из platform_tags актива
    (регистронезависимо). Теги выражают иерархию платформ без отдельной таблицы:
    у Astra Linux они, например, ["linux-server", "debian-family", "astra-se"] —
    общее правило для linux-server и специфичное для astra-se применятся оба.
    """
    results: list[CheckResult] = []
    scopes = {_normalize(asset_type), *(_normalize(tag) for tag in platform_tags or [])} - {""}

    for rule in rules:
        rule_scope = (rule.product_type or "").strip().lower()
        if rule_scope and scopes and rule_scope not in scopes:
            continue

        actual, found = _lookup_fact(facts, rule.rule_code or "")

        if not found:
            results.append(
                CheckResult(
                    rule_id=str(rule.id),
                    rule_code=rule.rule_code,
                    actual_value=None,
                    expected_value=rule.expected_value,
                    status="error",
                )
            )
            continue

        status = "pass" if _normalize(actual) == _normalize(rule.expected_value) else "fail"
        results.append(
            CheckResult(
                rule_id=str(rule.id),
                rule_code=rule.rule_code,
                actual_value=_normalize(actual) if not isinstance(actual, str) else str(actual),
                expected_value=rule.expected_value,
                status=status,
            )
        )

    return results


def compute_coverage(results: list[CheckResult]) -> dict:
    """Насколько оценка опирается на реально выполненные проверки.

    compliance_score считается только по pass/fail и не учитывает error, поэтому при
    неполном сборе оценка выглядит лучше, чем есть. Покрытие показывает это явно:
    evaluated — сколько проверок дали pass/fail, ratio — их доля от всех применимых (%).
    """
    total = len(results)
    evaluated = sum(1 for r in results if r.status in ("pass", "fail"))
    return {
        "total": total,
        "evaluated": evaluated,
        "errors": total - evaluated,
        "ratio": round(evaluated / total * 100, 2) if total else None,
    }


def compute_compliance_score(results: list[CheckResult]) -> tuple[float | None, int, int, int]:
    """Возвращает (compliance_score 0-100 | None, total, passed, failed).
    error/skipped считаются в total, но не в passed/failed — не участвуют
    в score как самостоятельная категория, но не искажают числитель.
    Нарушение с принятым риском тоже не входит ни в failed, ни в score (считается отдельно,
    count_accepted): риск осознанно оставлен, а не «соблюдено»."""
    total = len(results)
    passed = sum(1 for r in results if r.status == "pass")
    failed = sum(1 for r in results if r.status == "fail" and not r.accepted)
    scoreable = passed + failed
    score = round((passed / scoreable) * 100, 2) if scoreable else None
    return score, total, passed, failed


def count_accepted(results: list[CheckResult]) -> int:
    return sum(1 for r in results if r.accepted)
