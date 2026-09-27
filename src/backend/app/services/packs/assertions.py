"""Операторы сравнения для проверок пака: значение пробы vs утверждение.

Возвращает pass/fail/error. error — сравнивать нечего (проба не дала значения)
либо значение не подходит по типу оператору (например, lte для нечислового):
тот же принцип, что и в движке правил, — «нет факта не равно нарушение».
"""
import re
from typing import Any, Literal

Outcome = Literal["pass", "fail", "error"]

OPERATORS = ("eq", "ne", "in", "not_in", "lt", "lte", "gt", "gte", "between", "regex", "exists", "absent", "mode_within")
NUMERIC_OPERATORS = ("lt", "lte", "gt", "gte")
LIST_OPERATORS = ("in", "not_in")
VALUELESS_OPERATORS = ("exists", "absent")


def normalize_value(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value).strip().lower()


def _to_number(value: object) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        return float(str(value).strip())
    except ValueError:
        return None


def _to_octal(value: object) -> int | None:
    try:
        return int(str(value).strip(), 8)
    except ValueError:
        return None


def _is_present(value: object) -> bool:
    return value is not None and str(value).strip() != ""


def check_assertion(actual: object, op: str, expected: Any = None) -> Outcome:
    """Сравнивает значение пробы с ожиданием. `actual=None` означает «проба ничего не нашла»."""
    if op == "exists":
        return "pass" if _is_present(actual) else "fail"
    if op == "absent":
        return "pass" if not _is_present(actual) else "fail"

    if not _is_present(actual):
        return "error"

    if op in NUMERIC_OPERATORS:
        actual_num, expected_num = _to_number(actual), _to_number(expected)
        if actual_num is None or expected_num is None:
            return "error"
        ok = {
            "lt": actual_num < expected_num,
            "lte": actual_num <= expected_num,
            "gt": actual_num > expected_num,
            "gte": actual_num >= expected_num,
        }[op]
        return "pass" if ok else "fail"

    if op == "between":
        # Диапазон включительно: [min, max]. Нужен там, где 0 означает «выключено», например
        # MaximumPasswordAge = 0 — пароль не истекает никогда; простое lte 90 засчитало бы это соблюдением.
        actual_num = _to_number(actual)
        low, high = (_to_number(v) for v in expected)
        if actual_num is None or low is None or high is None:
            return "error"
        return "pass" if low <= actual_num <= high else "fail"

    if op == "mode_within":
        # Права не шире заданных: каждый установленный бит должен быть разрешён. Числовое lte здесь
        # неверно — 604 (читаемо всеми) меньше 640, но шире него.
        actual_mode, allowed_mode = _to_octal(actual), _to_octal(expected)
        if actual_mode is None or allowed_mode is None:
            return "error"
        return "pass" if actual_mode & ~allowed_mode == 0 else "fail"

    if op == "regex":
        return "pass" if re.search(str(expected), str(actual)) else "fail"

    if op in LIST_OPERATORS:
        options = {normalize_value(item) for item in expected}
        inside = normalize_value(actual) in options
        return "pass" if inside == (op == "in") else "fail"

    if op in ("eq", "ne"):
        same = normalize_value(actual) == normalize_value(expected)
        return "pass" if same == (op == "eq") else "fail"

    raise ValueError(f"Неизвестный оператор: {op}")


def describe_assertion(op: str, expected: Any = None) -> str:
    """Человекочитаемое ожидание для отчёта (кладётся в expected_value результата)."""
    if op in VALUELESS_OPERATORS:
        return "задано" if op == "exists" else "не задано"
    if op in LIST_OPERATORS:
        prefix = "одно из" if op == "in" else "не из"
        return f"{prefix}: {', '.join(str(v) for v in expected)}"
    if op == "mode_within":
        return f"права не шире {expected}"
    if op == "between":
        return f"от {expected[0]} до {expected[1]}"
    symbol = {"eq": "=", "ne": "!=", "lt": "<", "lte": "<=", "gt": ">", "gte": ">=", "regex": "~"}[op]
    return f"{symbol} {expected}"
