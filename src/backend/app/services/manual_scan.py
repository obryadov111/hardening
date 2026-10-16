"""Проверка по опросу (транспорт manual): оборудование, конфигурацию которого не прочитать ни командой, ни выгрузкой.

Пример — Континент 4: настройки узлов безопасности живут в ЦУС и меняются только в графическом Менеджере
конфигурации, по SSH доступно лишь текстовое локальное меню. Аудитор отвечает на вопросы пака по экранам
системы управления (у каждого вопроса — где смотреть), ответы оцениваются теми же утверждениями (assert), что
и пробы агента, и сохраняются обычным снимком с источником «опрос»: кто ответил и когда.

Ответ — не чтение конфигурации: в отчёте это видно (снимок помечен «по опросу»), а комментарий аудитора
(«скриншот МК, раздел SNMP») сохраняется как свидетельство.
"""
from app.services.packs.models import Pack
from app.services.packs.registry import PackRegistry

MAX_COMMENT = 1000
YES = {"yes", "да"}
NO = {"no", "нет"}


class ManualScanError(ValueError):
    pass


def _question(probe) -> dict:
    return {
        "question": probe.question, "hint": probe.hint, "answer": probe.answer,
        "choices": probe.choices, "unit": probe.unit,
    }


def manual_packs(registry: PackRegistry) -> list[dict]:
    """Паки для проверки по опросу и их вопросы — для страницы интерфейса."""
    result = []
    for pack in registry.latest("manual"):
        result.append({
            "pack": pack.pack, "version": pack.version, "maturity": pack.maturity, "tags": list(pack.tags),
            "asset_type": pack.asset_type,
            "questions": [
                {"id": check.id, "title": check.title, "severity": check.severity, **_question(check.probe)}
                for check in pack.checks
            ],
            "firmware": {"product": pack.firmware.product, **_question(pack.firmware.version_probe)} if pack.firmware else None,
        })
    return result


def normalize_answer(probe, raw) -> str | None:
    """Ответ в значение пробы. None — вопрос пропущен (проверка будет «не проверено», а не pass/fail)."""
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return None
    if isinstance(raw, bool):
        # true/false из JSON интерфейса (и yes/no без кавычек в YAML-образцах) — ответ «да/нет»
        if probe.answer != "yesno":
            raise ManualScanError("ответ да/нет на вопрос, где ожидалось другое")
        return "yes" if raw else "no"
    text = str(raw).strip()
    if probe.answer == "yesno":
        low = text.lower()
        if low in YES:
            return "yes"
        if low in NO:
            return "no"
        raise ManualScanError(f"ответ «{text[:40]}» — ожидалось да или нет")
    if probe.answer == "number":
        try:
            number = float(text.replace(",", "."))
        except ValueError:
            raise ManualScanError(f"ответ «{text[:40]}» — ожидалось число") from None
        return str(int(number)) if number.is_integer() else str(number)
    if probe.answer == "choice":
        if text not in probe.choices:
            raise ManualScanError(f"ответ «{text[:40]}» — ожидалось одно из: {', '.join(probe.choices)}")
        return text
    return text[:200]


def probe_results(pack: Pack, answers: dict[str, dict]) -> tuple[dict[str, dict], list[str]]:
    """Ответы {id проверки: {value, comment}} → результаты проб как от агента и список пропущенных вопросов."""
    known = {check.id for check in pack.checks}
    unknown = sorted(set(answers) - known)
    if unknown:
        raise ManualScanError(f"в паке {pack.pack} нет вопросов: {', '.join(unknown)}")
    results, skipped = {}, []
    for check in pack.checks:
        answer = answers.get(check.id) or {}
        try:
            value = normalize_answer(check.probe, answer.get("value"))
        except ManualScanError as exc:
            raise ManualScanError(f"{check.id}: {exc}") from None
        comment = (answer.get("comment") or "").strip()[:MAX_COMMENT] or None
        if value is None:
            skipped.append(check.id)
            results[check.id] = {"found": False, "value": None, "evidence": None, "error": "аудитор не ответил на вопрос"}
        else:
            results[check.id] = {"found": True, "value": value, "evidence": comment}
    return results, skipped


def firmware_software(pack: Pack, version) -> list[dict]:
    """Версия ПО из ответа аудитора — ПО актива для сопоставления с БДУ (как поле firmware у сетевых паков)."""
    if pack.firmware is None:
        return []
    value = normalize_answer(pack.firmware.version_probe, version)
    if value is None:
        return []
    return [{"name": pack.firmware.product.strip().lower(), "version": value, "vendor": pack.firmware.vendor,
             "category": "firmware"}]
