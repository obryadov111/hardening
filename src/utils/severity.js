/** Порядок уровней для сортировки: по алфавиту кода было бы critical < high < low < medium. */
const RANK = { low: 1, medium: 2, high: 3, critical: 4 };

export function severityRank(value) {
  return RANK[(value || "").toLowerCase()] ?? 0;
}
