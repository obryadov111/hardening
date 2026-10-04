/**
 * Даты в интерфейсе — в местном часовом поясе браузера.
 *
 * Бэкенд хранит и отдаёт время в UTC с явным поясом (…Z или …+00:00). Раньше строка просто
 * обрезалась (`created_at.slice(0, 16)`), и на экране оказывалось время UTC: скан в 15:26 по
 * местному времени показывался как 10:26.
 */
const DATE = { day: "2-digit", month: "2-digit", year: "numeric" };
const DATE_TIME = { ...DATE, hour: "2-digit", minute: "2-digit" };

function format(value, options, fallback) {
  if (!value) return fallback;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? fallback : date.toLocaleString("ru-RU", options);
}

/** «04.10.2026, 15:26» */
export function formatDateTime(value, fallback = "—") {
  return format(value, DATE_TIME, fallback);
}

/** «04.10.2026» */
export function formatDate(value, fallback = "—") {
  return format(value, DATE, fallback);
}

/** Конец выбранного дня (YYYY-MM-DD из <input type="date">) по местному времени — в ISO для API. */
export function endOfLocalDayIso(dateInput) {
  return new Date(`${dateInput}T23:59:59`).toISOString();
}
