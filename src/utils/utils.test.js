// Юнит-тесты вспомогательных функций интерфейса: npm run test:unit (node --test, без зависимостей).
// Часовой пояс задаёт скрипт (TZ=Asia/Yekaterinburg), как у сервера и в сквозных тестах.
import { test } from "node:test";
import assert from "node:assert/strict";
import { endOfLocalDayIso, formatDate, formatDateTime } from "./datetime.js";
import { getScoreTone } from "./score.js";
import { getRemediation, REMEDIATION_BY_SEVERITY } from "./remediation.js";
import { collectionSource } from "./collection.js";
import { roleLabel, ROLES } from "./roles.js";
import { severityRank } from "./severity.js";

test("даты: UTC с сервера — в местном времени, пустое и мусор — заглушка", () => {
  assert.equal(formatDateTime("2026-10-04T10:26:00Z"), "04.10.2026, 15:26");
  assert.equal(formatDateTime("2026-10-04T10:26:00+00:00"), "04.10.2026, 15:26");
  assert.equal(formatDate("2026-12-31T20:00:00Z"), "01.01.2027");  // в Екатеринбурге уже новый год
  assert.equal(formatDateTime(null), "—");
  assert.equal(formatDateTime("", "никогда"), "никогда");
  assert.equal(formatDate("не дата"), "—");
});

test("конец выбранного дня — 23:59:59 местного времени в UTC", () => {
  assert.equal(endOfLocalDayIso("2030-12-31"), "2030-12-31T18:59:59.000Z");
});

test("цвет оценки: пороги 50 и 80, нет оценки — серый", () => {
  assert.equal(getScoreTone(null).text, "text-zinc-400");
  assert.equal(getScoreTone(undefined).text, "text-zinc-400");
  assert.equal(getScoreTone(0).text, "text-rose-300");
  assert.equal(getScoreTone(49.99).text, "text-rose-300");
  assert.equal(getScoreTone(50).text, "text-amber-300");
  assert.equal(getScoreTone(79.9).text, "text-amber-300");
  assert.equal(getScoreTone(80).text, "text-emerald-300");
  assert.equal(getScoreTone(100).text, "text-emerald-300");
});

test("сроки устранения: только у нарушений, обязательно — критический и высокий", () => {
  assert.equal(getRemediation("pass", "critical"), null);
  assert.equal(getRemediation("error", "critical"), null);
  assert.equal(getRemediation("fail", "неизвестно"), null);
  assert.equal(getRemediation("fail", null), null);
  assert.deepEqual(getRemediation("fail", "CRITICAL"), REMEDIATION_BY_SEVERITY.critical);
  assert.equal(getRemediation("fail", "high").mandatory, true);
  assert.equal(getRemediation("fail", "medium").mandatory, false);
  assert.equal(getRemediation("fail", "low").deadline, "до 4 месяцев");
  const order = ["critical", "high", "medium", "low"].map((s) => REMEDIATION_BY_SEVERITY[s].order);
  assert.deepEqual(order, [...order].sort((a, b) => a - b));
});

test("уровни сортируются по важности, а не по алфавиту", () => {
  const sorted = ["medium", "critical", "low", "high", null, "x"].sort((a, b) => severityRank(a) - severityRank(b));
  assert.deepEqual(sorted, [null, "x", "low", "medium", "high", "critical"]);
  assert.equal(severityRank("HIGH"), severityRank("high"));
});

test("роли: подписи по-русски, неизвестная — как есть", () => {
  assert.deepEqual(ROLES.map((r) => r.value), ["viewer", "auditor", "admin"]);
  assert.equal(roleLabel("admin"), "Администратор организации");
  assert.equal(roleLabel("viewer"), "Наблюдатель");
  assert.equal(roleLabel("owner"), "owner");
  assert.equal(roleLabel(null), "");
});

test("источник данных: живой хост — без отметки; выгрузка — с датой самого старого файла", () => {
  assert.equal(collectionSource(null), null);
  const offline = collectionSource({
    source: "offline-config", declared_pack: true, uploaded_by: "admin@example.com",
    files: [{ modified: "2026-10-02T05:00:00Z" }, { modified: "2026-10-01T05:00:00Z" }, {}],
  });
  assert.equal(offline.short, "по выгрузке");
  assert.match(offline.text, /^По выгрузке конфигурации от 01\.10\.2026, 10:00, не живое устройство/);
  assert.match(offline.text, /пак задан оператором/);
  assert.match(offline.text, /загружена через интерфейс: admin@example\.com/);
  assert.match(collectionSource({ source: "offline-config" }).text, /дата выгрузки не указана/);

  const file = collectionSource({ source: "agent-report", transfer: "file", agent_key: "ЦОД", uploaded_by: "a@b.c" });
  assert.equal(file.short, "файлом");
  assert.match(file.text, /подпись ключа «ЦОД» проверена; загрузил a@b\.c/);
  const manual = collectionSource({ source: "manual", answered_by: "auditor@example.com", unanswered: ["a", "b"] });
  assert.equal(manual.short, "по опросу");
  assert.match(manual.text, /не чтение конфигурации/);
  assert.match(manual.text, /auditor@example\.com/);
  assert.match(manual.text, /без ответа вопросов: 2/);
  assert.deepEqual(collectionSource({ source: "что-то новое" }), { short: "что-то новое", text: "что-то новое" });
});
