import { formatDateTime } from "./datetime";

/**
 * Источник данных снимка. null — живой хост или устройство (агент), отметка не нужна.
 * Выгрузка конфигурации — с датой самого старого файла: проверено состояние на момент выгрузки,
 * а не на дату снимка (как «Источник данных» в PDF/Excel).
 */
export function collectionSource(collection) {
  if (!collection) return null;
  // Отчёт агента из изолированного сегмента, перенесённый файлом: подпись ключом агента проверена сервером.
  const transfer = collection.transfer === "file"
    ? `; отчёт перенесён файлом, подпись ключа «${collection.agent_key || "?"}» проверена`
    : "";
  if (collection.source === "agent-report") {
    return {
      short: "файлом",
      text: `Живой хост (агент)${transfer}; загрузил ${collection.uploaded_by || "—"}`,
    };
  }
  if (collection.source === "offline-config") {
    const times = (collection.files || []).map((f) => f.modified).filter(Boolean).sort();
    return {
      short: "по выгрузке",
      text: `По выгрузке конфигурации${times.length ? ` от ${formatDateTime(times[0])}` : " (дата выгрузки не указана)"}, не живое устройство`
        + (collection.declared_pack ? "; пак задан оператором, платформа не подтверждена" : "")
        + (collection.uploaded_by ? `; загружена через интерфейс: ${collection.uploaded_by}` : "")
        + transfer,
    };
  }
  return { short: collection.source, text: collection.source };
}
