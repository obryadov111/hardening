import { formatDateTime } from "./datetime";

/**
 * Источник данных снимка. null — живой хост или устройство (агент), отметка не нужна.
 * Выгрузка конфигурации — с датой самого старого файла: проверено состояние на момент выгрузки,
 * а не на дату снимка (как «Источник данных» в PDF/Excel).
 */
export function collectionSource(collection) {
  if (!collection) return null;
  if (collection.source === "offline-config") {
    const times = (collection.files || []).map((f) => f.modified).filter(Boolean).sort();
    return {
      short: "по выгрузке",
      text: `По выгрузке конфигурации${times.length ? ` от ${formatDateTime(times[0])}` : ""}, не живое устройство`
        + (collection.declared_pack ? "; пак задан оператором, платформа не подтверждена" : ""),
    };
  }
  return { short: collection.source, text: collection.source };
}
