import { apiDownload } from "./client";

/** Выгрузка снимка: format — "pdf" | "excel". Возвращает файл и имя из Content-Disposition. */
export async function downloadSnapshotExport(snapshotId, format) {
  const { blob, filename } = await apiDownload(
    `/exports/snapshots/${snapshotId}/download?format=${encodeURIComponent(format)}`
  );
  return { blob, filename: filename || `scan-${snapshotId}.${format === "pdf" ? "pdf" : "xlsx"}` };
}
