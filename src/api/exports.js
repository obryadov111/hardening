import { apiDownload } from "./client";

/** Выгрузка снимка: format — "pdf" | "excel". Возвращает файл и имя из Content-Disposition. */
/** Выгрузка прогона: сводка, хосты, нарушения по правилам. */
export async function downloadRunExport(runId, format) {
  const { blob, filename } = await apiDownload(
    `/exports/scan-runs/${runId}/download?format=${encodeURIComponent(format)}`
  );
  return { blob, filename: filename || `run-${runId}.${format === "pdf" ? "pdf" : "xlsx"}` };
}

export async function downloadSnapshotExport(snapshotId, format) {
  const { blob, filename } = await apiDownload(
    `/exports/snapshots/${snapshotId}/download?format=${encodeURIComponent(format)}`
  );
  return { blob, filename: filename || `scan-${snapshotId}.${format === "pdf" ? "pdf" : "xlsx"}` };
}
