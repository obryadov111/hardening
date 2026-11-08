import { apiFetch } from "./client";

/** Паки сетевых устройств, которые можно проверить по выгрузке, и какие команды (файлы) им нужны. */
export async function getOfflinePacks(organizationId) {
  return apiFetch(`/organizations/${organizationId}/offline-scans/packs`);
}

/** Разбор одного файла без записи снимка: пак, найденные команды, чего не хватает. */
export async function previewOfflineScan(organizationId, file, pack) {
  const body = new FormData();
  body.append("bundle", file);
  if (pack) body.append("pack", pack);
  return apiFetch(`/organizations/${organizationId}/offline-scans/preview`, { method: "POST", body });
}

/**
 * Загрузка выгрузки. bundle — один файл (журнал, бэкап, архив, JSON).
 * files — [{ command, file }], прежний режим «файл на команду».
 */
export async function uploadOfflineScan(organizationId, { files, bundle, ...fields }) {
  const body = new FormData();
  for (const [key, value] of Object.entries(fields)) {
    if (value != null && value !== "") body.append(key, value);
  }
  if (bundle) {
    body.append("bundle", bundle);
  } else {
    for (const { command, file } of files || []) {
      body.append("commands", command);
      body.append("files", file);
    }
  }
  return apiFetch(`/organizations/${organizationId}/offline-scans`, { method: "POST", body });
}
