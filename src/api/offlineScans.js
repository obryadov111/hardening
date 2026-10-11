import { apiFetch } from "./client";

/** Паки сетевых устройств, которые можно проверить по выгрузке, и какие команды (файлы) им нужны. */
export async function getOfflinePacks(organizationId) {
  return apiFetch(`/organizations/${organizationId}/offline-scans/packs`);
}

/**
 * Загрузка выгрузки: files — [{ command, file }]. Сервер выполняет пробы агента по файлам
 * и создаёт снимок с источником «выгрузка конфигурации».
 */
export async function uploadOfflineScan(organizationId, { files, ...fields }) {
  const body = new FormData();
  for (const [key, value] of Object.entries(fields)) {
    if (value != null && value !== "") body.append(key, value);
  }
  for (const { command, file } of files) {
    body.append("commands", command);
    body.append("files", file);
  }
  return apiFetch(`/organizations/${organizationId}/offline-scans`, { method: "POST", body });
}
