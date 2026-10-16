import { apiFetch } from "./client";

/** Паки для проверки по опросу (оборудование без машиночитаемой конфигурации) и их вопросы. */
export async function getManualPacks(organizationId) {
  return apiFetch(`/organizations/${organizationId}/manual-scans/packs`);
}

/**
 * Ответы аудитора: answers — { id проверки: { value, comment } }. Сервер оценивает их как пробы агента
 * и создаёт снимок с источником «опрос».
 */
export async function submitManualScan(organizationId, body) {
  return apiFetch(`/organizations/${organizationId}/manual-scans`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}
