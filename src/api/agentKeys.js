import { apiFetch } from "./client";

/** Ключи агентов организации и открытый ключ подписи паков (для настройки агентов). */
export async function getAgentKeys(organizationId) {
  return apiFetch(`/organizations/${organizationId}/agent-keys`);
}

/** Новый ключ: в ответе поле key — сам ключ, показывается один раз. */
export async function createAgentKey(organizationId, { name, expiresInDays }) {
  return apiFetch(`/organizations/${organizationId}/agent-keys`, {
    method: "POST",
    body: JSON.stringify({ name, expires_in_days: expiresInDays }),
  });
}

export async function revokeAgentKey(organizationId, keyId) {
  return apiFetch(`/organizations/${organizationId}/agent-keys/${keyId}/revoke`, { method: "POST" });
}

/** Отчёт агента из изолированного сегмента (agent --out), подписанный ключом агента. */
export async function uploadAgentReport(organizationId, file) {
  const body = new FormData();
  body.append("file", file);
  return apiFetch(`/organizations/${organizationId}/agent-reports`, { method: "POST", body });
}

/** Опубликованный агент (deploy/publish_agent.sh): версии, SHA-256, адрес и отпечаток ключа сервера.
 *  Статический файл nginx, не API; null — агент на сервере ещё не опубликован. */
export async function getAgentDownloads() {
  const response = await fetch("/downloads/version.json", { cache: "no-store" });
  if (!response.ok) return null;
  return response.json().catch(() => null);
}

/** Отзыв хоста: его ключ перестаёт действовать, по ключу площадки его заново не зарегистрировать. */
export async function revokeAgentHost(organizationId, hostId) {
  return apiFetch(`/organizations/${organizationId}/agent-hosts/${hostId}/revoke`, { method: "POST" });
}

/** Удаление регистрации хоста: имя освобождается, агент (переустановленный) регистрируется заново. */
export async function deleteAgentHost(organizationId, hostId) {
  return apiFetch(`/organizations/${organizationId}/agent-hosts/${hostId}`, { method: "DELETE" });
}

/** Охват: список ожидаемых хостов (из AD или CSV) против отчитавшихся за days дней. */
export async function getCoverage(organizationId, days = 7) {
  return apiFetch(`/organizations/${organizationId}/coverage?days=${days}`);
}

/** Загрузка списка ожидаемых хостов (CSV, выгрузка AD) — заменяет прежний. */
export async function uploadExpectedHosts(organizationId, file) {
  const body = new FormData();
  body.append("file", file);
  return apiFetch(`/organizations/${organizationId}/expected-hosts`, { method: "POST", body });
}

export async function deleteExpectedHosts(organizationId) {
  return apiFetch(`/organizations/${organizationId}/expected-hosts`, { method: "DELETE" });
}
