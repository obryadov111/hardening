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
