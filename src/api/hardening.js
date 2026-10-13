import { apiFetch } from "./client";

/**
 * Страница результатов проверок организации: { items, total, limit, offset, summary }.
 * status: fail — открытые нарушения, accepted — с принятым риском, pass, error; summary — по всей организации.
 */
export async function getHardeningByOrganization(
  organizationId,
  { q = "", host = "", status = "", severity = "", sort = "deadline", dir = "asc", limit = 100, offset = 0 } = {},
) {
  const params = new URLSearchParams({ sort, dir, limit: String(limit), offset: String(offset) });
  if (q.trim()) params.set("q", q.trim());
  if (host) params.set("host", host);
  if (status) params.set("status", status);
  if (severity) params.set("severity", severity);
  return apiFetch(`/organizations/${organizationId}/hardening?${params}`);
}
