import { apiFetch } from "./client";

/** Страница ПО организации: { items, total, limit, offset, summary: { programs, categories, hosts } }. */
export async function getSoftwareByOrganization(organizationId, { q = "", host = "", sort = "name", dir = "asc", limit = 100, offset = 0 } = {}) {
  const params = new URLSearchParams({ sort, dir, limit: String(limit), offset: String(offset) });
  if (q.trim()) params.set("q", q.trim());
  if (host) params.set("host", host);
  return apiFetch(`/organizations/${organizationId}/software?${params}`);
}
