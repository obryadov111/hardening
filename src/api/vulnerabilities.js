import { apiFetch } from "./client";

/**
 * Страница потенциальных уязвимостей организации (сначала самые критичные) и сводка.
 * distro: all | open (без исправленного в Ubuntu) | vulnerable | unfixed | fixed | unknown | not_checked.
 * Ответ: { items, found, total (открытые), summary, distro_summary, import, oval, not_compared, … }.
 */
export async function getVulnerabilitiesByOrganization(
  organizationId,
  { assetId = "", level = "", distro = "open", q = "", limit = 100, offset = 0 } = {},
) {
  const params = new URLSearchParams({ distro, limit: String(limit), offset: String(offset) });
  if (assetId) params.set("asset_id", assetId);
  if (level) params.set("level", level);
  if (q.trim()) params.set("q", q.trim());
  return apiFetch(`/organizations/${organizationId}/vulnerabilities?${params}`);
}
