import { apiFetch } from "./client";

/** Отчёты организации, новые сначала. daily — последний отчёт каждого дня (отчёт пересчитывается при каждом приёме). */
export async function getReportsByOrganization(organizationId, { daily = false, limit = 100 } = {}) {
  const params = new URLSearchParams({ limit: String(limit) });
  if (daily) params.set("daily", "true");
  return apiFetch(`/organizations/${organizationId}/reports?${params}`);
}
