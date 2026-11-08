import { apiFetch } from "./client";

/** Прогоны организации, новые сначала. */
export async function getScanRuns(organizationId, { status = "", limit = 50, offset = 0 } = {}) {
  const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
  if (status) params.set("status", status);
  return apiFetch(`/organizations/${organizationId}/scan-runs?${params}`);
}

export async function getScanRun(runId) {
  return apiFetch(`/scan-runs/${runId}`);
}

export async function getScanRunHosts(runId, { q = "", status = "", environmentId = "", limit = 50, offset = 0 } = {}) {
  const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
  if (q) params.set("q", q);
  if (status) params.set("status", status);
  if (environmentId) params.set("environment_id", environmentId);
  return apiFetch(`/scan-runs/${runId}/hosts?${params}`);
}

export async function getScanRunFindings(runId, { limit = 100, offset = 0 } = {}) {
  const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
  return apiFetch(`/scan-runs/${runId}/findings?${params}`);
}

export async function compareScanRuns(beforeId, afterId, { limit = 50, offset = 0 } = {}) {
  const params = new URLSearchParams({
    before_run_id: beforeId,
    after_run_id: afterId,
    limit: String(limit),
    offset: String(offset),
  });
  return apiFetch(`/scan-runs/compare?${params}`);
}

export async function openScanRun(organizationId, body) {
  return apiFetch(`/organizations/${organizationId}/scan-runs`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

export async function closeScanRun(runId) {
  return apiFetch(`/scan-runs/${runId}/close`, { method: "POST" });
}

export async function getScanSchedule(organizationId) {
  return apiFetch(`/organizations/${organizationId}/scan-schedule`);
}

export async function setScanSchedule(organizationId, schedule) {
  return apiFetch(`/organizations/${organizationId}/scan-schedule`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ schedule }),
  });
}

export async function getEnvironments(organizationId) {
  return apiFetch(`/organizations/${organizationId}/environments`);
}
