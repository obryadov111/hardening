import { apiFetch } from "./client";

export async function getRiskExceptions(organizationId, { includeInactive = false } = {}) {
  const query = includeInactive ? "?include_inactive=true" : "";
  return apiFetch(`/organizations/${organizationId}/risk-exceptions${query}`);
}

export async function createRiskException(organizationId, exception) {
  return apiFetch(`/organizations/${organizationId}/risk-exceptions`, {
    method: "POST",
    body: JSON.stringify(exception),
  });
}

export async function revokeRiskException(organizationId, exceptionId) {
  return apiFetch(`/organizations/${organizationId}/risk-exceptions/${exceptionId}`, { method: "DELETE" });
}
