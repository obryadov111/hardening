import { apiFetch } from "./client";

export async function getVulnerabilitiesByOrganization(organizationId, assetId) {
  const query = assetId ? `?asset_id=${assetId}` : "";
  return apiFetch(`/organizations/${organizationId}/vulnerabilities${query}`);
}
