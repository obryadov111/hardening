import { apiFetch } from "./client";

export async function getFstecCoverage(organizationId) {
  return apiFetch(`/organizations/${organizationId}/fstec-coverage`);
}
