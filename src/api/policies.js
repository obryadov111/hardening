import { apiFetch } from "./client";

export async function getPoliciesByOrganization(organizationId) {
  return apiFetch(`/organizations/${organizationId}/policies`);
}

export async function createPolicy(organizationId, policy) {
  return apiFetch(`/organizations/${organizationId}/policies`, {
    method: "POST",
    body: JSON.stringify(policy),
  });
}

export async function updatePolicy(organizationId, policyId, changes) {
  return apiFetch(`/organizations/${organizationId}/policies/${policyId}`, {
    method: "PATCH",
    body: JSON.stringify(changes),
  });
}

export async function deletePolicy(organizationId, policyId) {
  return apiFetch(`/organizations/${organizationId}/policies/${policyId}`, { method: "DELETE" });
}
