import { apiFetch } from "./client";

export async function getUsersByOrganization(organizationId) {
  return apiFetch(`/organizations/${organizationId}/users`);
}

export async function addUserToOrganization(email, organizationId, role) {
  return apiFetch(`/organizations/${organizationId}/users`, {
    method: "POST",
    body: JSON.stringify({
      email: email.trim().toLowerCase(),
      role,
    }),
  });
}

export async function removeUserFromOrganization(userId, organizationId) {
  return apiFetch(`/organizations/${organizationId}/users/${userId}`, {
    method: "DELETE",
  });
}

export async function updateUserRole(userId, organizationId, role) {
  return apiFetch(`/organizations/${organizationId}/users/${userId}`, {
    method: "PATCH",
    body: JSON.stringify({ role }),
  });
}

export async function getCurrentUserRoleInOrganization(organizationId) {
  const data = await apiFetch(`/organizations/${organizationId}/my-role`);
  return data?.role || null;
}

export async function getCurrentUserProfile() {
  return apiFetch("/auth/me");
}

// ---------- учётные записи (только суперадмин) ----------

export async function adminListUsers() {
  return apiFetch("/admin/users");
}

/** payload: { email, password (временный), full_name?, organization_id?, role? } */
export async function adminCreateUser(payload) {
  return apiFetch("/admin/users", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function adminResetUserPassword(userId, newPassword) {
  return apiFetch(`/admin/users/${userId}/reset-password`, {
    method: "POST",
    body: JSON.stringify({ new_password: newPassword }),
  });
}

export async function adminSetUserBlocked(userId, blocked) {
  return apiFetch(`/admin/users/${userId}/${blocked ? "block" : "activate"}`, {
    method: "POST",
  });
}

/** Временный пароль для выдачи пользователю: 16 символов из криптостойкого генератора. */
export function generateTemporaryPassword(length = 16) {
  // без похожих символов (0/O, 1/l/I) и знаков, которые путаются при передаче (_ выглядит как пробел)
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";
  const bytes = crypto.getRandomValues(new Uint32Array(length));
  return Array.from(bytes, (b) => alphabet[b % alphabet.length]).join("");
}
