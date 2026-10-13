/** Роли в организации — коды с сервера (user_organizations.role) и подписи в интерфейсе. */
export const ROLES = [
  { value: "viewer", label: "Наблюдатель" },
  { value: "auditor", label: "Аудитор" },
  { value: "admin", label: "Администратор организации" },
];

const LABELS = Object.fromEntries(ROLES.map((r) => [r.value, r.label]));

export function roleLabel(role) {
  return LABELS[role] || role || "";
}
