import { useEffect, useState } from "react";
import AppCard from "../components/ui/AppCard";
import EmptyState from "../components/ui/EmptyState";
import ErrorState from "../components/ui/ErrorState";
import { useOrganization } from "../context/OrganizationContext";
import {
  addUserToOrganization,
  getUsersByOrganization,
  removeUserFromOrganization,
  updateUserRole,
  getCurrentUserRoleInOrganization,
} from "../api/users";

export default function OrganizationUsers() {
  const {
    selectedOrganization,
    selectedOrganizationId,
    loading: orgLoading,
    hasOrganizations,
    error: orgError,
  } = useOrganization();

  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(false);
  const [email, setEmail] = useState("");
  const [role, setRole] = useState("auditor");
  const [actionError, setActionError] = useState("");
  const [currentRole, setCurrentRole] = useState(null);

  async function loadUsers() {
    if (!selectedOrganizationId) {
      setRows([]);
      return;
    }

    try {
      setLoading(true);
      setActionError("");

      // Сначала роль: не-админу список не запрашивается (сервер всё равно ответит 403),
      // и страница показывает «Недостаточно прав», а не текст ошибки запроса.
      const myRole = await getCurrentUserRoleInOrganization(selectedOrganizationId);
      setCurrentRole(myRole);
      setRows(myRole === "admin" ? await getUsersByOrganization(selectedOrganizationId) : []);
    } catch (error) {
      console.error("Ошибка загрузки пользователей:", error.message);
      setRows([]);
      setActionError(error.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    if (!orgLoading) {
      loadUsers();
    }
  }, [selectedOrganizationId, orgLoading]);

  async function handleAddUser() {
    try {
      setActionError("");

      if (!email.trim()) {
        throw new Error("Введите email пользователя");
      }

      await addUserToOrganization(email, selectedOrganizationId, role);
      setEmail("");
      setRole("auditor");
      await loadUsers();
    } catch (error) {
      console.error("Ошибка добавления пользователя:", error.message);
      setActionError(error.message);
    }
  }

  async function handleDeleteUser(userId) {
    const member = rows.find((item) => item.id === userId);
    if (!window.confirm(`Убрать ${member?.email || "пользователя"} из организации?`)) return;
    try {
      setActionError("");
      await removeUserFromOrganization(userId, selectedOrganizationId);
      await loadUsers();
    } catch (error) {
      console.error("Ошибка удаления пользователя:", error.message);
      setActionError(error.message);
    }
  }

  async function handleChangeRole(userId, newRole) {
    try {
      setActionError("");
      await updateUserRole(userId, selectedOrganizationId, newRole);
      await loadUsers();
    } catch (error) {
      console.error("Ошибка смены роли:", error.message);
      setActionError(error.message);
    }
  }

  if (orgLoading) {
    return <div className="text-zinc-400">Загрузка организаций...</div>;
  }

  if (orgError) {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-semibold text-white">Управление доступом</h1>
        <ErrorState title="Не удалось загрузить организации" description={orgError} />
      </div>
    );
  }

  if (!hasOrganizations) {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-semibold text-white">Управление доступом</h1>
        <EmptyState
          title="Нет организаций"
          description="Сначала создай организацию."
        />
      </div>
    );
  }

  if (currentRole && currentRole !== "admin") {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-semibold text-white">Управление доступом</h1>
        <ErrorState
          title="Недостаточно прав"
          description="Только администратор организации может управлять пользователями."
        />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-white">Управление доступом</h1>
        <p className="mt-1 text-sm text-zinc-400">
          Пользователи и роли для организации{" "}
          <span className="text-white">{selectedOrganization?.name || "—"}</span>
        </p>
      </div>

      {actionError ? (
        <ErrorState title="Ошибка действия" description={actionError} />
      ) : null}

      <AppCard title="Добавить пользователя" subtitle="Пользователь должен уже существовать в системе">
        <div className="grid gap-3 md:grid-cols-[1fr_180px_160px]">
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="email@example.com"
            className="rounded-xl border border-zinc-800 bg-zinc-950 px-3 py-2 text-white outline-none placeholder:text-zinc-500"
          />

          <select
            value={role}
            onChange={(e) => setRole(e.target.value)}
            className="rounded-xl border border-zinc-800 bg-zinc-950 px-3 py-2 text-white outline-none"
          >
            <option value="admin">admin</option>
            <option value="auditor">auditor</option>
            <option value="viewer">viewer</option>
          </select>

          <button
            type="button"
            onClick={handleAddUser}
            className="rounded-xl border border-zinc-700 bg-zinc-950 px-4 py-2 text-sm text-white hover:bg-zinc-800"
          >
            Добавить
          </button>
        </div>
      </AppCard>

      <AppCard title="Список пользователей" subtitle="Пользователи, связанные с текущей организацией">
        {loading ? (
          <div className="text-zinc-400">Загрузка...</div>
        ) : rows.length === 0 ? (
          <EmptyState
            title="Нет пользователей"
            description="Для этой организации пока нет связанных пользователей."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead className="border-b border-zinc-800 text-left text-zinc-400">
                <tr>
                  <th className="px-4 py-3">Email</th>
                  <th className="px-4 py-3">Роль</th>
                  <th className="px-4 py-3">Действия</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((item) => (
                  <tr
                    key={item.id}
                    className="border-b border-zinc-800/60 text-zinc-200"
                  >
                    <td className="px-4 py-3 font-medium text-white">
                      {item.email || "—"}
                    </td>

                    <td className="px-4 py-3">
                      <select
                        value={item.role}
                        onChange={(e) => handleChangeRole(item.id, e.target.value)}
                        className="rounded-lg border border-zinc-700 bg-zinc-950 px-2 py-1 text-white outline-none"
                      >
                        <option value="admin">admin</option>
                        <option value="auditor">auditor</option>
                        <option value="viewer">viewer</option>
                      </select>
                    </td>

                    <td className="px-4 py-3">
                      <button
                        type="button"
                        onClick={() => handleDeleteUser(item.id)}
                        className="rounded-lg border border-rose-500/20 bg-rose-500/10 px-3 py-1.5 text-xs text-rose-300 hover:bg-rose-500/20"
                      >
                        Удалить
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </AppCard>
    </div>
  );
}