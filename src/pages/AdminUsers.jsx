import { useCallback, useEffect, useState } from "react";
import AppCard from "../components/ui/AppCard";
import ErrorState from "../components/ui/ErrorState";
import { useOrganization } from "../context/OrganizationContext";
import {
  adminCreateUser,
  adminListUsers,
  adminResetUserPassword,
  adminResetUserTwoFactor,
  adminSetUserBlocked,
  generateTemporaryPassword,
  getCurrentUserProfile,
} from "../api/users";
import { formatDateTime } from "../utils/datetime";

const ROLES = [
  { value: "viewer", label: "Наблюдатель" },
  { value: "auditor", label: "Аудитор" },
  { value: "admin", label: "Администратор организации" },
];
const INPUT = "w-full rounded-xl border border-zinc-800 bg-zinc-950 px-3 py-2 text-sm text-white outline-none placeholder:text-zinc-500 focus:border-blue-500";
const EMPTY_FORM = { email: "", full_name: "", password: "", organization_id: "", role: "viewer" };

function StatusBadge({ user }) {
  if (user.account_status === "blocked" || !user.is_active) {
    return <span className="rounded-full border border-rose-500/20 bg-rose-500/10 px-2 py-0.5 text-xs text-rose-300">заблокирован</span>;
  }
  if (user.locked_until) {
    const until = new Date(user.locked_until).toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit" });
    return (
      <span title="Серия неудачных попыток входа; блокировка снимется сама или кнопкой «Разблокировать»" className="rounded-full border border-amber-500/20 bg-amber-500/10 px-2 py-0.5 text-xs text-amber-300">
        вход закрыт до {until}
      </span>
    );
  }
  if (user.must_change_password) {
    return <span className="rounded-full border border-amber-500/20 bg-amber-500/10 px-2 py-0.5 text-xs text-amber-300">временный пароль</span>;
  }
  return <span className="rounded-full border border-emerald-500/20 bg-emerald-500/10 px-2 py-0.5 text-xs text-emerald-300">активен</span>;
}

/** Пароль, выданный администратором: показывается один раз, чтобы передать пользователю. */
function IssuedPassword({ issued, onClose }) {
  if (!issued) return null;
  return (
    <div className="rounded-xl border border-amber-500/20 bg-amber-500/10 p-4 text-sm text-amber-200">
      <div>
        Временный пароль для <span className="font-medium text-white">{issued.email}</span>. Передайте его пользователю
        защищённым каналом: при входе система потребует сменить его, после этого он перестанет действовать.
      </div>
      <div className="mt-3 flex flex-wrap items-center gap-3">
        <code className="rounded-lg bg-zinc-950 px-3 py-1.5 font-mono text-base text-white">{issued.password}</code>
        <button type="button" onClick={() => navigator.clipboard?.writeText(issued.password)} className="rounded-lg border border-zinc-700 px-3 py-1.5 text-xs text-white hover:bg-zinc-800">
          Скопировать
        </button>
        <button type="button" onClick={onClose} className="rounded-lg px-3 py-1.5 text-xs text-zinc-300 hover:text-white">
          Скрыть
        </button>
      </div>
    </div>
  );
}

export default function AdminUsers() {
  const { organizations } = useOrganization();
  const [me, setMe] = useState(null);
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [form, setForm] = useState(EMPTY_FORM);
  const [error, setError] = useState("");
  const [issued, setIssued] = useState(null);
  const [busy, setBusy] = useState("");

  const load = useCallback(async () => {
    try {
      const [profile, rows] = await Promise.all([getCurrentUserProfile(), adminListUsers()]);
      setMe(profile);
      setUsers(rows);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function run(key, action) {
    setBusy(key);
    setError("");
    try {
      await action();
      await load();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy("");
    }
  }

  function handleCreate(e) {
    e.preventDefault();
    run("create", async () => {
      const email = form.email.trim().toLowerCase();
      await adminCreateUser({
        email,
        password: form.password,
        full_name: form.full_name.trim() || null,
        organization_id: form.organization_id || null,
        role: form.role,
      });
      setIssued({ email, password: form.password });
      setForm(EMPTY_FORM);
    });
  }

  function handleReset(user) {
    if (!window.confirm(`Сбросить пароль ${user.email}? Все его текущие сессии будут завершены.`)) return;
    const password = generateTemporaryPassword();
    run(`reset-${user.id}`, async () => {
      await adminResetUserPassword(user.id, password);
      setIssued({ email: user.email, password });
    });
  }

  function handleReset2FA(user) {
    if (!window.confirm(`Сбросить 2FA ${user.email}? Делайте это, только убедившись, что обращается сам пользователь (он потерял телефон и резервные коды). После сброса вход — по одному паролю, пока 2FA не подключат заново.`)) return;
    run(`2fa-${user.id}`, () => adminResetUserTwoFactor(user.id));
  }

  function handleBlock(user, blocked) {
    const question = blocked
      ? `Заблокировать ${user.email}? Доступ прекратится сразу, в том числе в открытых сессиях.`
      : `Разблокировать ${user.email}?`;
    if (!window.confirm(question)) return;
    run(`block-${user.id}`, () => adminSetUserBlocked(user.id, blocked));
  }

  if (!loading && me && !me.is_superadmin) {
    return <ErrorState title="Недостаточно прав" description="Учётными записями управляет суперадминистратор." />;
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-white">Пользователи системы</h1>
        <p className="mt-1 text-sm text-zinc-400">
          Учётные записи. Доступ к данным организации выдаётся её администратором или здесь при создании.
        </p>
      </div>

      {error ? <ErrorState title="Ошибка действия" description={error} /> : null}
      <IssuedPassword issued={issued} onClose={() => setIssued(null)} />

      <AppCard title="Новый пользователь" subtitle="Пароль временный: при первом входе пользователь задаст свой">
        <form onSubmit={handleCreate} className="grid gap-3 md:grid-cols-2">
          <input className={INPUT} type="email" required placeholder="Email *" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} />
          <input className={INPUT} placeholder="ФИО" value={form.full_name} onChange={(e) => setForm({ ...form, full_name: e.target.value })} />
          <div className="flex gap-2">
            <input className={INPUT} required minLength={12} placeholder="Временный пароль * (от 12 символов)" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
            <button type="button" onClick={() => setForm({ ...form, password: generateTemporaryPassword() })} className="shrink-0 rounded-xl border border-zinc-700 px-3 text-xs text-white hover:bg-zinc-800">
              Сгенерировать
            </button>
          </div>
          <div className="grid grid-cols-2 gap-2">
            <select aria-label="Организация" className={INPUT} value={form.organization_id} onChange={(e) => setForm({ ...form, organization_id: e.target.value })}>
              <option value="">Без организации</option>
              {organizations.map((org) => <option key={org.id} value={org.id}>{org.name}</option>)}
            </select>
            <select aria-label="Роль в организации" className={INPUT} value={form.role} disabled={!form.organization_id} onChange={(e) => setForm({ ...form, role: e.target.value })}>
              {ROLES.map((r) => <option key={r.value} value={r.value}>{r.label}</option>)}
            </select>
          </div>
          <div className="md:col-span-2">
            <button type="submit" disabled={busy === "create"} className="rounded-xl bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500 disabled:opacity-60">
              {busy === "create" ? "Создаём..." : "Создать"}
            </button>
          </div>
        </form>
      </AppCard>

      <AppCard title="Учётные записи" subtitle={loading ? "Загрузка..." : `Всего: ${users.length}`}>
        <div className="overflow-x-auto">
          <table className="min-w-full text-sm">
            <thead className="border-b border-zinc-800 text-left text-zinc-400">
              <tr>
                <th className="px-4 py-3 font-medium">Пользователь</th>
                <th className="px-4 py-3 font-medium">Организации</th>
                <th className="px-4 py-3 font-medium">Статус</th>
                <th className="px-4 py-3 font-medium">Последний вход</th>
                <th className="px-4 py-3 font-medium">Действия</th>
              </tr>
            </thead>
            <tbody>
              {users.map((user) => {
                const self = user.id === me?.id;
                // «Разблокировать» снимает и ручную блокировку, и временную (после неудачных входов)
                const blocked = user.account_status === "blocked" || !user.is_active || Boolean(user.locked_until);
                return (
                  <tr key={user.id} className="border-b border-zinc-800/60 align-top text-zinc-200">
                    <td className="px-4 py-3">
                      <div className="font-medium text-white">{user.email}</div>
                      <div className="text-xs text-zinc-500">
                        {user.full_name || "—"}
                        {user.is_superadmin ? " · суперадмин" : ""}
                        {user.two_factor_enabled ? " · 2FA" : ""}
                        {self ? " · это вы" : ""}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-xs text-zinc-300">
                      {user.organizations.length
                        ? user.organizations.map((o) => <div key={o.id}>{o.name} <span className="text-zinc-500">({o.role})</span></div>)
                        : <span className="text-zinc-500">{user.is_superadmin ? "все" : "нет"}</span>}
                    </td>
                    <td className="px-4 py-3"><StatusBadge user={user} /></td>
                    <td className="px-4 py-3 text-xs text-zinc-400">{formatDateTime(user.last_login_at)}</td>
                    <td className="px-4 py-3">
                      {self ? (
                        <span className="text-xs text-zinc-500">свой пароль — в меню профиля</span>
                      ) : (
                        <div className="flex flex-wrap gap-2">
                          <button type="button" disabled={!!busy} onClick={() => handleReset(user)} className="rounded-lg border border-zinc-700 px-3 py-1.5 text-xs text-white hover:bg-zinc-800 disabled:opacity-50">
                            Сбросить пароль
                          </button>
                          {user.two_factor_enabled ? (
                            <button type="button" disabled={!!busy} onClick={() => handleReset2FA(user)} className="rounded-lg border border-zinc-700 px-3 py-1.5 text-xs text-white hover:bg-zinc-800 disabled:opacity-50">
                              Сбросить 2FA
                            </button>
                          ) : null}
                          <button
                            type="button"
                            disabled={!!busy}
                            onClick={() => handleBlock(user, !blocked)}
                            className={`rounded-lg border px-3 py-1.5 text-xs disabled:opacity-50 ${blocked ? "border-emerald-500/20 bg-emerald-500/10 text-emerald-300" : "border-rose-500/20 bg-rose-500/10 text-rose-300"}`}
                          >
                            {blocked ? "Разблокировать" : "Заблокировать"}
                          </button>
                        </div>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </AppCard>
    </div>
  );
}
