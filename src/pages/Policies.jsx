import { useEffect, useState } from "react";
import AppCard from "../components/ui/AppCard";
import StatCard from "../components/ui/StatCard";
import EmptyState from "../components/ui/EmptyState";
import OrgGate from "../components/OrgGate";
import { Skeleton } from "../components/ui/Skeleton";
import { useOrganization } from "../context/OrganizationContext";
import { createPolicy, deletePolicy, getPoliciesByOrganization, updatePolicy } from "../api/policies";
import { getCurrentUserRoleInOrganization } from "../api/users";
import ErrorState from "../components/ui/ErrorState";
import { formatDate } from "../utils/datetime";

const STATUSES = ["draft", "active", "review", "archived"];
const EMPTY_FORM = { name: "", scope: "", description: "", status: "draft", owner_name: "", source: "" };
const INPUT = "rounded-xl border border-zinc-800 bg-zinc-950 px-3 py-2 text-sm text-white outline-none placeholder:text-zinc-500";

function getStatusTone(status) {
  switch (status) {
    case "active":
      return "border-emerald-500/20 bg-emerald-500/10 text-emerald-300";
    case "review":
      return "border-amber-500/20 bg-amber-500/10 text-amber-300";
    case "draft":
      return "border-zinc-700 bg-zinc-800 text-zinc-300";
    case "archived":
      return "border-rose-500/20 bg-rose-500/10 text-rose-300";
    default:
      return "border-zinc-700 bg-zinc-800 text-zinc-300";
  }
}

function getStatusLabel(status) {
  switch (status) {
    case "active":
      return "Активна";
    case "review":
      return "На пересмотре";
    case "draft":
      return "Черновик";
    case "archived":
      return "Архив";
    default:
      return status || "—";
  }
}

export default function Policies() {
  const {
    selectedOrganization,
    selectedOrganizationId,
    loading: orgLoading,
    hasOrganizations,
    error: orgError,
  } = useOrganization();

  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(false);
  const [canManage, setCanManage] = useState(false);
  const [form, setForm] = useState(EMPTY_FORM);
  const [actionError, setActionError] = useState("");
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    async function loadData() {
      if (!selectedOrganizationId) {
        setRows([]);
        setCanManage(false);
        setLoading(false);
        return;
      }

      try {
        setLoading(true);
        const [data, role] = await Promise.all([
          getPoliciesByOrganization(selectedOrganizationId),
          getCurrentUserRoleInOrganization(selectedOrganizationId).catch(() => null),
        ]);
        setRows(data);
        // Менять политики может администратор организации (сервер проверяет это сам, здесь — только вид).
        setCanManage(role === "admin");
      } catch (error) {
        console.error("Ошибка загрузки политик:", error.message);
        setRows([]);
      } finally {
        setLoading(false);
      }
    }

    if (!orgLoading) {
      loadData();
    }
  }, [selectedOrganizationId, orgLoading, reloadKey]);

  async function runAction(action) {
    try {
      setActionError("");
      await action();
      setReloadKey((n) => n + 1);
    } catch (error) {
      setActionError(error.message);
    }
  }

  function handleCreate(e) {
    e.preventDefault();
    runAction(async () => {
      if (!form.name.trim()) throw new Error("Введите название политики");
      await createPolicy(selectedOrganizationId, form);
      setForm(EMPTY_FORM);
    });
  }

  function handleDelete(policy) {
    if (!window.confirm(`Удалить политику «${policy.name}»?`)) return;
    runAction(() => deletePolicy(selectedOrganizationId, policy.id));
  }

  const activeCount = rows.filter((item) => item.status === "active").length;
  const reviewCount = rows.filter((item) => item.status === "review").length;

  return (
    <OrgGate
      title="Политики"
      orgLoading={orgLoading}
      orgError={orgError}
      hasOrganizations={hasOrganizations}
    >
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-white">Политики</h1>
        <p className="mt-1 text-sm text-zinc-400">
          Политики и нормативные профили для{" "}
          <span className="text-white">{selectedOrganization?.name || "—"}</span>
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <StatCard label="Всего политик" value={rows.length} loading={loading} hint="Нормативные профили организации" tone="info" />
        <StatCard label="Активные" value={activeCount} loading={loading} hint="Используются в текущем аудите" tone="success" />
        <StatCard label="На пересмотре" value={reviewCount} loading={loading} hint="Требуют согласования" tone="warning" />
      </div>

      {actionError ? <ErrorState title="Ошибка действия" description={actionError} /> : null}

      {canManage ? (
        <AppCard title="Добавить политику" subtitle="Доступно администратору организации">
          <form onSubmit={handleCreate} className="grid gap-3 md:grid-cols-2">
            <input className={INPUT} placeholder="Название *" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
            <input className={INPUT} placeholder="Область применения" value={form.scope} onChange={(e) => setForm({ ...form, scope: e.target.value })} />
            <input className={INPUT} placeholder="Владелец" value={form.owner_name} onChange={(e) => setForm({ ...form, owner_name: e.target.value })} />
            <input className={INPUT} placeholder="Источник (например, методика ФСТЭК от 25.11.2025)" value={form.source} onChange={(e) => setForm({ ...form, source: e.target.value })} />
            <textarea className={`${INPUT} md:col-span-2`} rows={2} placeholder="Описание" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
            <select className={INPUT} value={form.status} onChange={(e) => setForm({ ...form, status: e.target.value })}>
              {STATUSES.map((s) => <option key={s} value={s}>{getStatusLabel(s)}</option>)}
            </select>
            <button type="submit" className="rounded-xl border border-zinc-700 bg-zinc-950 px-4 py-2 text-sm text-white hover:bg-zinc-800">
              Добавить
            </button>
          </form>
        </AppCard>
      ) : null}

      <AppCard title="Реестр политик" subtitle="Политики выбранной организации">
        {loading ? (
          <div className="grid gap-4 lg:grid-cols-2">
            {Array.from({ length: 4 }).map((_, i) => (
              <Skeleton key={i} className="h-32 w-full" />
            ))}
          </div>
        ) : rows.length === 0 ? (
          <EmptyState
            title="Нет политик"
            description="Для выбранной организации в таблице policies пока нет записей."
          />
        ) : (
          <div className="grid gap-4 lg:grid-cols-2">
            {rows.map((item) => (
              <div key={item.id} className="rounded-2xl border border-zinc-800 bg-zinc-950/70 p-5">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <div className="text-base font-semibold text-white">{item.name}</div>
                    <div className="mt-1 text-sm text-zinc-400">{item.scope || "Без области применения"}</div>
                  </div>

                  {canManage ? (
                    <select
                      aria-label="Статус политики"
                      value={item.status}
                      onChange={(e) => runAction(() => updatePolicy(selectedOrganizationId, item.id, { status: e.target.value }))}
                      className={`rounded-full border px-3 py-1 text-xs outline-none ${getStatusTone(item.status)}`}
                    >
                      {STATUSES.map((s) => <option key={s} value={s} className="bg-zinc-950 text-white">{getStatusLabel(s)}</option>)}
                    </select>
                  ) : (
                    <span className={`rounded-full border px-3 py-1 text-xs ${getStatusTone(item.status)}`}>
                      {getStatusLabel(item.status)}
                    </span>
                  )}
                </div>

                <div className="mt-4 text-sm text-zinc-400">
                  {item.description || "Описание отсутствует"}
                </div>

                <div className="mt-5 grid gap-3 sm:grid-cols-2">
                  <div>
                    <div className="text-xs uppercase tracking-wide text-zinc-500">Владелец</div>
                    <div className="mt-1 text-sm text-zinc-200">{item.owner_name || "—"}</div>
                  </div>

                  <div>
                    <div className="text-xs uppercase tracking-wide text-zinc-500">Источник</div>
                    <div className="mt-1 text-sm text-zinc-200">{item.source || "—"}</div>
                  </div>

                  <div>
                    <div className="text-xs uppercase tracking-wide text-zinc-500">Создано</div>
                    <div className="mt-1 text-sm text-zinc-200">{formatDate(item.created_at)}</div>
                  </div>

                  <div>
                    <div className="text-xs uppercase tracking-wide text-zinc-500">Обновлено</div>
                    <div className="mt-1 text-sm text-zinc-200">{formatDate(item.updated_at)}</div>
                  </div>
                </div>

                {canManage ? (
                  <div className="mt-4 text-right">
                    <button
                      type="button"
                      onClick={() => handleDelete(item)}
                      className="rounded-lg border border-rose-500/20 bg-rose-500/10 px-3 py-1.5 text-xs text-rose-300 hover:bg-rose-500/20"
                    >
                      Удалить
                    </button>
                  </div>
                ) : null}
              </div>
            ))}
          </div>
        )}
      </AppCard>
    </div>
    </OrgGate>
  );
}