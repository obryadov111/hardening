import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import AppCard from "../components/ui/AppCard";
import StatCard from "../components/ui/StatCard";
import EmptyState from "../components/ui/EmptyState";
import ErrorState from "../components/ui/ErrorState";
import OrgGate from "../components/OrgGate";
import { SkeletonTable } from "../components/ui/Skeleton";
import { getScoreTone } from "../utils/score";
import { useOrganization } from "../context/OrganizationContext";
import {
  closeScanRun, getEnvironments, getScanRuns, getScanSchedule, openScanRun, setScanSchedule,
} from "../api/scanRuns";
import { downloadRunExport } from "../api/exports";
import { getCurrentUserRoleInOrganization } from "../api/users";
import { formatDateTime } from "../utils/datetime";

const PAGE_SIZE = 50;
const PAGER = "rounded-xl border border-zinc-700 px-3 py-1.5 text-sm text-zinc-200 hover:bg-zinc-800 disabled:opacity-40";
const SELECT = "rounded-xl border border-zinc-800 bg-zinc-950 px-3 py-2 text-sm text-white outline-none";
const INPUT = "rounded-xl border border-zinc-800 bg-zinc-950 px-3 py-2 text-sm text-white outline-none";

function statusLabel(status) {
  if (status === "open") return "Открыт";
  if (status === "closed") return "Закрыт";
  return status || "—";
}

function statusClass(status) {
  if (status === "open") return "border-blue-500/20 bg-blue-500/10 text-blue-300";
  if (status === "closed") return "border-zinc-700 bg-zinc-800 text-zinc-300";
  return "border-zinc-700 bg-zinc-800 text-zinc-300";
}

function scoreText(value) {
  return value != null ? `${Math.round(value)}%` : "—";
}

export default function Scans() {
  const {
    selectedOrganization,
    selectedOrganizationId,
    loading: orgLoading,
    hasOrganizations,
    error: orgError,
  } = useOrganization();

  return (
    <OrgGate
      title="Сканирования"
      orgLoading={orgLoading}
      orgError={orgError}
      hasOrganizations={hasOrganizations}
    >
      <div className="space-y-6">
        <div>
          <h1 className="text-2xl font-semibold text-white">Сканирования</h1>
          <p className="mt-1 text-sm text-zinc-400">
            Прогоны организации{" "}
            <span className="text-white">{selectedOrganization?.name || "—"}</span>.
            Один прогон собирает снимки всех хостов за окно расписания агентов.
            Устройство без агента можно проверить{" "}
            <Link to="/offline-scan" className="text-blue-300 underline hover:text-blue-200">по выгрузке конфигурации</Link>.
          </p>
        </div>
        {selectedOrganizationId ? <ScansView key={selectedOrganizationId} organizationId={selectedOrganizationId} /> : null}
      </div>
    </OrgGate>
  );
}

function ScansView({ organizationId }) {
  const [result, setResult] = useState({ key: null, items: [], total: 0, schedule: "daily", error: "" });
  const [status, setStatus] = useState("");
  const [offset, setOffset] = useState(0);
  const [role, setRole] = useState(null);
  const [environments, setEnvironments] = useState([]);
  const [selected, setSelected] = useState([]);
  const [busyKey, setBusyKey] = useState("");
  const [exportError, setExportError] = useState("");
  const [actionError, setActionError] = useState("");
  const [opening, setOpening] = useState(false);
  const [form, setForm] = useState({ label: "", environment_id: "", closes_at: "" });
  const [scheduleDraft, setScheduleDraft] = useState("daily");
  const navigate = useNavigate();

  useEffect(() => {
    let cancelled = false;
    Promise.all([
      getCurrentUserRoleInOrganization(organizationId).catch(() => null),
      getEnvironments(organizationId).catch(() => []),
      getScanSchedule(organizationId).catch(() => ({ schedule: "daily" })),
    ]).then(([nextRole, envs, schedule]) => {
      if (cancelled) return;
      setRole(nextRole);
      setEnvironments(envs || []);
      setScheduleDraft(schedule.schedule || "daily");
    });
    return () => { cancelled = true; };
  }, [organizationId]);

  const requestKey = JSON.stringify([status, offset]);
  const loading = result.key !== requestKey;

  function reload() {
    return getScanRuns(organizationId, { status, limit: PAGE_SIZE, offset }).then((data) => {
      setResult({
        key: requestKey, items: data.items || [], total: data.total || 0,
        schedule: data.schedule || "daily", error: "",
      });
      setScheduleDraft(data.schedule || "daily");
    });
  }

  useEffect(() => {
    let cancelled = false;
    getScanRuns(organizationId, { status, limit: PAGE_SIZE, offset })
      .then((data) => {
        if (!cancelled) {
          setResult({
            key: requestKey, items: data.items || [], total: data.total || 0,
            schedule: data.schedule || "daily", error: "",
          });
        }
      })
      .catch((error) => {
        if (!cancelled) setResult((prev) => ({ ...prev, key: requestKey, error: error.message || "Не удалось получить данные" }));
      });
    return () => { cancelled = true; };
  }, [organizationId, status, offset, requestKey]);

  async function handleExport(run, format) {
    const key = `${run.id}-${format}`;
    setBusyKey(key);
    setExportError("");
    try {
      const { blob, filename } = await downloadRunExport(run.id, format);
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (error) {
      setExportError(`Не удалось сформировать ${format === "pdf" ? "PDF" : "Excel"}: ${error.message}`);
    } finally {
      setBusyKey("");
    }
  }

  function toggleSelected(run) {
    setSelected((current) => {
      if (current.some((item) => item.id === run.id)) return current.filter((item) => item.id !== run.id);
      return [...current, run].slice(-2);
    });
  }

  function compareSelected() {
    const [a, b] = selected;
    if (!a || !b) return;
    const [before, after] = new Date(a.opened_at) <= new Date(b.opened_at) ? [a, b] : [b, a];
    navigate(`/scan-runs/compare?before=${before.id}&after=${after.id}`);
  }

  async function handleOpen(event) {
    event.preventDefault();
    setOpening(true);
    setActionError("");
    try {
      await openScanRun(organizationId, {
        label: form.label.trim() || null,
        environment_id: form.environment_id || null,
        closes_at: form.closes_at ? new Date(form.closes_at).toISOString() : null,
      });
      setForm({ label: "", environment_id: "", closes_at: "" });
      setOffset(0);
      await reload();
    } catch (error) {
      setActionError(error.message);
    } finally {
      setOpening(false);
    }
  }

  async function handleClose(run) {
    setActionError("");
    try {
      await closeScanRun(run.id);
      await reload();
    } catch (error) {
      setActionError(error.message);
    }
  }

  async function handleSchedule(event) {
    event.preventDefault();
    setActionError("");
    try {
      const saved = await setScanSchedule(organizationId, scheduleDraft);
      setScheduleDraft(saved.schedule);
      setResult((prev) => ({ ...prev, schedule: saved.schedule }));
    } catch (error) {
      setActionError(error.message);
    }
  }

  const rows = result.items;
  const firstLoad = result.key === null;
  const openCount = rows.filter((item) => item.status === "open").length;
  const latest = rows[0];

  return (
    <>
      <div className="grid gap-4 md:grid-cols-4">
        <StatCard label="Всего прогонов" value={result.total} loading={firstLoad} hint="Волны сканирования" tone="info" />
        <StatCard label="На странице открыто" value={openCount} loading={firstLoad} hint="Ещё принимают хосты" tone="success" />
        <StatCard
          label="Хостов в последнем"
          value={latest ? latest.hosts : "—"}
          loading={firstLoad}
          hint="Последний прогон"
          tone="default"
        />
        <StatCard
          label="Оценка последнего"
          value={latest ? scoreText(latest.compliance_score) : "—"}
          loading={firstLoad}
          hint="Соблюдено / проверенное"
          tone="default"
        />
      </div>

      {exportError ? (
        <div className="flex items-start justify-between gap-4 rounded-2xl border border-rose-500/20 bg-rose-500/10 px-4 py-3 text-sm text-rose-300">
          <span>{exportError}</span>
          <button type="button" onClick={() => setExportError("")} className="shrink-0 text-rose-300/70 hover:text-rose-200">
            Закрыть
          </button>
        </div>
      ) : null}
      {actionError ? (
        <div className="rounded-2xl border border-rose-500/20 bg-rose-500/10 px-4 py-3 text-sm text-rose-300">{actionError}</div>
      ) : null}

      <AppCard
        title="Расписание агентов"
        subtitle="Автопрогон: сутки или неделя в часовом поясе сервера плюс час случайной задержки. Уже открытый прогон не переписывается."
      >
        <form className="flex flex-wrap items-end gap-3" onSubmit={handleSchedule}>
          <label className="text-sm text-zinc-400">
            Расписание
            <select
              aria-label="Расписание агентов"
              className={`${SELECT} mt-1 block`}
              value={scheduleDraft}
              disabled={role !== "admin"}
              onChange={(event) => setScheduleDraft(event.target.value)}
            >
              <option value="daily">Ежедневно + 1 ч</option>
              <option value="weekly">Еженедельно + 1 ч</option>
            </select>
          </label>
          {role === "admin" ? (
            <button type="submit" className="rounded-xl border border-zinc-700 px-3 py-2 text-sm text-white hover:bg-zinc-800">
              Сохранить расписание
            </button>
          ) : (
            <span className="pb-2 text-sm text-zinc-500">Меняет администратор организации.</span>
          )}
        </form>
      </AppCard>

      {role === "admin" ? (
        <AppCard title="Открыть прогон" subtitle="Пока прогон открыт, новые снимки этой области попадают в него, а не в автоокно. Для волны GPO на несколько суток.">
          <form className="grid items-end gap-3 md:grid-cols-4" onSubmit={handleOpen}>
            <label className="text-sm text-zinc-400">
              Метка
              <input className={`${INPUT} mt-1 w-full`} value={form.label} maxLength={200} placeholder="Волна GPO" onChange={(event) => setForm({ ...form, label: event.target.value })} />
            </label>
            <label className="text-sm text-zinc-400">
              Область
              <select aria-label="Область прогона" className={`${SELECT} mt-1 w-full`} value={form.environment_id} onChange={(event) => setForm({ ...form, environment_id: event.target.value })}>
                <option value="">Вся организация</option>
                {environments.map((env) => <option key={env.id} value={env.id}>{env.name}</option>)}
              </select>
            </label>
            <label className="text-sm text-zinc-400">
              Закрыть автоматически
              <input type="datetime-local" aria-label="Закрыть автоматически" className={`${INPUT} mt-1 w-full`} value={form.closes_at} onChange={(event) => setForm({ ...form, closes_at: event.target.value })} />
            </label>
            <button type="submit" disabled={opening} className="rounded-xl border border-blue-500/30 bg-blue-500/15 px-3 py-2 text-sm text-blue-200 hover:bg-blue-500/25 disabled:opacity-40">
              {opening ? "Открываю…" : "Открыть прогон"}
            </button>
          </form>
        </AppCard>
      ) : null}

      <AppCard title="Прогоны" subtitle="Сравнение — прогон с прогоном. Внутри прогона — все хосты.">
        {result.total > 0 ? (
          <div className="mb-4 flex flex-wrap items-center gap-3 rounded-xl border border-zinc-800 bg-zinc-950/70 px-4 py-3 text-sm">
            <span className="text-zinc-400">Отметьте два прогона для сравнения: выбрано {selected.length} из 2</span>
            <button
              type="button"
              disabled={selected.length !== 2}
              onClick={compareSelected}
              className="rounded-lg border border-blue-500/30 bg-blue-500/15 px-3 py-1.5 text-xs text-blue-200 hover:bg-blue-500/25 disabled:opacity-40"
            >
              Сравнить выбранные
            </button>
            {selected.length ? (
              <button type="button" onClick={() => setSelected([])} className="text-xs text-zinc-400 underline hover:text-white">сбросить</button>
            ) : null}
            <select
              aria-label="Состояние"
              className={`${SELECT} ml-auto`}
              value={status}
              onChange={(event) => { setStatus(event.target.value); setOffset(0); }}
            >
              <option value="">Все прогоны</option>
              <option value="open">Открытые</option>
              <option value="closed">Закрытые</option>
            </select>
          </div>
        ) : null}
        {result.error ? (
          <ErrorState title="Ошибка загрузки" description={result.error} />
        ) : firstLoad ? (
          <SkeletonTable rows={6} cols={8} />
        ) : result.total === 0 ? (
          <EmptyState title="Нет прогонов" description="Прогон появится после первого отчёта агента или проверки по выгрузке." />
        ) : (
          <div className={`overflow-x-auto ${loading ? "opacity-60" : ""}`}>
            <table className="min-w-full text-sm">
              <thead className="border-b border-zinc-800 text-left text-zinc-400">
                <tr>
                  <th className="px-4 py-3"><span className="sr-only">Выбрать для сравнения</span></th>
                  <th className="px-4 py-3">Прогон</th>
                  <th className="px-4 py-3">Окно</th>
                  <th className="px-4 py-3">Состояние</th>
                  <th className="px-4 py-3">Хосты</th>
                  <th className="px-4 py-3">Нарушено</th>
                  <th className="px-4 py-3">Оценка</th>
                  <th className="px-4 py-3">PDF</th>
                  <th className="px-4 py-3">Excel</th>
                  <th className="px-4 py-3">С предыдущим</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((item) => {
                  const pdfBusy = busyKey === `${item.id}-pdf`;
                  const excelBusy = busyKey === `${item.id}-excel`;
                  const checked = selected.some((run) => run.id === item.id);
                  return (
                    <tr key={item.id} className={`border-b border-zinc-800/60 text-zinc-200 hover:bg-zinc-800/40 ${checked ? "bg-blue-500/10" : ""}`}>
                      <td className="px-4 py-3">
                        <input
                          type="checkbox"
                          aria-label={`Выбрать прогон №${item.run_number} для сравнения`}
                          checked={checked}
                          onChange={() => toggleSelected(item)}
                          className="h-4 w-4 accent-blue-500"
                        />
                      </td>
                      <td className="px-4 py-3">
                        <Link to={`/scans/${item.id}`} className="font-medium text-white underline-offset-2 hover:underline" aria-label={`Открыть прогон №${item.run_number}`}>
                          {item.label || `Прогон №${item.run_number}`}
                        </Link>
                        <div className="mt-1 text-xs text-zinc-500">
                          №{item.run_number}
                          {item.environment_name ? ` · ${item.environment_name}` : ""}
                          {item.source === "manual" ? " · вручную" : ""}
                        </div>
                      </td>
                      <td className="px-4 py-3 text-zinc-300">
                        {formatDateTime(item.opened_at)}
                        {item.window_ends_at ? <div className="text-xs text-zinc-500">до {formatDateTime(item.window_ends_at)}</div> : null}
                      </td>
                      <td className="px-4 py-3">
                        <span className={`rounded-full border px-3 py-1 text-xs ${statusClass(item.status)}`}>{statusLabel(item.status)}</span>
                        {role === "admin" && item.status === "open" ? (
                          <button type="button" onClick={() => handleClose(item)} className="ml-2 text-xs text-zinc-400 underline hover:text-white" aria-label={`Закрыть прогон №${item.run_number}`}>
                            Закрыть
                          </button>
                        ) : null}
                      </td>
                      <td className="px-4 py-3">{item.hosts}</td>
                      <td className="px-4 py-3">{item.failed}</td>
                      <td className={`px-4 py-3 font-semibold ${getScoreTone(item.compliance_score).text}`}>{scoreText(item.compliance_score)}</td>
                      <td className="px-4 py-3">
                        <button type="button" disabled={pdfBusy} aria-label={`Скачать PDF прогона №${item.run_number}`} onClick={() => handleExport(item, "pdf")} className="rounded-lg border border-zinc-700 px-3 py-1.5 text-xs text-white hover:bg-zinc-800 disabled:opacity-50">
                          {pdfBusy ? "..." : "Скачать PDF"}
                        </button>
                      </td>
                      <td className="px-4 py-3">
                        <button type="button" disabled={excelBusy} aria-label={`Скачать Excel прогона №${item.run_number}`} onClick={() => handleExport(item, "excel")} className="rounded-lg border border-zinc-700 px-3 py-1.5 text-xs text-white hover:bg-zinc-800 disabled:opacity-50">
                          {excelBusy ? "..." : "Скачать Excel"}
                        </button>
                      </td>
                      <td className="px-4 py-3">
                        {item.previous_run_id ? (
                          <Link to={`/scan-runs/compare?before=${item.previous_run_id}&after=${item.id}`} aria-label={`Сравнить прогон №${item.run_number} с предыдущим`} className="rounded-lg border border-zinc-700 px-3 py-1.5 text-xs text-white hover:bg-zinc-800">
                            Сравнить
                          </Link>
                        ) : <span className="text-zinc-500">—</span>}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        {result.total > PAGE_SIZE ? (
          <div className="mt-4 flex items-center gap-3 text-sm text-zinc-400">
            <button type="button" className={PAGER} disabled={offset === 0 || loading} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}>Назад</button>
            <span>{offset + 1}–{Math.min(offset + PAGE_SIZE, result.total)} из {result.total}</span>
            <button type="button" className={PAGER} disabled={offset + PAGE_SIZE >= result.total || loading} onClick={() => setOffset(offset + PAGE_SIZE)}>Вперёд</button>
          </div>
        ) : null}
      </AppCard>
    </>
  );
}
