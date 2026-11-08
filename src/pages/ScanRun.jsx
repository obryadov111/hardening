import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import AppCard from "../components/ui/AppCard";
import StatCard from "../components/ui/StatCard";
import EmptyState from "../components/ui/EmptyState";
import ErrorState from "../components/ui/ErrorState";
import OrgGate from "../components/OrgGate";
import { SkeletonTable } from "../components/ui/Skeleton";
import { getScoreTone } from "../utils/score";
import { useOrganization } from "../context/OrganizationContext";
import { getScanRun, getScanRunFindings, getScanRunHosts } from "../api/scanRuns";
import { downloadRunExport } from "../api/exports";
import { formatDateTime } from "../utils/datetime";
import { collectionSource } from "../utils/collection";

const PAGE_SIZE = 50;
const PAGER = "rounded-xl border border-zinc-700 px-3 py-1.5 text-sm text-zinc-200 hover:bg-zinc-800 disabled:opacity-40";
const SELECT = "rounded-xl border border-zinc-800 bg-zinc-950 px-3 py-2 text-sm text-white outline-none";
const INPUT = "rounded-xl border border-zinc-800 bg-zinc-950 px-3 py-2 text-sm text-white outline-none";

function scoreText(value) {
  return value != null ? `${Math.round(value)}%` : "—";
}

export default function ScanRun() {
  const { runId } = useParams();
  const { loading: orgLoading, hasOrganizations, error: orgError } = useOrganization();

  return (
    <OrgGate title="Прогон" orgLoading={orgLoading} orgError={orgError} hasOrganizations={hasOrganizations}>
      <RunView key={runId} runId={runId} />
    </OrgGate>
  );
}

function RunView({ runId }) {
  const [run, setRun] = useState(null);
  const [loadError, setLoadError] = useState("");
  const [hosts, setHosts] = useState({ key: null, items: [], total: 0, error: "" });
  const [findings, setFindings] = useState({ items: [], total: 0, error: "" });
  const [q, setQ] = useState("");
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState("");
  const [environmentId, setEnvironmentId] = useState("");
  const [offset, setOffset] = useState(0);
  const [exportError, setExportError] = useState("");
  const [busy, setBusy] = useState("");

  useEffect(() => {
    let cancelled = false;
    setRun(null);
    setLoadError("");
    getScanRun(runId)
      .then((data) => { if (!cancelled) setRun(data); })
      .catch((error) => { if (!cancelled) setLoadError(error.message || "Не удалось получить прогон"); });
    getScanRunFindings(runId)
      .then((data) => { if (!cancelled) setFindings({ items: data.items || [], total: data.total || 0, error: "" }); })
      .catch((error) => { if (!cancelled) setFindings({ items: [], total: 0, error: error.message }); });
    return () => { cancelled = true; };
  }, [runId]);

  const requestKey = JSON.stringify([query, status, environmentId, offset]);
  const hostsLoading = hosts.key !== requestKey;

  useEffect(() => {
    let cancelled = false;
    getScanRunHosts(runId, { q: query, status, environmentId, limit: PAGE_SIZE, offset })
      .then((data) => {
        if (!cancelled) setHosts({ key: requestKey, items: data.items || [], total: data.total || 0, error: "" });
      })
      .catch((error) => {
        if (!cancelled) setHosts((prev) => ({ ...prev, key: requestKey, error: error.message || "Не удалось получить хосты" }));
      });
    return () => { cancelled = true; };
  }, [runId, query, status, environmentId, offset, requestKey]);

  async function handleExport(format) {
    setBusy(format);
    setExportError("");
    try {
      const { blob, filename } = await downloadRunExport(runId, format);
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
      setBusy("");
    }
  }

  if (loadError) {
    return (
      <div className="space-y-4">
        <h1 className="text-2xl font-semibold text-white">Прогон</h1>
        <ErrorState title="Ошибка загрузки" description={loadError} />
      </div>
    );
  }
  if (!run) {
    return (
      <div className="space-y-4">
        <h1 className="text-2xl font-semibold text-white">Прогон</h1>
        <SkeletonTable rows={4} cols={4} />
      </div>
    );
  }

  const title = run.label || `Прогон №${run.run_number}`;
  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <Link to="/scans" className="text-sm text-zinc-400 underline hover:text-white">Все прогоны</Link>
          <h1 className="mt-1 text-2xl font-semibold text-white">{title}</h1>
          <p className="mt-1 text-sm text-zinc-400">
            №{run.run_number} · {run.status === "open" ? "открыт" : "закрыт"}
            {run.environment_name ? ` · ${run.environment_name}` : " · вся организация"}
            {" · "}
            {formatDateTime(run.opened_at)}
            {run.window_ends_at ? ` — ${formatDateTime(run.window_ends_at)}` : ""}
          </p>
        </div>
        <div className="flex gap-2">
          <button type="button" disabled={busy === "pdf"} onClick={() => handleExport("pdf")} className="rounded-lg border border-zinc-700 px-3 py-1.5 text-xs text-white hover:bg-zinc-800 disabled:opacity-50">
            {busy === "pdf" ? "..." : "Скачать PDF"}
          </button>
          <button type="button" disabled={busy === "excel"} onClick={() => handleExport("excel")} className="rounded-lg border border-zinc-700 px-3 py-1.5 text-xs text-white hover:bg-zinc-800 disabled:opacity-50">
            {busy === "excel" ? "..." : "Скачать Excel"}
          </button>
        </div>
      </div>
      {exportError ? <div className="rounded-2xl border border-rose-500/20 bg-rose-500/10 px-4 py-3 text-sm text-rose-300">{exportError}</div> : null}

      <div className="grid gap-4 md:grid-cols-4">
        <StatCard label="Хостов" value={run.hosts} hint="В этом прогоне" tone="info" />
        <StatCard label="Оценка" value={scoreText(run.compliance_score)} hint="Соблюдено / проверенное" tone="default" />
        <StatCard label="Нарушено" value={run.failed} hint="Без принятого риска" tone="danger" />
        <StatCard label="Риск принят" value={run.accepted_risks} hint="Не входит в оценку" tone="warning" />
      </div>

      <AppCard title="Нарушения по правилам" subtitle="Сколько хостов задело каждое открытое нарушение. Принятый риск не считается.">
        {findings.error ? <ErrorState title="Ошибка загрузки" description={findings.error} /> : findings.total === 0 ? (
          <EmptyState title="Нарушений нет" description="В снимках этого прогона нет открытых нарушений." />
        ) : (
          <div className="overflow-x-auto">
            <table aria-label="Нарушения прогона" className="min-w-full text-sm">
              <thead className="border-b border-zinc-800 text-left text-zinc-400">
                <tr>
                  <th className="px-4 py-3">Проверка</th>
                  <th className="px-4 py-3">Уровень</th>
                  <th className="px-4 py-3">Хостов</th>
                </tr>
              </thead>
              <tbody>
                {findings.items.map((item) => (
                  <tr key={`${item.check_key}-${item.severity}`} className="border-b border-zinc-800/60 text-zinc-200">
                    <td className="px-4 py-3">
                      <div className="text-white">{item.title || item.check_key}</div>
                      <div className="text-xs text-zinc-500">{item.check_key}</div>
                    </td>
                    <td className="px-4 py-3">{item.severity || "—"}</td>
                    <td className="px-4 py-3">{item.hosts}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </AppCard>

      <AppCard title="Хосты" subtitle="Один хост — последний снимок в этом прогоне. Поиск и страницы, чтобы список на сотни машин не грузился целиком.">
        <form
          className="mb-4 flex flex-wrap items-end gap-3"
          onSubmit={(event) => { event.preventDefault(); setOffset(0); setQuery(q.trim()); }}
        >
          <label className="text-sm text-zinc-400">
            Поиск
            <input aria-label="Поиск" className={`${INPUT} mt-1 block w-56`} value={q} placeholder="имя или IP" onChange={(event) => setQ(event.target.value)} />
          </label>
          <label className="text-sm text-zinc-400">
            Состояние
            <select aria-label="Состояние хоста" className={`${SELECT} mt-1 block`} value={status} onChange={(event) => { setStatus(event.target.value); setOffset(0); }}>
              <option value="">Все</option>
              <option value="failed">Есть нарушения</option>
              <option value="clean">Без нарушений</option>
              <option value="unchecked">Есть непроверенное</option>
            </select>
          </label>
          <label className="text-sm text-zinc-400">
            Окружение
            <select aria-label="Окружение" className={`${SELECT} mt-1 block`} value={environmentId} onChange={(event) => { setEnvironmentId(event.target.value); setOffset(0); }}>
              <option value="">Все</option>
              {(run.environments || []).map((env) => <option key={env.id} value={env.id}>{env.name}</option>)}
            </select>
          </label>
          <button type="submit" className="rounded-xl border border-zinc-700 px-3 py-2 text-sm text-white hover:bg-zinc-800">Найти</button>
        </form>
        {hosts.error ? (
          <ErrorState title="Ошибка загрузки" description={hosts.error} />
        ) : hosts.key === null ? (
          <SkeletonTable rows={5} cols={6} />
        ) : hosts.total === 0 ? (
          <div className="text-sm text-zinc-400">{query || status || environmentId ? "Ничего не найдено." : "В прогоне нет хостов."}</div>
        ) : (
          <div className={`overflow-x-auto ${hostsLoading ? "opacity-60" : ""}`}>
            <table aria-label="Хосты прогона" className="min-w-full text-sm">
              <thead className="border-b border-zinc-800 text-left text-zinc-400">
                <tr>
                  <th className="px-4 py-3">Хост</th>
                  <th className="px-4 py-3">Окружение</th>
                  <th className="px-4 py-3">Снимок</th>
                  <th className="px-4 py-3">Нарушено</th>
                  <th className="px-4 py-3">Не проверено</th>
                  <th className="px-4 py-3">Оценка</th>
                </tr>
              </thead>
              <tbody>
                {hosts.items.map((item) => {
                  const source = collectionSource(item.collection);
                  return (
                    <tr key={item.snapshot_id} className="border-b border-zinc-800/60 text-zinc-200">
                      <td className="px-4 py-3">
                        {item.asset_id ? (
                          <Link to={`/assets/${item.asset_id}`} className="font-medium text-white underline-offset-2 hover:underline">
                            {item.hostname || "—"}
                          </Link>
                        ) : <span>{item.hostname || "—"}</span>}
                        <div className="text-xs text-zinc-500">{item.ip_address || item.os || ""}</div>
                      </td>
                      <td className="px-4 py-3">{item.environment_name || "—"}</td>
                      <td className="px-4 py-3">
                        <div>{item.snapshot_label || `№${item.scan_number}`}</div>
                        {source ? (
                          <div className="mt-1 inline-block rounded-full border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 text-xs text-amber-300" title={source.text}>
                            {source.short}
                          </div>
                        ) : <div className="text-xs text-zinc-500">агент</div>}
                      </td>
                      <td className="px-4 py-3">{item.failed ?? 0}</td>
                      <td className="px-4 py-3">{item.not_checked ?? 0}</td>
                      <td className={`px-4 py-3 font-semibold ${getScoreTone(item.compliance_score).text}`}>{scoreText(item.compliance_score)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        {hosts.total > PAGE_SIZE ? (
          <div className="mt-4 flex items-center gap-3 text-sm text-zinc-400">
            <button type="button" className={PAGER} disabled={offset === 0 || hostsLoading} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}>Назад</button>
            <span>{offset + 1}–{Math.min(offset + PAGE_SIZE, hosts.total)} из {hosts.total}</span>
            <button type="button" className={PAGER} disabled={offset + PAGE_SIZE >= hosts.total || hostsLoading} onClick={() => setOffset(offset + PAGE_SIZE)}>Вперёд</button>
          </div>
        ) : null}
      </AppCard>
    </div>
  );
}
