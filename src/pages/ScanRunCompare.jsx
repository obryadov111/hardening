import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import AppCard from "../components/ui/AppCard";
import StatCard from "../components/ui/StatCard";
import ErrorState from "../components/ui/ErrorState";
import OrgGate from "../components/OrgGate";
import { useOrganization } from "../context/OrganizationContext";
import { compareScanRuns, getScanRuns } from "../api/scanRuns";
import { formatDateTime } from "../utils/datetime";

const SELECT = "w-full rounded-xl border border-zinc-800 bg-zinc-950 px-3 py-2 text-sm text-white outline-none";

function changeLabel(changeType) {
  switch (changeType) {
    case "fixed": return "Исправлено";
    case "regressed": return "Ухудшилось";
    case "still_failed": return "Не исправлено";
    case "new": return "Новая запись";
    case "removed": return "Удалено";
    case "changed": return "Изменилось";
    case "accepted": return "Риск принят";
    default: return changeType;
  }
}

function changeClass(changeType) {
  switch (changeType) {
    case "fixed": return "text-emerald-300";
    case "regressed": return "text-rose-300";
    case "still_failed": return "text-amber-300";
    case "new": return "text-blue-300";
    case "accepted": return "text-fuchsia-300";
    default: return "text-zinc-300";
  }
}

function runLabel(run) {
  if (!run) return "—";
  const score = run.compliance_score != null ? ` · ${Math.round(run.compliance_score)}%` : "";
  return `№${run.run_number}${run.label ? ` «${run.label}»` : ""} · ${formatDateTime(run.opened_at, "без даты")}${score} · хостов ${run.hosts ?? "—"}`;
}

function scoreText(value) {
  return value != null ? `${Math.round(value)}%` : "—";
}

export default function ScanRunCompare() {
  const { selectedOrganizationId, loading: orgLoading, hasOrganizations, error: orgError } = useOrganization();
  return (
    <OrgGate title="Сравнение прогонов" orgLoading={orgLoading} orgError={orgError} hasOrganizations={hasOrganizations}>
      {selectedOrganizationId ? <CompareView key={selectedOrganizationId} organizationId={selectedOrganizationId} /> : null}
    </OrgGate>
  );
}

function CompareView({ organizationId }) {
  const [params, setSearchParams] = useSearchParams();
  const beforeId = params.get("before") || "";
  const afterId = params.get("after") || "";
  const [runs, setRuns] = useState([]);
  const [listError, setListError] = useState("");
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    let cancelled = false;
    getScanRuns(organizationId, { limit: 200 })
      .then((page) => { if (!cancelled) { setRuns(page.items || []); setListError(""); } })
      .catch((err) => { if (!cancelled) { setRuns([]); setListError(err.message || "Не удалось получить данные"); } });
    return () => { cancelled = true; };
  }, [organizationId]);

  useEffect(() => {
    if (beforeId || afterId || runs.length < 2) return;
    const latest = runs[0];
    const previous = latest.previous_run_id || runs[1].id;
    setSearchParams({ before: previous, after: latest.id }, { replace: true });
  }, [beforeId, afterId, runs, setSearchParams]);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      if (!beforeId || !afterId || beforeId === afterId) {
        setData(null);
        setLoading(false);
        return;
      }
      setLoading(true);
      setError("");
      try {
        const body = await compareScanRuns(beforeId, afterId);
        if (!cancelled) setData(body);
      } catch (err) {
        if (!cancelled) {
          setData(null);
          setError(err.message);
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    load();
    return () => { cancelled = true; };
  }, [beforeId, afterId]);

  const byId = useMemo(() => Object.fromEntries(runs.map((run) => [run.id, run])), [runs]);
  const reversed = beforeId && afterId && byId[beforeId] && byId[afterId]
    && new Date(byId[beforeId].opened_at) > new Date(byId[afterId].opened_at);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-white">Сравнение прогонов</h1>
        <p className="mt-1 text-sm text-zinc-400">
          {data
            ? `Прогон №${data.before.run_number} → прогон №${data.after.run_number}`
            : "Выберите два прогона: было и стало"}
        </p>
      </div>

      <AppCard title="Какие прогоны сравнить" subtitle="Оценка — по всем проверкам прогона, не среднее процентов хостов">
        <form
          className="grid items-end gap-3 md:grid-cols-[1fr_auto_1fr_auto]"
          onSubmit={(event) => {
            event.preventDefault();
            const before = event.currentTarget.before.value;
            const after = event.currentTarget.after.value;
            if (before && after) setSearchParams({ before, after });
          }}
        >
          <label className="text-sm text-zinc-400">
            Было
            <select name="before" aria-label="Было" className={`${SELECT} mt-1`} defaultValue={beforeId} key={`b-${beforeId}`}>
              <option value="">— выберите прогон —</option>
              {runs.map((run) => <option key={run.id} value={run.id}>{runLabel(run)}</option>)}
            </select>
          </label>
          <button type="button" aria-label="Поменять местами" className="rounded-xl border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-300 hover:bg-zinc-800" onClick={() => setSearchParams({ before: afterId, after: beforeId })}>
            ⇄
          </button>
          <label className="text-sm text-zinc-400">
            Стало
            <select name="after" aria-label="Стало" className={`${SELECT} mt-1`} defaultValue={afterId} key={`a-${afterId}`}>
              <option value="">— выберите прогон —</option>
              {runs.map((run) => <option key={run.id} value={run.id}>{runLabel(run)}</option>)}
            </select>
          </label>
          <button type="submit" disabled={!beforeId || !afterId || beforeId === afterId} className="rounded-xl border border-blue-500/30 bg-blue-500/15 px-3 py-2 text-sm text-blue-200 hover:bg-blue-500/25 disabled:opacity-40">
            Сравнить
          </button>
        </form>
        {beforeId && afterId && beforeId === afterId ? (
          <p className="mt-3 text-sm text-amber-300">Выбран один и тот же прогон — выберите два разных.</p>
        ) : null}
        {reversed ? <p className="mt-3 text-sm text-amber-300">«Было» новее, чем «стало».</p> : null}
      </AppCard>

      {listError ? <ErrorState title="Ошибка загрузки" description={listError} /> : null}
      {loading ? <div className="text-zinc-400">Загрузка сравнения...</div> : null}
      {error ? <div className="rounded-xl border border-rose-500/20 bg-rose-500/10 px-4 py-3 text-sm text-rose-300">Не удалось сравнить прогоны: {error}</div> : null}
      {!loading && !error && !data && runs.length < 2 ? (
        <div className="text-zinc-500">Для сравнения нужно хотя бы два прогона в организации.</div>
      ) : null}

      {data ? <Result data={data} /> : null}
    </div>
  );
}

function Result({ data }) {
  const delta = data.score.delta;
  const deltaText = delta == null ? "—" : `${delta > 0 ? "+" : ""}${delta}`;
  return (
    <>
      <div className="grid gap-4 md:grid-cols-4">
        <StatCard label="Было" value={scoreText(data.score.before)} hint={`Прогон №${data.before.run_number}`} />
        <StatCard label="Стало" value={scoreText(data.score.after)} hint={`Прогон №${data.after.run_number}`} />
        <StatCard label="Динамика оценки" value={deltaText} hint="Пункты процента" tone={delta > 0 ? "success" : delta < 0 ? "danger" : "default"} />
        <StatCard label="Исправлено" value={data.summary.fixed} hint="На общих хостах" tone="success" />
      </div>
      <div className="grid gap-4 md:grid-cols-4">
        <StatCard label="Ухудшилось" value={data.summary.regressed} tone="danger" />
        <StatCard label="Новые нарушения" value={data.summary.newIssues} tone="warning" />
        <StatCard label="Добавились хосты" value={data.hostsAdded.length} hint="Их не было в прошлом прогоне" tone="info" />
        <StatCard label="Пропали хосты" value={data.hostsRemoved.length} hint="Не прислали снимок" />
      </div>

      {data.hostsAdded.length ? (
        <AppCard title="Добавились" subtitle="Хост есть только в новом прогоне. Его нарушения не входят в «новые»: это не исправление и не регресс.">
          <HostList hosts={data.hostsAdded} />
        </AppCard>
      ) : null}
      {data.hostsRemoved.length ? (
        <AppCard title="Пропали" subtitle="Хост был в прошлом прогоне и не попал в новый.">
          <HostList hosts={data.hostsRemoved} />
        </AppCard>
      ) : null}

      <AppCard title="По хостам" subtitle="Раскройте строку, чтобы увидеть проверки. Общие хосты — что изменилось. Остальные — только присутствие.">
        <div className="space-y-2">
          {data.hosts.items.map((host) => (
            <details key={host.assetId} className="rounded-xl border border-zinc-800 bg-zinc-950/40 px-4 py-3">
              <summary className="cursor-pointer text-sm text-white">
                {host.hostname || "—"}
                <span className="ml-2 text-zinc-400">
                  {host.presence === "added" ? "добавился" : host.presence === "removed" ? "пропал" : "общий"}
                  {host.beforeScore != null ? ` · было ${Math.round(host.beforeScore)}%` : ""}
                  {host.afterScore != null ? ` · стало ${Math.round(host.afterScore)}%` : ""}
                  {host.summary.fixed ? ` · исправлено ${host.summary.fixed}` : ""}
                  {host.summary.regressed ? ` · ухудшилось ${host.summary.regressed}` : ""}
                </span>
              </summary>
              {host.diffs.length ? (
                <table className="mt-3 min-w-full text-sm">
                  <thead className="text-left text-zinc-500">
                    <tr>
                      <th className="py-1 pr-3">Проверка</th>
                      <th className="py-1 pr-3">Было</th>
                      <th className="py-1 pr-3">Стало</th>
                      <th className="py-1">Изменение</th>
                    </tr>
                  </thead>
                  <tbody>
                    {host.diffs.map((diff) => (
                      <tr key={diff.key} className="border-t border-zinc-800/80 text-zinc-200">
                        <td className="py-2 pr-3">
                          <div>{diff.rule.title || diff.rule.rule_code}</div>
                          <div className="text-xs text-zinc-500">{diff.rule.rule_code}</div>
                        </td>
                        <td className="py-2 pr-3">{diff.beforeStatus || "—"}</td>
                        <td className="py-2 pr-3">{diff.afterStatus || "—"}</td>
                        <td className={`py-2 ${changeClass(diff.changeType)}`}>{changeLabel(diff.changeType)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <p className="mt-2 text-sm text-zinc-500">
                  {host.presence === "both" ? "На общих проверках изменений нет." : "Проверки этого хоста в сводку динамики не входят."}
                  {host.afterFailed != null ? ` Нарушений в снимке: ${host.afterFailed}.` : ""}
                  {host.beforeFailed != null && host.presence === "removed" ? ` Было нарушений: ${host.beforeFailed}.` : ""}
                </p>
              )}
              {host.assetId ? (
                <Link to={`/assets/${host.assetId}`} className="mt-2 inline-block text-xs text-blue-300 underline">Карточка хоста</Link>
              ) : null}
            </details>
          ))}
        </div>
      </AppCard>
    </>
  );
}

function HostList({ hosts }) {
  return (
    <ul className="flex flex-wrap gap-2 text-sm text-zinc-200">
      {hosts.map((host) => (
        <li key={host.assetId} className="rounded-full border border-zinc-700 px-3 py-1">
          {host.assetId ? <Link to={`/assets/${host.assetId}`} className="hover:underline">{host.hostname || "—"}</Link> : (host.hostname || "—")}
          <span className="text-zinc-500"> · нарушений {host.failed}</span>
        </li>
      ))}
    </ul>
  );
}
