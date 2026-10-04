import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import AppCard from "../components/ui/AppCard";
import StatCard from "../components/ui/StatCard";
import OrgGate from "../components/OrgGate";
import CheckStatusBadge from "../components/ui/CheckStatusBadge";
import { SkeletonTable } from "../components/ui/Skeleton";
import { useOrganization } from "../context/OrganizationContext";
import { getFstecCoverage } from "../api/fstec";

// Статусы пункта методики (app/services/fstec/coverage.py).
const STATUS = {
  violated: { label: "нарушено", tone: "border-rose-500/30 bg-rose-500/15 text-rose-300", card: "danger" },
  accepted: { label: "риск принят", tone: "border-violet-500/30 bg-violet-500/15 text-violet-300", card: "default" },
  not_checked: { label: "не проверено", tone: "border-amber-500/30 bg-amber-500/15 text-amber-300", card: "warning" },
  passed: { label: "соблюдено", tone: "border-emerald-500/30 bg-emerald-500/15 text-emerald-300", card: "success" },
  not_applied: { label: "не применялось", tone: "border-blue-500/30 bg-blue-500/15 text-blue-300", card: "info" },
  no_checks: { label: "нет проверок", tone: "border-zinc-700 bg-zinc-800 text-zinc-300", card: "default" },
  out: { label: "вне модели", tone: "border-zinc-800 bg-zinc-900 text-zinc-500", card: "default" },
};
const ORDER = ["violated", "accepted", "not_checked", "passed", "not_applied", "no_checks", "out"];
const HINTS = {
  violated: "есть нарушение без принятого риска",
  accepted: "нарушения есть, по всем принят риск",
  not_checked: "проверки не выполнились",
  passed: "все проверки соблюдены",
  not_applied: "проверки есть, платформы нет",
  no_checks: "проверок пока нет",
  out: "другой класс инструментов",
};
const SELECT = "rounded-xl border border-zinc-800 bg-zinc-950 px-3 py-2 text-sm text-white outline-none";

function StatusBadge({ status }) {
  const info = STATUS[status] || STATUS.no_checks;
  return <span className={`inline-flex whitespace-nowrap rounded-full border px-2 py-1 text-xs font-medium ${info.tone}`}>{info.label}</span>;
}

function Details({ item }) {
  if (item.kind === "bdu" && item.findings) {
    const f = item.findings;
    return (
      <div className="text-xs text-zinc-400">
        Открытых находок БДУ: <span className="text-white">{f.total}</span>
        {f.total ? ` (критических ${f.critical}, высоких ${f.high}, средних ${f.medium}, низких ${f.low})` : ""}
        {" · "}<Link to="/vulnerabilities" className="text-blue-300 hover:underline">к уязвимостям ПО</Link>
      </div>
    );
  }
  if (!item.checks.length) return item.note ? <div className="text-xs text-zinc-500">{item.note}</div> : null;
  return (
    <details className="text-xs">
      <summary className="cursor-pointer text-zinc-400 hover:text-white">
        Проверок: {item.checks.length}
        {item.checks.some((c) => c.status === "fail") ? `, нарушено: ${item.checks.filter((c) => c.status === "fail").length}` : ""}
      </summary>
      <ul className="mt-2 space-y-1">
        {item.checks.map((c) => (
          <li key={`${c.asset}:${c.check_id}`} className="flex flex-wrap items-center gap-2">
            {c.status === "accepted" ? <StatusBadge status="accepted" /> : <CheckStatusBadge value={c.status} />}
            <span className="text-zinc-200">{c.title}</span>
            <span className="text-zinc-500">{c.check_id} · {c.asset} · {c.pack}</span>
          </li>
        ))}
      </ul>
    </details>
  );
}

export default function FstecCoverage() {
  const { selectedOrganization, selectedOrganizationId, loading: orgLoading, hasOrganizations, error: orgError } = useOrganization();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [filter, setFilter] = useState("");

  useEffect(() => {
    async function load() {
      if (!selectedOrganizationId) {
        setData(null);
        return;
      }
      try {
        setLoading(true);
        setError("");
        setData(await getFstecCoverage(selectedOrganizationId));
      } catch (err) {
        setError(err.message);
        setData(null);
      } finally {
        setLoading(false);
      }
    }
    if (!orgLoading) load();
  }, [selectedOrganizationId, orgLoading]);

  const sections = useMemo(
    () => (data?.sections || [])
      .map((s) => ({ ...s, items: s.items.filter((i) => !filter || i.status === filter) }))
      .filter((s) => s.items.length),
    [data, filter],
  );

  return (
    <OrgGate title="Методика ФСТЭК" orgLoading={orgLoading} orgError={orgError} hasOrganizations={hasOrganizations}>
      <div className="space-y-6">
        <div>
          <h1 className="text-2xl font-semibold text-white">Методика ФСТЭК: покрытие по пунктам</h1>
          <p className="mt-1 text-sm text-zinc-400">
            «Методика анализа защищённости информационных систем», ФСТЭК России, 25.11.2025, таблица 3 (внутреннее
            сканирование) — по текущему состоянию активов организации{" "}
            <span className="text-white">{selectedOrganization?.name || "—"}</span>
          </p>
        </div>

        {error ? (
          <div className="rounded-xl border border-rose-500/20 bg-rose-500/10 px-4 py-3 text-sm text-rose-300">Не удалось загрузить: {error}</div>
        ) : null}

        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-7">
          {ORDER.map((s) => (
            <StatCard key={s} label={STATUS[s].label} value={data?.summary?.[s] ?? 0} hint={HINTS[s]} tone={STATUS[s].card} loading={loading} />
          ))}
        </div>

        <AppCard title="Пункты методики" subtitle="Пункт закрывается проверками паков, у которых в источниках указан этот пункт; уязвимости ПО — по БДУ ФСТЭК">
          <div className="mb-4">
            <select className={SELECT} value={filter} onChange={(e) => setFilter(e.target.value)}>
              <option value="">Все пункты</option>
              {ORDER.map((s) => <option key={s} value={s}>{STATUS[s].label}</option>)}
            </select>
          </div>
          {loading ? (
            <SkeletonTable rows={10} cols={3} />
          ) : (
            <div className="space-y-6">
              {sections.map((section) => (
                <div key={section.code}>
                  <h3 className="mb-2 text-sm font-semibold text-white">{section.code} — {section.title}</h3>
                  <table className="min-w-full text-sm">
                    <tbody>
                      {section.items.map((item) => (
                        <tr key={item.code} className="border-b border-zinc-800/60 align-top">
                          <td className="w-24 px-3 py-2 font-mono text-xs text-zinc-300">{item.code}</td>
                          <td className="px-3 py-2">
                            <div className="text-zinc-200">{item.title}</div>
                            <div className="mt-1"><Details item={item} /></div>
                          </td>
                          <td className="w-36 px-3 py-2 text-right"><StatusBadge status={item.status} /></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ))}
              {!sections.length ? <div className="text-sm text-zinc-500">Нет пунктов с таким статусом.</div> : null}
            </div>
          )}
        </AppCard>
      </div>
    </OrgGate>
  );
}
