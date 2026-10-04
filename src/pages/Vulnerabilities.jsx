import { useEffect, useMemo, useState } from "react";
import AppCard from "../components/ui/AppCard";
import StatCard from "../components/ui/StatCard";
import EmptyState from "../components/ui/EmptyState";
import OrgGate from "../components/OrgGate";
import SeverityBadge from "../components/ui/SeverityBadge";
import { SkeletonTable } from "../components/ui/Skeleton";
import { useOrganization } from "../context/OrganizationContext";
import { getVulnerabilitiesByOrganization } from "../api/vulnerabilities";
import { formatDateTime } from "../utils/datetime";

const LEVELS = [
  { key: "critical", label: "Критический", hint: "V > 8 · устранить до 24 часов", tone: "danger" },
  { key: "high", label: "Высокий", hint: "5 ≤ V ≤ 8 · до 7 дней", tone: "warning" },
  { key: "medium", label: "Средний", hint: "2 ≤ V < 5 · до 4 недель", tone: "info" },
  { key: "low", label: "Низкий", hint: "V < 2 · до 4 месяцев", tone: "default" },
];
const LEVEL_LABEL = Object.fromEntries(LEVELS.map((l) => [l.key, l.label.toLowerCase()]));
const INPUT = "rounded-xl border border-zinc-800 bg-zinc-950 px-3 py-2 text-sm text-white outline-none placeholder:text-zinc-500";
const PAGE = 100;

function bduLink(bduId) {
  // BDU:2024-04914 → https://bdu.fstec.ru/vul/2024-04914
  return `https://bdu.fstec.ru/vul/${bduId.replace(/^BDU:/, "")}`;
}

export default function Vulnerabilities() {
  const { selectedOrganization, selectedOrganizationId, loading: orgLoading, hasOrganizations, error: orgError } = useOrganization();

  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [level, setLevel] = useState("");
  const [search, setSearch] = useState("");
  const [shown, setShown] = useState(PAGE);

  useEffect(() => {
    async function loadData() {
      if (!selectedOrganizationId) {
        setData(null);
        return;
      }
      try {
        setLoading(true);
        setError("");
        setData(await getVulnerabilitiesByOrganization(selectedOrganizationId));
      } catch (err) {
        setError(err.message);
        setData(null);
      } finally {
        setLoading(false);
      }
    }
    if (!orgLoading) loadData();
  }, [selectedOrganizationId, orgLoading]);

  const items = useMemo(() => {
    const query = search.trim().toLowerCase();
    return (data?.items || []).filter((item) => {
      if (level && item.level !== level) return false;
      if (!query) return true;
      return [item.bdu_id, item.name, item.package, item.product, item.asset?.hostname, ...(item.cves || [])]
        .some((value) => (value || "").toLowerCase().includes(query));
    });
  }, [data, level, search]);

  return (
    <OrgGate title="Уязвимости ПО" orgLoading={orgLoading} orgError={orgError} hasOrganizations={hasOrganizations}>
      <div className="space-y-6">
        <div>
          <h1 className="text-2xl font-semibold text-white">Уязвимости ПО (БДУ ФСТЭК)</h1>
          <p className="mt-1 text-sm text-zinc-400">
            Установленное ПО организации <span className="text-white">{selectedOrganization?.name || "—"}</span>{" "}
            в сравнении с уязвимыми версиями из Банка данных угроз ФСТЭК России
          </p>
        </div>

        <div className="rounded-xl border border-amber-500/20 bg-amber-500/10 px-4 py-3 text-sm text-amber-200">
          Это <b>потенциальные</b> уязвимости: версия пакета попадает в уязвимый диапазон БДУ. Дистрибутивы переносят
          исправления в старые версии, не меняя номер, поэтому каждую находку нужно сверить с бюллетенем дистрибутива
          (для Ubuntu — USN). Уровень критичности V рассчитан по методике ФСТЭК от 30.06.2025:
          V = CVSS 3.1 × Iinfr × (Iat + Iimp).
        </div>

        {error ? (
          <div className="rounded-xl border border-rose-500/20 bg-rose-500/10 px-4 py-3 text-sm text-rose-300">Не удалось загрузить: {error}</div>
        ) : null}

        <div className="grid gap-4 md:grid-cols-4">
          {LEVELS.map((l) => (
            <StatCard key={l.key} label={l.label} value={data?.summary?.[l.key] ?? 0} hint={l.hint} tone={l.tone} loading={loading} />
          ))}
        </div>

        {data ? (
          <div className="grid gap-3 text-sm text-zinc-400 md:grid-cols-2">
            <div className="rounded-xl border border-zinc-800 bg-zinc-950/70 px-4 py-3">
              {data.import ? (
                <>
                  Копия БДУ: загружена {formatDateTime(data.import.imported_at)}, уязвимостей —{" "}
                  {data.import.vulnerabilities.toLocaleString("ru-RU")}.{" "}
                </>
              ) : (
                <>Копия БДУ ещё не загружена (команда <code>python -m app.commands.bdu import</code>). </>
              )}
              Проверено продуктов: {data.products_checked}, активов: {data.assets_checked}.
            </div>
            {data.not_compared?.length ? (
              <div className="rounded-xl border border-zinc-800 bg-zinc-950/70 px-4 py-3">
                Не сопоставляются:
                <ul className="mt-1 list-disc pl-5">
                  {data.not_compared.map((n) => <li key={n.reason}>{n.reason}</li>)}
                </ul>
              </div>
            ) : null}
          </div>
        ) : null}

        <AppCard title="Потенциальные уязвимости" subtitle="Сначала самые критичные; номер БДУ ведёт на страницу уязвимости на сайте ФСТЭК">
          <div className="mb-4 flex flex-wrap gap-3">
            <select className={INPUT} value={level} onChange={(e) => { setLevel(e.target.value); setShown(PAGE); }}>
              <option value="">Все уровни</option>
              {LEVELS.map((l) => <option key={l.key} value={l.key}>{l.label}</option>)}
            </select>
            <input
              className={`${INPUT} min-w-[18rem]`}
              placeholder="Поиск: пакет, BDU, CVE, актив…"
              value={search}
              onChange={(e) => { setSearch(e.target.value); setShown(PAGE); }}
            />
            <span className="self-center text-sm text-zinc-500">Найдено: {items.length}</span>
          </div>

          {loading ? (
            <SkeletonTable rows={8} cols={7} />
          ) : items.length === 0 ? (
            <EmptyState
              title="Нет потенциальных уязвимостей"
              description={data?.import ? "По выбранным условиям ничего не найдено." : "Сначала загрузите копию БДУ."}
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="min-w-full text-sm">
                <thead className="border-b border-zinc-800 text-left text-zinc-400">
                  <tr>
                    <th className="px-4 py-3">Уровень</th>
                    <th className="px-4 py-3">Уязвимость</th>
                    <th className="px-4 py-3">ПО</th>
                    <th className="px-4 py-3">CVSS</th>
                    <th className="px-4 py-3">Эксплуатация</th>
                    <th className="px-4 py-3">Срок</th>
                  </tr>
                </thead>
                <tbody>
                  {items.slice(0, shown).map((item) => {
                    const crit = item.criticality;
                    return (
                      <tr key={`${item.asset.id}:${item.bdu_id}`} className="border-b border-zinc-800/60 align-top text-zinc-200">
                        <td className="px-4 py-3">
                          <SeverityBadge value={item.level ? LEVEL_LABEL[item.level] : "нет оценки"} />
                          {crit ? <div className="mt-1 text-xs text-zinc-400">V = {crit.v}</div> : null}
                        </td>
                        <td className="max-w-xl px-4 py-3">
                          <a href={bduLink(item.bdu_id)} target="_blank" rel="noreferrer" className="font-medium text-blue-300 hover:underline">
                            {item.bdu_id}
                          </a>
                          {item.cves?.length ? <span className="ml-2 text-xs text-zinc-500">{item.cves.join(", ")}</span> : null}
                          <div className="mt-1 text-zinc-300">{item.name}</div>
                          {crit ? <div className="mt-1 text-xs text-zinc-500">Последствия: {crit.impact}</div> : null}
                        </td>
                        <td className="px-4 py-3">
                          <div className="font-medium text-white">{item.package}</div>
                          <div className="text-xs text-zinc-400">установлено {item.installed_version}</div>
                          <div className="text-xs text-zinc-500">уязвимы: {item.vulnerable_versions}</div>
                          {data?.assets_checked > 1 ? <div className="text-xs text-zinc-500">{item.asset.hostname}</div> : null}
                        </td>
                        <td className="px-4 py-3">
                          {crit ? <>{crit.icvss}<div className="text-xs text-zinc-500">CVSS {crit.cvss_version}</div></> : "—"}
                        </td>
                        <td className="px-4 py-3 text-xs">{crit?.exploitation || "—"}</td>
                        <td className="px-4 py-3 text-xs">
                          <div className="whitespace-nowrap text-white">{item.deadline || "—"}</div>
                          {item.fix_status ? <div className="mt-1 text-zinc-500">{item.fix_status}</div> : null}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              {items.length > shown ? (
                <div className="mt-4 text-center">
                  <button type="button" onClick={() => setShown((n) => n + PAGE)} className="rounded-xl border border-zinc-700 px-4 py-2 text-sm text-white hover:bg-zinc-800">
                    Показать ещё ({items.length - shown})
                  </button>
                </div>
              ) : null}
            </div>
          )}
        </AppCard>
      </div>
    </OrgGate>
  );
}
