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

// Статус находки по данным дистрибутива (OVAL Canonical); null — не Ubuntu или данные не загружены.
const DISTRO = {
  vulnerable: { label: "уязвимо: исправление не установлено", tone: "border-rose-500/30 bg-rose-500/15 text-rose-300" },
  unfixed: { label: "затронуто, исправления нет", tone: "border-amber-500/30 bg-amber-500/15 text-amber-300" },
  fixed: { label: "исправлено в Ubuntu", tone: "border-emerald-500/30 bg-emerald-500/15 text-emerald-300" },
  unknown: { label: "нет данных Ubuntu — потенциальная", tone: "border-zinc-700 bg-zinc-800 text-zinc-300" },
};
const NOT_CHECKED = { label: "не проверено по дистрибутиву", tone: "border-zinc-700 bg-zinc-900 text-zinc-400" };

function DistroCell({ distro }) {
  const info = distro ? DISTRO[distro.status] : NOT_CHECKED;
  return (
    <div className="min-w-[11rem] text-xs">
      <span className={`inline-flex rounded-full border px-2 py-1 font-medium ${info.tone}`}>{info.label}</span>
      {distro?.fixed_version ? (
        <div className="mt-1 text-zinc-400">
          {distro.status === "fixed" ? "исправлено в" : "исправление:"} {distro.fixed_version}
        </div>
      ) : null}
      {distro?.fix_requires_pro ? <div className="mt-1 text-amber-300">только в ESM — нужна подписка Ubuntu Pro</div> : null}
      {distro?.usns?.length ? (
        <div className="mt-1">
          {distro.usns.map((usn) => (
            <a key={usn} href={`https://ubuntu.com/security/notices/${usn}`} target="_blank" rel="noreferrer" className="mr-2 text-blue-300 hover:underline">
              {usn}
            </a>
          ))}
        </div>
      ) : null}
    </div>
  );
}

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
  // По умолчанию исправленное в дистрибутиве скрыто: уязвимости на активе уже нет.
  const [distroFilter, setDistroFilter] = useState("open");
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
      const status = item.distro?.status || "not_checked";
      if (distroFilter === "open" && status === "fixed") return false;
      if (distroFilter !== "open" && distroFilter !== "all" && status !== distroFilter) return false;
      if (!query) return true;
      return [item.bdu_id, item.name, item.package, item.product, item.asset?.hostname, ...(item.cves || [])]
        .some((value) => (value || "").toLowerCase().includes(query));
    });
  }, [data, level, search, distroFilter]);

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
          Версия пакета сравнивается с уязвимыми диапазонами БДУ. Дистрибутивы переносят исправления в старые версии, не
          меняя номер, поэтому находки дополнительно сверяются с данными Ubuntu (OVAL Canonical): исправленное в
          дистрибутиве скрыто и в счёт не входит, а находки без данных Ubuntu остаются <b>потенциальными</b>. Уровень
          критичности V — по методике ФСТЭК от 30.06.2025: V = CVSS 3.1 × Iinfr × (Iat + Iimp).
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
              {data.oval?.length ? (
                <div className="mt-2">
                  Данные Ubuntu: {data.oval.map((o) => `${o.release} (${formatDateTime(o.imported_at)})`).join(", ")}.
                  По ним: подтверждено — {data.distro_summary.vulnerable}, без исправления — {data.distro_summary.unfixed},
                  исправлено и скрыто — {data.distro_summary.fixed}, нет данных — {data.distro_summary.unknown}.
                </div>
              ) : (
                <div className="mt-2">Данные Ubuntu не загружены: все находки — потенциальные.</div>
              )}
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

        <AppCard title="Находки" subtitle="Сначала самые критичные; номер БДУ ведёт на страницу уязвимости на сайте ФСТЭК, USN — на бюллетень Ubuntu">
          <div className="mb-4 flex flex-wrap gap-3">
            <select className={INPUT} value={level} onChange={(e) => { setLevel(e.target.value); setShown(PAGE); }}>
              <option value="">Все уровни</option>
              {LEVELS.map((l) => <option key={l.key} value={l.key}>{l.label}</option>)}
            </select>
            <select className={INPUT} value={distroFilter} onChange={(e) => { setDistroFilter(e.target.value); setShown(PAGE); }}>
              <option value="open">Без исправленных в Ubuntu</option>
              <option value="vulnerable">Уязвимо: исправление не установлено</option>
              <option value="unfixed">Исправления нет</option>
              <option value="unknown">Нет данных Ubuntu</option>
              <option value="fixed">Исправлено в Ubuntu</option>
              <option value="all">Все</option>
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
            <SkeletonTable rows={8} cols={8} />
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
                    <th className="px-4 py-3">Статус в Ubuntu</th>
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
                          <SeverityBadge value={item.level} label={item.level ? LEVEL_LABEL[item.level] : "нет оценки"} />
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
                        <td className="px-4 py-3"><DistroCell distro={item.distro} /></td>
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
