import { useEffect, useState } from "react";
import AppCard from "../components/ui/AppCard";
import StatCard from "../components/ui/StatCard";
import EmptyState from "../components/ui/EmptyState";
import ErrorState from "../components/ui/ErrorState";
import SortableHeader from "../components/ui/SortableHeader";
import { SkeletonTable } from "../components/ui/Skeleton";
import OrgGate from "../components/OrgGate";
import { useOrganization } from "../context/OrganizationContext";
import { getSoftwareByOrganization } from "../api/software";
import { formatDate } from "../utils/datetime";

// На хосте — порядка 1500 пакетов, на тысячу хостов — полтора миллиона строк: поиск, фильтр, сортировка
// и страницы — на сервере (GET /organizations/{id}/software), браузер получает только видимую страницу.
const PAGE_SIZE = 100;
const INPUT = "rounded-xl border border-zinc-800 bg-zinc-950 px-3 py-2 text-sm text-white outline-none placeholder:text-zinc-500 focus:border-blue-500";
const PAGER = "rounded-xl border border-zinc-700 px-3 py-1.5 text-sm text-zinc-200 hover:bg-zinc-800 disabled:opacity-40";
const EMPTY_SUMMARY = { programs: 0, categories: 0, hosts: [] };

export default function SoftwareInventory() {
  const {
    selectedOrganization,
    selectedOrganizationId,
    loading: orgLoading,
    hasOrganizations,
    error: orgError,
  } = useOrganization();

  return (
    <OrgGate title="Инвентаризация ПО" orgLoading={orgLoading} orgError={orgError} hasOrganizations={hasOrganizations}>
      <div className="space-y-6">
        <div>
          <h1 className="text-2xl font-semibold text-white">Инвентаризация ПО</h1>
          <p className="mt-1 text-sm text-zinc-400">
            Полный перечень ПО по организации{" "}
            <span className="text-white">{selectedOrganization?.name || "—"}</span>
          </p>
        </div>
        {/* key: смена организации — поиск, фильтр и страница с чистого листа */}
        {selectedOrganizationId ? <SoftwareList key={selectedOrganizationId} organizationId={selectedOrganizationId} /> : null}
      </div>
    </OrgGate>
  );
}

function SoftwareList({ organizationId }) {
  const [result, setResult] = useState({ key: null, items: [], total: 0, summary: EMPTY_SUMMARY, error: "" });
  const [search, setSearch] = useState("");
  const [query, setQuery] = useState("");  // поиск с задержкой: запрос не на каждую букву
  const [host, setHost] = useState("");
  const [sort, setSort] = useState({ key: "name", dir: "asc" });
  const [offset, setOffset] = useState(0);

  useEffect(() => {
    const timer = setTimeout(() => {
      setQuery(search);
      setOffset(0);
    }, 300);
    return () => clearTimeout(timer);
  }, [search]);

  // Идёт загрузка, пока ответ не пришёл на текущий запрос; ответ на устаревший запрос (быстрый ввод,
  // смена страницы) отбрасывается.
  const requestKey = JSON.stringify([query, host, sort, offset]);
  const loading = result.key !== requestKey;

  useEffect(() => {
    let cancelled = false;
    getSoftwareByOrganization(organizationId, { q: query, host, sort: sort.key, dir: sort.dir, limit: PAGE_SIZE, offset })
      .then((data) => {
        if (!cancelled) setResult({ key: requestKey, items: data.items || [], total: data.total || 0, summary: data.summary || EMPTY_SUMMARY, error: "" });
      })
      .catch((error) => {
        if (!cancelled) setResult((prev) => ({ ...prev, key: requestKey, error: error.message || "Не удалось получить данные" }));
      });
    return () => { cancelled = true; };
  }, [organizationId, query, host, sort, offset, requestKey]);

  function toggleSort(key) {
    setSort((prev) => ({ key, dir: prev.key === key && prev.dir === "asc" ? "desc" : "asc" }));
    setOffset(0);
  }

  const { summary, error: loadError } = result;
  const page = result;
  const firstLoad = result.key === null;
  const filtering = Boolean(query.trim() || host);
  const header = (label, key) => (
    <SortableHeader label={label} sortKey={key} activeKey={sort.key} sortDir={sort.dir} onSort={toggleSort} />
  );

  return (
    <>
      <div className="grid gap-4 md:grid-cols-3">
        <StatCard label="Всего программ" value={summary.programs} loading={firstLoad} hint="Все обнаруженные компоненты" tone="info" />
        <StatCard label="Категории" value={summary.categories} loading={firstLoad} hint="Уникальные классы ПО" tone="default" />
        <StatCard label="Хосты" value={summary.hosts.length} loading={firstLoad} hint="Узлы с установленным ПО" tone="default" />
      </div>

      <AppCard title="Список ПО" subtitle="Инвентаризация программных компонентов">
        {loadError ? (
          <ErrorState title="Ошибка загрузки" description={loadError} />
        ) : firstLoad ? (
          <SkeletonTable rows={6} cols={6} />
        ) : summary.programs === 0 ? (
          <EmptyState
            title="Нет данных по ПО"
            description="Список ПО собирает агент при каждом прогоне: пока отчётов не было."
          />
        ) : (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center gap-3">
              <input
                type="search"
                aria-label="Поиск ПО"
                placeholder="Поиск: название, версия, производитель, хост…"
                className={`${INPUT} min-w-[18rem] flex-1`}
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
              <select aria-label="Хост" className={INPUT} value={host} onChange={(e) => { setHost(e.target.value); setOffset(0); }}>
                <option value="">Все хосты</option>
                {summary.hosts.map((name) => (
                  <option key={name} value={name}>{name}</option>
                ))}
              </select>
              <span className="text-sm text-zinc-400" aria-live="polite">
                {filtering ? `Найдено: ${page.total} из ${summary.programs}` : `Всего: ${summary.programs}`}
              </span>
            </div>

            {page.items.length === 0 ? (
              <div className="text-sm text-zinc-400">{loading ? "Поиск…" : "Под фильтр не попала ни одна программа."}</div>
            ) : (
              <div className={`overflow-x-auto ${loading ? "opacity-60" : ""}`}>
                <table className="min-w-full text-sm">
                  <thead className="border-b border-zinc-800 text-left text-zinc-400">
                    <tr>
                      {header("Название", "name")}
                      {header("Версия", "version")}
                      {header("Производитель", "vendor")}
                      <th className="px-4 py-3">Категория</th>
                      {header("Хост", "host")}
                      <th className="px-4 py-3">ОС</th>
                      {header("Дата", "created_at")}
                    </tr>
                  </thead>
                  <tbody>
                    {page.items.map((item) => (
                      <tr key={item.id} className="border-b border-zinc-800/60 text-zinc-200 hover:bg-zinc-800/40">
                        <td className="px-4 py-3 font-medium text-white">{item.name}</td>
                        <td className="px-4 py-3">{item.version || "—"}</td>
                        <td className="px-4 py-3">{item.vendor || "—"}</td>
                        <td className="px-4 py-3">{item.category || "—"}</td>
                        <td className="px-4 py-3">{item.asset?.hostname || "—"}</td>
                        <td className="px-4 py-3">{item.asset?.os || "—"}</td>
                        <td className="px-4 py-3">{formatDate(item.created_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {page.total > PAGE_SIZE ? (
              <div className="flex items-center gap-3 text-sm text-zinc-400">
                <button type="button" className={PAGER} disabled={offset === 0 || loading} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}>
                  Назад
                </button>
                <span>
                  {offset + 1}–{Math.min(offset + PAGE_SIZE, page.total)} из {page.total}
                </span>
                <button type="button" className={PAGER} disabled={offset + PAGE_SIZE >= page.total || loading} onClick={() => setOffset(offset + PAGE_SIZE)}>
                  Вперёд
                </button>
              </div>
            ) : null}
          </div>
        )}
      </AppCard>
    </>
  );
}
