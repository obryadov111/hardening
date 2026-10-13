import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { getAssetsByOrganization } from "../api/assets";
import { severityRank } from "../utils/severity";
import { useOrganization } from "../context/OrganizationContext";
import { useSort } from "../hooks/useSort";
import SortableHeader from "../components/ui/SortableHeader";
import { SkeletonTable } from "../components/ui/Skeleton";
import SeverityBadge from "../components/ui/SeverityBadge";

const NO_ENVIRONMENT = "__none__";

/**
 * Среды (контуры) организации — карточки над таблицей: узлов, критичных, с непройденными проверками.
 * Считаются по тем же активам, что и таблица, поэтому числа совпадают; клик — фильтр таблицы по среде.
 */
function summarizeEnvironments(assets) {
  const groups = new Map();
  for (const asset of assets) {
    const key = asset.environment_id || NO_ENVIRONMENT;
    const group = groups.get(key) || { key, name: asset.environment_name || "Без среды", total: 0, critical: 0, failing: 0 };
    group.total += 1;
    if (asset.criticality === "critical") group.critical += 1;
    if ((asset.failed_checks_count ?? 0) > 0) group.failing += 1;
    groups.set(key, group);
  }
  return [...groups.values()].sort((a, b) => a.name.localeCompare(b.name, "ru"));
}

function EnvironmentCard({ name, total, critical, failing, active, onClick }) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={`rounded-2xl border p-4 text-left transition ${
        active ? "border-blue-500 bg-blue-500/10" : "border-zinc-800 bg-zinc-900 hover:border-zinc-700"
      }`}
    >
      <div className="truncate font-medium text-white">{name}</div>
      <dl className="mt-3 space-y-1 text-sm">
        <div className="flex justify-between gap-2"><dt className="text-zinc-400">Узлов</dt><dd className="font-semibold text-white">{total}</dd></div>
        <div className="flex justify-between gap-2"><dt className="text-zinc-400">Критичных</dt><dd className={`font-semibold ${critical ? "text-rose-300" : "text-white"}`}>{critical}</dd></div>
        <div className="flex justify-between gap-2"><dt className="text-zinc-400">С нарушениями</dt><dd className={`font-semibold ${failing ? "text-amber-300" : "text-white"}`}>{failing}</dd></div>
      </dl>
    </button>
  );
}

export default function Assets() {
  const { selectedOrganization } = useOrganization();

  const [assets, setAssets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [environment, setEnvironment] = useState(null);

  const orgId = selectedOrganization?.id;

  const loadAssets = useCallback(async (showRefreshState = false) => {
    if (!orgId) {
      setAssets([]);
      setLoading(false);
      return;
    }

    try {
      setError("");

      if (showRefreshState) {
        setRefreshing(true);
      } else {
        setLoading(true);
      }

      const data = await getAssetsByOrganization(orgId);
      setAssets(Array.isArray(data) ? data : []);
    } catch (err) {
      setError(err.message || "Не удалось загрузить активы");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [orgId]);

  useEffect(() => {
    setEnvironment(null);
    loadAssets();
  }, [loadAssets]);

  const environments = useMemo(() => summarizeEnvironments(assets), [assets]);

  const filteredAssets = useMemo(() => {
    const q = search.trim().toLowerCase();
    const inEnvironment = environment
      ? assets.filter((asset) => (asset.environment_id || NO_ENVIRONMENT) === environment)
      : assets;

    if (!q) {
      return inEnvironment;
    }

    return inEnvironment.filter((asset) => {
      return [
        asset.hostname,
        asset.ip_address,
        asset.os,
        asset.asset_type,
        asset.criticality,
        asset.environment_name,
      ]
        .filter(Boolean)
        .some((value) => String(value).toLowerCase().includes(q));
    });
  }, [assets, search, environment]);

  const { sortedRows, activeKey, sortDir, toggleSort } = useSort(filteredAssets, {
    hostname: (row) => row.hostname || "",
    ip_address: (row) => row.ip_address || "",
    os: (row) => row.os || "",
    asset_type: (row) => row.asset_type || "",
    criticality: (row) => severityRank(row.criticality),
    environment_name: (row) => row.environment_name || "",
    software_count: (row) => row.software_count ?? 0,
    failed_checks_count: (row) => row.failed_checks_count ?? 0,
  });

  if (!selectedOrganization?.id) {
    return (
      <div className="p-6 text-zinc-300">
        <h1 className="text-2xl font-semibold mb-2">Активы</h1>
        <p>Сначала выбери организацию.</p>
      </div>
    );
  }

  return (
    <div className="p-6 text-white">
      <div className="mb-6 flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div>
          <h1 className="text-2xl font-semibold">Активы</h1>
          <p className="text-sm text-zinc-400 mt-1">
            Организация: {selectedOrganization.name || "Без названия"}
          </p>
        </div>

        <div className="flex gap-3">
          <input
            type="text"
            placeholder="Поиск по имени хоста, IP, ОС..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="field-input w-64"
          />

          <button
            type="button"
            onClick={() => loadAssets(true)}
            disabled={refreshing}
            className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium hover:bg-blue-500 disabled:opacity-60"
          >
            {refreshing ? "Обновляем..." : "Обновить"}
          </button>
        </div>
      </div>

      {error && (
        <div className="mb-4 rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-red-300">
          {error}
        </div>
      )}

      {!loading && environments.length > 0 ? (
        <div className="mb-6 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <EnvironmentCard
            name="Все среды"
            total={assets.length}
            critical={environments.reduce((sum, env) => sum + env.critical, 0)}
            failing={environments.reduce((sum, env) => sum + env.failing, 0)}
            active={!environment}
            onClick={() => setEnvironment(null)}
          />
          {environments.map((env) => (
            <EnvironmentCard
              key={env.key}
              name={env.name}
              total={env.total}
              critical={env.critical}
              failing={env.failing}
              active={environment === env.key}
              onClick={() => setEnvironment(environment === env.key ? null : env.key)}
            />
          ))}
        </div>
      ) : null}

      {loading ? (
        <div className="rounded-2xl border border-zinc-800 bg-zinc-900 p-6">
          <SkeletonTable rows={6} cols={8} />
        </div>
      ) : filteredAssets.length === 0 ? (
        <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-6 text-zinc-300">
          {assets.length ? "Под фильтр не попал ни один актив." : "Для выбранной организации активы не найдены."}
        </div>
      ) : (
        <div className="overflow-hidden rounded-2xl border border-zinc-800 bg-zinc-900">
          <div className="overflow-x-auto">
            <table className="min-w-full text-left text-sm">
              <thead className="bg-zinc-950 text-zinc-400">
                <tr>
                  <SortableHeader label="Имя хоста" sortKey="hostname" activeKey={activeKey} sortDir={sortDir} onSort={toggleSort} />
                  <SortableHeader label="IP" sortKey="ip_address" activeKey={activeKey} sortDir={sortDir} onSort={toggleSort} />
                  <SortableHeader label="ОС" sortKey="os" activeKey={activeKey} sortDir={sortDir} onSort={toggleSort} />
                  <SortableHeader label="Тип" sortKey="asset_type" activeKey={activeKey} sortDir={sortDir} onSort={toggleSort} />
                  <SortableHeader label="Критичность" sortKey="criticality" activeKey={activeKey} sortDir={sortDir} onSort={toggleSort} />
                  <SortableHeader label="Контур" sortKey="environment_name" activeKey={activeKey} sortDir={sortDir} onSort={toggleSort} />
                  <SortableHeader label="ПО" sortKey="software_count" activeKey={activeKey} sortDir={sortDir} onSort={toggleSort} />
                  <SortableHeader label="Нарушений" sortKey="failed_checks_count" activeKey={activeKey} sortDir={sortDir} onSort={toggleSort} />
                </tr>
              </thead>

              <tbody>
                {sortedRows.map((asset) => (
                  <tr key={asset.id} className="border-t border-zinc-800">
                    <td className="px-4 py-3 font-medium">
			  <Link
			    to={`/assets/${asset.id}`}
			    className="text-blue-400 hover:text-blue-300 hover:underline"
			  >
			    {asset.hostname}
			  </Link>
		    </td>
                    <td className="px-4 py-3 text-zinc-300">{asset.ip_address || "—"}</td>
                    <td className="px-4 py-3 text-zinc-300">{asset.os || "—"}</td>
                    <td className="px-4 py-3 text-zinc-300">{asset.asset_type || "—"}</td>
                    <td className="px-4 py-3">
                      <SeverityBadge value={asset.criticality} />
                    </td>
                    <td className="px-4 py-3 text-zinc-300">
                      {asset.environment_name || "—"}
                    </td>
                    <td className="px-4 py-3 text-zinc-300">{asset.software_count ?? 0}</td>
                    <td className="px-4 py-3 text-zinc-300">{asset.failed_checks_count ?? 0}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="border-t border-zinc-800 px-4 py-3 text-sm text-zinc-400">
            Всего активов: {filteredAssets.length}
          </div>
        </div>
      )}
    </div>
  );
}
