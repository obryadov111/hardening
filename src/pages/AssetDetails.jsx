import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import AppCard from "../components/ui/AppCard";
import StatCard from "../components/ui/StatCard";
import ErrorState from "../components/ui/ErrorState";
import EmptyState from "../components/ui/EmptyState";
import SeverityBadge from "../components/ui/SeverityBadge";
import CheckStatusBadge from "../components/ui/CheckStatusBadge";
import { Skeleton, SkeletonTable } from "../components/ui/Skeleton";
import { getAssetById } from "../api/assets";
import { formatDateTime } from "../utils/datetime";

export default function AssetDetails() {
  const params = useParams();
  const assetId = params.assetId || params.id || null;

  const [asset, setAsset] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  async function loadAsset(currentAssetId) {
    try {
      setLoading(true);
      setError("");

      const data = await getAssetById(currentAssetId);
      setAsset(data);
    } catch (err) {
      console.error("Ошибка загрузки актива:", err);
      setError(err.message || "Не удалось загрузить актив");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    if (!assetId) {
      setError("Не передан идентификатор актива");
      setLoading(false);
      return;
    }

    loadAsset(assetId);
  }, [assetId]);

  const backLink = (
    <Link to="/assets" className="text-sm text-blue-400 hover:text-blue-300">
      ← Назад к списку активов
    </Link>
  );

  if (loading) {
    return (
      <div className="space-y-6">
        <div>
          {backLink}
          <Skeleton className="mt-2 h-8 w-56" />
        </div>
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-20 w-full" />
          ))}
        </div>
        <AppCard title="Установленное ПО">
          <SkeletonTable rows={4} cols={5} />
        </AppCard>
      </div>
    );
  }

  if (error) {
    return (
      <div className="space-y-6">
        <div>{backLink}</div>
        <ErrorState title="Ошибка загрузки актива" description={error} />
      </div>
    );
  }

  if (!asset) {
    return (
      <div className="space-y-6">
        <div>{backLink}</div>
        <EmptyState title="Актив не найден" description="Такого актива нет или он был удалён." />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          {backLink}
          <h1 className="mt-2 text-2xl font-semibold text-white">{asset.hostname}</h1>
          <p className="mt-1 text-sm text-zinc-400">Подробная информация об активе</p>
        </div>

        <SeverityBadge value={asset.criticality} />
      </div>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <StatCard label="IP-адрес" value={asset.ip_address || "—"} tone="default" />
        <StatCard label="ОС" value={asset.os || "—"} tone="default" />
        <StatCard label="Контур" value={asset.environment_name || "—"} tone="default" />
        <StatCard label="Тип актива" value={asset.asset_type || "—"} tone="default" />
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <StatCard label="Единиц ПО" value={asset.software_count ?? 0} tone="info" />
        <StatCard label="Проверок выполнено" value={asset.checks_count ?? 0} tone="default" />
        <StatCard label="Проваленных проверок" value={asset.failed_checks_count ?? 0} tone="danger" />
      </div>

      <AppCard title="Установленное ПО" subtitle="Инвентаризация ПО на активе">
        {asset.software?.length ? (
          <div className="overflow-x-auto">
            <table className="min-w-full text-left text-sm">
              <thead className="border-b border-zinc-800 text-zinc-400">
                <tr>
                  <th className="px-4 py-3">Название</th>
                  <th className="px-4 py-3">Версия</th>
                  <th className="px-4 py-3">Производитель</th>
                  <th className="px-4 py-3">Категория</th>
                  <th className="px-4 py-3">Тип</th>
                </tr>
              </thead>
              <tbody>
                {asset.software.map((item) => (
                  <tr key={item.id} className="border-b border-zinc-800/60 text-zinc-200 hover:bg-zinc-800/40">
                    <td className="px-4 py-3 font-medium text-white">{item.name}</td>
                    <td className="px-4 py-3 text-zinc-300">{item.version || "—"}</td>
                    <td className="px-4 py-3 text-zinc-300">{item.vendor || "—"}</td>
                    <td className="px-4 py-3 text-zinc-300">{item.category || "—"}</td>
                    <td className="px-4 py-3 text-zinc-300">{item.type || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState title="ПО не найдено" description="Для этого актива нет данных инвентаризации." />
        )}
      </AppCard>

      <AppCard title="Проверки харденинга" subtitle="Результаты проверок по этому активу">
        {asset.checks?.length ? (
          <div className="overflow-x-auto">
            <table className="min-w-full text-left text-sm">
              <thead className="border-b border-zinc-800 text-zinc-400">
                <tr>
                  <th className="px-4 py-3">Правило</th>
                  <th className="px-4 py-3">Actual</th>
                  <th className="px-4 py-3">Expected</th>
                  <th className="px-4 py-3">Статус</th>
                  <th className="px-4 py-3">Проверено</th>
                </tr>
              </thead>
              <tbody>
                {asset.checks.map((item) => (
                  <tr key={item.id} className="border-b border-zinc-800/60 text-zinc-200 hover:bg-zinc-800/40">
                    <td className="px-4 py-3 text-zinc-300">{item.rule_id || "—"}</td>
                    <td className="px-4 py-3 text-zinc-300">{item.actual_value || "—"}</td>
                    <td className="px-4 py-3 text-zinc-300">{item.expected_value || "—"}</td>
                    <td className="px-4 py-3">
                      <CheckStatusBadge value={item.status} />
                    </td>
                    <td className="px-4 py-3 text-zinc-300">
                      {formatDateTime(item.checked_at)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState title="Проверки не найдены" description="Для этого актива ещё нет результатов проверок." />
        )}
      </AppCard>
    </div>
  );
}
