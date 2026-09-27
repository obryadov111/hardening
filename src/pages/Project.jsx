import { useEffect, useState } from "react";
import AppCard from "../components/ui/AppCard";
import StatCard from "../components/ui/StatCard";
import EmptyState from "../components/ui/EmptyState";
import ErrorState from "../components/ui/ErrorState";
import { useOrganization } from "../context/OrganizationContext";
import { getEnvironmentsByOrganization } from "../api/infrastructure";

export default function Project() {
  const {
    selectedOrganization,
    selectedOrganizationId,
    loading: orgLoading,
    hasOrganizations,
    error: orgError,
  } = useOrganization();

  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    async function loadData() {
      if (!selectedOrganizationId) {
        setRows([]);
        setLoading(false);
        return;
      }

      try {
        setLoading(true);
        const data = await getEnvironmentsByOrganization(selectedOrganizationId);
        setRows(data);
      } catch (error) {
        console.error("Ошибка загрузки инфраструктуры:", error.message);
        setRows([]);
      } finally {
        setLoading(false);
      }
    }

    if (!orgLoading) {
      loadData();
    }
  }, [selectedOrganizationId, orgLoading]);

  if (orgLoading) {
    return <div className="text-zinc-400">Загрузка организаций...</div>;
  }

  if (orgError) {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-semibold text-white">Инфраструктура</h1>
        <ErrorState title="Не удалось загрузить организации" description={orgError} />
      </div>
    );
  }

  if (!hasOrganizations) {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-semibold text-white">Инфраструктура</h1>
        <EmptyState
          title="Нет организаций"
          description="Таблица client_organizations пустая. Сначала добавь хотя бы одну организацию."
        />
      </div>
    );
  }

  const totalAssets = rows.reduce((sum, item) => sum + (item.assets?.length || 0), 0);
  const totalCritical = rows.reduce(
    (sum, item) =>
      sum + (item.assets?.filter((asset) => asset.criticality === "critical").length || 0),
    0
  );

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-white">Инфраструктура</h1>
        <p className="mt-1 text-sm text-zinc-400">
          Контуры и среды организации{" "}
          <span className="text-white">{selectedOrganization?.name || "—"}</span>
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <StatCard label="Контуры" value={loading ? "..." : rows.length} hint="Среды и сегменты" tone="info" />
        <StatCard label="Активы" value={loading ? "..." : totalAssets} hint="Всего узлов" tone="default" />
        <StatCard label="Critical" value={loading ? "..." : totalCritical} hint="Критичные активы" tone="danger" />
      </div>

      <AppCard title="Среды организации" subtitle="Обзор инфраструктурных контуров">
        {loading ? (
          <div className="text-zinc-400">Загрузка...</div>
        ) : rows.length === 0 ? (
          <EmptyState
            title="Нет инфраструктурных контуров"
            description="Для выбранной организации в таблице environments пока нет записей."
          />
        ) : (
          <div className="grid gap-4 lg:grid-cols-2">
            {rows.map((item) => {
              const assetsCount = item.assets?.length || 0;
              const criticalCount =
                item.assets?.filter((asset) => asset.criticality === "critical").length || 0;

              return (
                <div key={item.id} className="rounded-2xl border border-zinc-800 bg-zinc-950/70 p-5">
                  <div className="text-lg font-semibold text-white">{item.name}</div>

                  <div className="mt-5 grid gap-4 sm:grid-cols-2">
                    <div className="rounded-xl border border-zinc-800 bg-zinc-900/80 p-4">
                      <div className="text-xs uppercase tracking-wide text-zinc-500">Активы</div>
                      <div className="mt-2 text-2xl font-semibold text-white">{assetsCount}</div>
                    </div>

                    <div className="rounded-xl border border-zinc-800 bg-zinc-900/80 p-4">
                      <div className="text-xs uppercase tracking-wide text-zinc-500">Critical</div>
                      <div className="mt-2 text-2xl font-semibold text-rose-300">{criticalCount}</div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </AppCard>
    </div>
  );
}