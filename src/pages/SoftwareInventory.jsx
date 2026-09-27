import { useEffect, useState } from "react";
import AppCard from "../components/ui/AppCard";
import StatCard from "../components/ui/StatCard";
import EmptyState from "../components/ui/EmptyState";
import ErrorState from "../components/ui/ErrorState";
import { useOrganization } from "../context/OrganizationContext";
import { getSoftwareByOrganization } from "../api/software";

export default function SoftwareInventory() {
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
        const data = await getSoftwareByOrganization(selectedOrganizationId);
        setRows(data);
      } catch (error) {
        console.error("Ошибка загрузки ПО:", error.message);
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
        <h1 className="text-2xl font-semibold text-white">Инвентаризация ПО</h1>
        <ErrorState title="Не удалось загрузить организации" description={orgError} />
      </div>
    );
  }

  if (!hasOrganizations) {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-semibold text-white">Инвентаризация ПО</h1>
        <EmptyState
          title="Нет организаций"
          description="Таблица client_organizations пустая. Сначала добавь хотя бы одну организацию."
        />
      </div>
    );
  }

  const categories = [...new Set(rows.map((item) => item.category).filter(Boolean))].length;
  const hosts = [...new Set(rows.map((item) => item.asset?.hostname).filter(Boolean))].length;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-white">Инвентаризация ПО</h1>
        <p className="mt-1 text-sm text-zinc-400">
          Полный перечень ПО по организации{" "}
          <span className="text-white">{selectedOrganization?.name || "—"}</span>
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <StatCard label="Всего программ" value={loading ? "..." : rows.length} hint="Все обнаруженные компоненты" tone="info" />
        <StatCard label="Категории" value={loading ? "..." : categories} hint="Уникальные классы ПО" tone="default" />
        <StatCard label="Хосты" value={loading ? "..." : hosts} hint="Узлы с установленным ПО" tone="default" />
      </div>

      <AppCard title="Список ПО" subtitle="Инвентаризация программных компонентов">
        {loading ? (
          <div className="text-zinc-400">Загрузка...</div>
        ) : rows.length === 0 ? (
          <EmptyState
            title="Нет данных по ПО"
            description="Для выбранной организации в таблице software пока нет записей."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead className="border-b border-zinc-800 text-left text-zinc-400">
                <tr>
                  <th className="px-4 py-3">Название</th>
                  <th className="px-4 py-3">Версия</th>
                  <th className="px-4 py-3">Вендор</th>
                  <th className="px-4 py-3">Категория</th>
                  <th className="px-4 py-3">Тип</th>
                  <th className="px-4 py-3">Хост</th>
                  <th className="px-4 py-3">ОС</th>
                  <th className="px-4 py-3">Дата</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((item) => (
                  <tr key={item.id} className="border-b border-zinc-800/60 text-zinc-200 hover:bg-zinc-800/40">
                    <td className="px-4 py-3 font-medium text-white">{item.name}</td>
                    <td className="px-4 py-3">{item.version || "—"}</td>
                    <td className="px-4 py-3">{item.vendor || "—"}</td>
                    <td className="px-4 py-3">{item.category || "—"}</td>
                    <td className="px-4 py-3">{item.type || "—"}</td>
                    <td className="px-4 py-3">{item.asset?.hostname || "—"}</td>
                    <td className="px-4 py-3">{item.asset?.os || "—"}</td>
                    <td className="px-4 py-3">{item.created_at?.slice(0, 10) || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </AppCard>
    </div>
  );
}