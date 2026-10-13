import { useEffect, useMemo, useState } from "react";
import AppCard from "../components/ui/AppCard";
import StatCard from "../components/ui/StatCard";
import EmptyState from "../components/ui/EmptyState";
import ErrorState from "../components/ui/ErrorState";
import OrgGate from "../components/OrgGate";
import { SkeletonTable } from "../components/ui/Skeleton";
import SortableHeader from "../components/ui/SortableHeader";
import { useSort } from "../hooks/useSort";
import { useOrganization } from "../context/OrganizationContext";
import { getReportsByOrganization } from "../api/reports";
import { getScoreTone } from "../utils/score";
import { getHardeningByOrganization } from "../api/hardening";
import SeverityBadge from "../components/ui/SeverityBadge";
import { REMEDIATION_BY_SEVERITY, REMEDIATION_SOURCE_NOTE } from "../utils/remediation";
import { Link } from "react-router-dom";
import { formatDateTime } from "../utils/datetime";

/** Текущие нарушения по уровням: сколько, на скольких активах, в какой срок и обязательно ли. */
/** План устранения: открытые нарушения по уровням (считает сервер) + сроки и обязательность по методике. */
function remediationPlan(openBySeverity) {
  return (openBySeverity || [])
    .filter((row) => REMEDIATION_BY_SEVERITY[row.severity])
    .map((row) => ({ ...row, ...REMEDIATION_BY_SEVERITY[row.severity] }))
    .sort((a, b) => a.order - b.order);
}

export default function Report() {
  const {
    selectedOrganization,
    selectedOrganizationId,
    loading: orgLoading,
    hasOrganizations,
    error: orgError,
  } = useOrganization();

  const [reports, setReports] = useState([]);
  const [openBySeverity, setOpenBySeverity] = useState([]);
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState("");

  useEffect(() => {
    async function loadData() {
      if (!selectedOrganizationId) {
        setReports([]);
        setOpenBySeverity([]);
        setLoading(false);
        return;
      }

      try {
        setLoading(true);
        setLoadError("");
        const [data, current] = await Promise.all([
          // по дням: отчёт пересчитывается при каждом приёме данных
          getReportsByOrganization(selectedOrganizationId, { daily: true, limit: 90 }),
          // limit=1: нужна только сводка по организации, а не сами проверки
          getHardeningByOrganization(selectedOrganizationId, { limit: 1 }),
        ]);
        setReports(data);
        setOpenBySeverity(current?.summary?.open_by_severity || []);
      } catch (error) {
        setLoadError(error.message || "Не удалось получить данные");
        setReports([]);
        setOpenBySeverity([]);
      } finally {
        setLoading(false);
      }
    }

    if (!orgLoading) {
      loadData();
    }
  }, [selectedOrganizationId, orgLoading]);

  const latest = reports[0] || null;
  const plan = useMemo(() => remediationPlan(openBySeverity), [openBySeverity]);

  const avgScore = useMemo(() => {
    if (!reports.length) return 0;
    const total = reports.reduce((sum, item) => sum + (item.compliance_score || 0), 0);
    return Math.round(total / reports.length);
  }, [reports]);

  const { sortedRows, activeKey, sortDir, toggleSort } = useSort(reports, {
    date: (row) => row.generated_at || "",
    total: (row) => row.total_checks ?? 0,
    passed: (row) => row.passed ?? 0,
    failed: (row) => row.failed ?? 0,
    score: (row) => row.compliance_score ?? 0,
  });

  return (
    <OrgGate
      title="Отчёты"
      orgLoading={orgLoading}
      orgError={orgError}
      hasOrganizations={hasOrganizations}
    >
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-white">Отчёты</h1>
        <p className="mt-1 text-sm text-zinc-400">
          История отчётов по организации{" "}
          <span className="text-white">{selectedOrganization?.name || "—"}</span>
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-4">
        <StatCard
          label="Последнее соответствие"
          value={latest ? `${Math.round(latest.compliance_score || 0)}%` : "—"}
          loading={loading}
          hint="Последний рассчитанный показатель"
          tone="info"
        />
        <StatCard label="Пройдено" value={latest?.passed ?? "—"} loading={loading} hint="Успешные проверки" tone="success" />
        <StatCard label="Нарушения" value={latest?.failed ?? "—"} loading={loading} hint="Проваленные проверки" tone="danger" />
        <StatCard label="Среднее соответствие" value={`${avgScore}%`} loading={loading} hint="Среднее по дням, до 90 дней" tone="default" />
      </div>

      <AppCard title="Что устранить и в какие сроки" subtitle={REMEDIATION_SOURCE_NOTE}>
        {loading ? (
          <SkeletonTable rows={4} cols={5} />
        ) : loadError ? (
          <ErrorState title="Ошибка загрузки" description={loadError} />
        ) : plan.length === 0 ? (
          <div className="text-sm text-zinc-400">Текущих нарушений нет.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead className="border-b border-zinc-800 text-left text-zinc-400">
                <tr>
                  <th className="px-4 py-3 font-medium">Уровень</th>
                  <th className="px-4 py-3 font-medium">Нарушений</th>
                  <th className="px-4 py-3 font-medium">Активов</th>
                  <th className="px-4 py-3 font-medium">Срок устранения</th>
                  <th className="px-4 py-3 font-medium">Порядок</th>
                </tr>
              </thead>
              <tbody>
                {plan.map((row) => (
                  <tr key={row.severity} className="border-b border-zinc-800/60 text-zinc-200">
                    <td className="px-4 py-3"><SeverityBadge value={row.severity} /></td>
                    <td className="px-4 py-3 font-semibold text-white">{row.count}</td>
                    <td className="px-4 py-3">{row.assets}</td>
                    <td className="px-4 py-3">{row.deadline}</td>
                    <td className={`px-4 py-3 ${row.mandatory ? "text-rose-300" : "text-zinc-400"}`}>
                      {row.mandatory ? "Обязательно (п. 3.4.4)" : "После экспертной оценки (п. 3.4.5)"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <div className="mt-3 text-xs text-zinc-500">
              Список нарушений с рекомендациями — на странице{" "}
              <Link to="/hardening" className="text-zinc-300 underline hover:text-white">Харденинг</Link>.
            </div>
          </div>
        )}
      </AppCard>

      <AppCard title="История отчётов" subtitle="По дням: последний отчёт каждого дня, до 90 дней">
        {loading ? (
          <SkeletonTable rows={5} cols={5} />
        ) : loadError ? (
          <ErrorState title="Ошибка загрузки" description={loadError} />
        ) : reports.length === 0 ? (
          <EmptyState
            title="Нет отчётов"
            description="Отчёт формируется после каждого скана: пока сканов не было."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead className="border-b border-zinc-800 text-left text-zinc-400">
                <tr>
                  <SortableHeader label="Дата" sortKey="date" activeKey={activeKey} sortDir={sortDir} onSort={toggleSort} />
                  <SortableHeader label="Всего проверок" sortKey="total" activeKey={activeKey} sortDir={sortDir} onSort={toggleSort} />
                  <SortableHeader label="Соблюдено" sortKey="passed" activeKey={activeKey} sortDir={sortDir} onSort={toggleSort} />
                  <SortableHeader label="Нарушено" sortKey="failed" activeKey={activeKey} sortDir={sortDir} onSort={toggleSort} />
                  <SortableHeader label="Соответствие" sortKey="score" activeKey={activeKey} sortDir={sortDir} onSort={toggleSort} />
                </tr>
              </thead>
              <tbody>
                {sortedRows.map((item) => (
                  <tr key={item.id} className="border-b border-zinc-800/60 text-zinc-200 hover:bg-zinc-800/40">
                    <td className="px-4 py-3">{formatDateTime(item.generated_at)}</td>
                    <td className="px-4 py-3">{item.total_checks ?? 0}</td>
                    <td className="px-4 py-3">{item.passed ?? 0}</td>
                    <td className="px-4 py-3">{item.failed ?? 0}</td>
                    <td className={`px-4 py-3 font-semibold ${getScoreTone(item.compliance_score).text}`}>
                      {Math.round(item.compliance_score || 0)}%
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </AppCard>
    </div>
    </OrgGate>
  );
}