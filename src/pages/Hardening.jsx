import { useEffect, useMemo, useState } from "react";
import AppCard from "../components/ui/AppCard";
import StatCard from "../components/ui/StatCard";
import EmptyState from "../components/ui/EmptyState";
import OrgGate from "../components/OrgGate";
import { SkeletonTable } from "../components/ui/Skeleton";
import SortableHeader from "../components/ui/SortableHeader";
import SeverityBadge from "../components/ui/SeverityBadge";
import CheckStatusBadge from "../components/ui/CheckStatusBadge";
import { useSort } from "../hooks/useSort";
import { useOrganization } from "../context/OrganizationContext";
import { getHardeningByOrganization } from "../api/hardening";
import { getRemediation, REMEDIATION_SOURCE_NOTE } from "../utils/remediation";

function RemediationCell({ status, severity }) {
  const remediation = getRemediation(status, severity);
  if (!remediation) return <span className="text-zinc-500">—</span>;
  return (
    <div className="min-w-[8rem]">
      <div className="whitespace-nowrap text-white">{remediation.deadline}</div>
      <div className={`text-xs ${remediation.mandatory ? "text-rose-300" : "text-zinc-500"}`}>
        {remediation.mandatory ? "обязательно (п. 3.4.4)" : "после экспертной оценки"}
      </div>
    </div>
  );
}

export default function Hardening() {
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
        const data = await getHardeningByOrganization(selectedOrganizationId);
        setRows(data);
      } catch (error) {
        console.error("Ошибка загрузки hardening checks:", error.message);
        setRows([]);
      } finally {
        setLoading(false);
      }
    }

    if (!orgLoading) {
      loadData();
    }
  }, [selectedOrganizationId, orgLoading]);

  const stats = useMemo(() => {
    return {
      total: rows.length,
      passed: rows.filter((item) => item.status === "pass").length,
      failed: rows.filter((item) => item.status === "fail").length,
      // Нарушения критического и высокого уровня — обязательны к устранению (п. 3.4.4 методики ФСТЭК).
      // Раньше здесь считались правила уровня critical независимо от результата, включая пройденные.
      mandatory: rows.filter((item) => getRemediation(item.status, item.rule?.severity)?.mandatory).length,
    };
  }, [rows]);

  const { sortedRows, activeKey, sortDir, toggleSort } = useSort(rows, {
    asset: (row) => row.asset?.hostname || "",
    rule: (row) => row.rule?.title || "",
    severity: (row) => row.rule?.severity || "",
    actual: (row) => row.actual_value || "",
    expected: (row) => row.expected_value || row.rule?.expected_value || "",
    status: (row) => row.status || "",
    deadline: (row) => getRemediation(row.status, row.rule?.severity)?.order ?? 9,
    checked_at: (row) => row.checked_at || "",
  });

  return (
    <OrgGate
      title="Харденинг"
      orgLoading={orgLoading}
      orgError={orgError}
      hasOrganizations={hasOrganizations}
    >
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-white">Харденинг</h1>
        <p className="mt-1 text-sm text-zinc-400">
          Результаты hardening-checks по организации{" "}
          <span className="text-white">{selectedOrganization?.name || "—"}</span>
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-4">
        <StatCard label="Всего проверок" value={stats.total} loading={loading} hint="Проверки по активам" tone="info" />
        <StatCard label="Passed" value={stats.passed} loading={loading} hint="Успешно выполнены" tone="success" />
        <StatCard label="Failed" value={stats.failed} loading={loading} hint="Требуют исправления" tone="danger" />
        <StatCard
          label="Обязательно к устранению"
          value={stats.mandatory}
          loading={loading}
          hint="Нарушения уровня critical и high (п. 3.4.4 методики ФСТЭК)"
          tone="warning"
        />
      </div>

      <AppCard title="Результаты проверок" subtitle={REMEDIATION_SOURCE_NOTE}>
        {loading ? (
          <SkeletonTable rows={6} cols={8} />
        ) : rows.length === 0 ? (
          <EmptyState
            title="Нет результатов проверок"
            description="Для выбранной организации в таблице hardening_checks пока нет записей."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead className="border-b border-zinc-800 text-left text-zinc-400">
                <tr>
                  <SortableHeader label="Актив" sortKey="asset" activeKey={activeKey} sortDir={sortDir} onSort={toggleSort} />
                  <SortableHeader label="Правило" sortKey="rule" activeKey={activeKey} sortDir={sortDir} onSort={toggleSort} />
                  <SortableHeader label="Severity" sortKey="severity" activeKey={activeKey} sortDir={sortDir} onSort={toggleSort} />
                  <SortableHeader label="Actual" sortKey="actual" activeKey={activeKey} sortDir={sortDir} onSort={toggleSort} />
                  <SortableHeader label="Expected" sortKey="expected" activeKey={activeKey} sortDir={sortDir} onSort={toggleSort} />
                  <SortableHeader label="Status" sortKey="status" activeKey={activeKey} sortDir={sortDir} onSort={toggleSort} />
                  <SortableHeader label="Срок устранения" sortKey="deadline" activeKey={activeKey} sortDir={sortDir} onSort={toggleSort} />
                  <SortableHeader label="Дата" sortKey="checked_at" activeKey={activeKey} sortDir={sortDir} onSort={toggleSort} />
                </tr>
              </thead>
              <tbody>
                {sortedRows.map((item) => (
                  <tr
                    key={item.id}
                    className="border-b border-zinc-800/60 text-zinc-200 transition hover:bg-zinc-800/40"
                  >
                    <td className="px-4 py-3 font-medium text-white">
                      {item.asset?.hostname || "—"}
                    </td>
                    <td className="px-4 py-3">
                      <div className="font-medium text-white">{item.rule?.title || "—"}</div>
                      <div className="text-xs text-zinc-500">{item.rule?.rule_code || "—"}</div>
                      {item.status === "fail" && item.rule?.remediation ? (
                        <div className="mt-1 max-w-md text-xs text-zinc-400">Как исправить: {item.rule.remediation}</div>
                      ) : null}
                    </td>
                    <td className="px-4 py-3"><SeverityBadge value={item.rule?.severity} /></td>
                    <td className="px-4 py-3">{item.actual_value || "—"}</td>
                    <td className="px-4 py-3">{item.expected_value || item.rule?.expected_value || "—"}</td>
                    <td className="px-4 py-3"><CheckStatusBadge value={item.status} /></td>
                    <td className="px-4 py-3"><RemediationCell status={item.status} severity={item.rule?.severity} /></td>
                    <td className="px-4 py-3">{item.checked_at?.slice(0, 10) || "—"}</td>
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