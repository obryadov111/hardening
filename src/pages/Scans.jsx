import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import AppCard from "../components/ui/AppCard";
import StatCard from "../components/ui/StatCard";
import EmptyState from "../components/ui/EmptyState";
import OrgGate from "../components/OrgGate";
import { SkeletonTable } from "../components/ui/Skeleton";
import SortableHeader from "../components/ui/SortableHeader";
import { useSort } from "../hooks/useSort";
import { getScoreTone } from "../utils/score";
import { useOrganization } from "../context/OrganizationContext";
import { getSnapshotsByOrganization } from "../api/snapshots";
import { downloadSnapshotExport } from "../api/exports";

function getStatusBadgeClass(status) {
  switch (status) {
    case "completed":
      return "border-emerald-500/20 bg-emerald-500/10 text-emerald-300";
    case "processing":
      return "border-blue-500/20 bg-blue-500/10 text-blue-300";
    case "pending":
      return "border-amber-500/20 bg-amber-500/10 text-amber-300";
    case "failed":
      return "border-rose-500/20 bg-rose-500/10 text-rose-300";
    default:
      return "border-zinc-700 bg-zinc-800 text-zinc-300";
  }
}

function getStatusLabel(status) {
  switch (status) {
    case "completed":
      return "Завершён";
    case "processing":
      return "В обработке";
    case "pending":
      return "Ожидает";
    case "failed":
      return "Ошибка";
    default:
      return status || "—";
  }
}

export default function Scans() {
  const {
    selectedOrganization,
    selectedOrganizationId,
    loading: orgLoading,
    hasOrganizations,
    error: orgError,
  } = useOrganization();

  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(false);
  const [busyKey, setBusyKey] = useState("");
  const [exportError, setExportError] = useState("");

  useEffect(() => {
    async function loadData() {
      if (!selectedOrganizationId) {
        setRows([]);
        setLoading(false);
        return;
      }

      try {
        setLoading(true);
        const data = await getSnapshotsByOrganization(selectedOrganizationId);
        setRows(data);
      } catch (error) {
        console.error("Ошибка загрузки snapshots:", error.message);
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
    const total = rows.length;
    const completed = rows.filter((item) => item.status === "completed").length;
    const failed = rows.filter((item) => item.status === "failed").length;
    const latest = rows[0] || null;

    return { total, completed, failed, latest };
  }, [rows]);

  // Файл формируется на бэкенде на лету и скачивается авторизованным запросом: без хранилища
  // и подписанных ссылок, у отчёта аудита нет публичного URL.
  async function handleExport(snapshot, format) {
    const key = `${snapshot.id}-${format}`;
    setBusyKey(key);
    setExportError("");

    try {
      const { blob, filename } = await downloadSnapshotExport(snapshot.id, format);
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (error) {
      console.error(`Ошибка экспорта ${format}:`, error.message);
      setExportError(`Не удалось сформировать ${format === "pdf" ? "PDF" : "Excel"}: ${error.message}`);
    } finally {
      setBusyKey("");
    }
  }

  const previousByRow = useMemo(() => {
    const map = new Map();
    rows.forEach((item, index) => map.set(item.id, rows[index + 1] || null));
    return map;
  }, [rows]);

  const { sortedRows, activeKey, sortDir, toggleSort } = useSort(rows, {
    snapshot: (row) => row.snapshot_label || row.scan_number || "",
    date: (row) => row.created_at || "",
    status: (row) => row.status || "",
    assets: (row) => row.total_assets ?? 0,
    software: (row) => row.total_software ?? 0,
    checks: (row) => row.total_checks ?? 0,
    failed: (row) => row.failed ?? 0,
    score: (row) => row.compliance_score ?? 0,
  });

  return (
    <OrgGate
      title="Сканирования"
      orgLoading={orgLoading}
      orgError={orgError}
      hasOrganizations={hasOrganizations}
    >
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-white">Сканирования</h1>
        <p className="mt-1 text-sm text-zinc-400">
          История snapshot-сканов по организации{" "}
          <span className="text-white">{selectedOrganization?.name || "—"}</span>
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-4">
        <StatCard label="Всего snapshot" value={stats.total} loading={loading} hint="История сканирований" tone="info" />
        <StatCard label="Завершено" value={stats.completed} loading={loading} hint="Успешно обработанные" tone="success" />
        <StatCard label="Ошибки" value={stats.failed} loading={loading} hint="Неудачные запуски" tone="danger" />
        <StatCard
          label="Последний score"
          value={
            stats.latest?.compliance_score != null
              ? `${Math.round(stats.latest.compliance_score)}%`
              : "—"
          }
          loading={loading}
          hint="Последний snapshot"
          tone="default"
        />
      </div>

      {exportError ? (
        <div className="flex items-start justify-between gap-4 rounded-2xl border border-rose-500/20 bg-rose-500/10 px-4 py-3 text-sm text-rose-300">
          <span>{exportError}</span>
          <button
            type="button"
            onClick={() => setExportError("")}
            className="shrink-0 text-rose-300/70 hover:text-rose-200"
          >
            Закрыть
          </button>
        </div>
      ) : null}

      <AppCard title="История snapshot-сканов" subtitle="Сравнение и экспорт по каждому запуску">
        {loading ? (
          <SkeletonTable rows={6} cols={8} />
        ) : rows.length === 0 ? (
          <EmptyState
            title="Нет сканирований"
            description="Для выбранной организации в таблице scan_snapshots пока нет записей."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead className="border-b border-zinc-800 text-left text-zinc-400">
                <tr>
                  <SortableHeader label="Snapshot" sortKey="snapshot" activeKey={activeKey} sortDir={sortDir} onSort={toggleSort} />
                  <SortableHeader label="Дата" sortKey="date" activeKey={activeKey} sortDir={sortDir} onSort={toggleSort} />
                  <SortableHeader label="Статус" sortKey="status" activeKey={activeKey} sortDir={sortDir} onSort={toggleSort} />
                  <SortableHeader label="Активы" sortKey="assets" activeKey={activeKey} sortDir={sortDir} onSort={toggleSort} />
                  <SortableHeader label="ПО" sortKey="software" activeKey={activeKey} sortDir={sortDir} onSort={toggleSort} />
                  <SortableHeader label="Checks" sortKey="checks" activeKey={activeKey} sortDir={sortDir} onSort={toggleSort} />
                  <SortableHeader label="Failed" sortKey="failed" activeKey={activeKey} sortDir={sortDir} onSort={toggleSort} />
                  <SortableHeader label="Score" sortKey="score" activeKey={activeKey} sortDir={sortDir} onSort={toggleSort} />
                  <th className="px-4 py-3">PDF</th>
                  <th className="px-4 py-3">Excel</th>
                  <th className="px-4 py-3">Сравнить</th>
                </tr>
              </thead>
              <tbody>
                {sortedRows.map((item) => {
                  const previous = previousByRow.get(item.id) || null;
                  const pdfBusy = busyKey === `${item.id}-pdf`;
                  const excelBusy = busyKey === `${item.id}-excel`;

                  return (
                    <tr
                      key={item.id}
                      className="border-b border-zinc-800/60 text-zinc-200 transition hover:bg-zinc-800/40"
                    >
                      <td className="px-4 py-3">
                        <div className="font-medium text-white">
                          {item.snapshot_label || `Snapshot #${item.scan_number}`}
                        </div>
                        {item.notes ? (
                          <div className="mt-1 text-xs text-zinc-500">{item.notes}</div>
                        ) : null}
                      </td>

                      <td className="px-4 py-3">
                        {item.created_at ? item.created_at.slice(0, 16).replace("T", " ") : "—"}
                      </td>

                      <td className="px-4 py-3">
                        <span
                          className={`rounded-full border px-3 py-1 text-xs ${getStatusBadgeClass(
                            item.status
                          )}`}
                        >
                          {getStatusLabel(item.status)}
                        </span>
                      </td>

                      <td className="px-4 py-3">{item.total_assets ?? 0}</td>
                      <td className="px-4 py-3">{item.total_software ?? 0}</td>
                      <td className="px-4 py-3">{item.total_checks ?? 0}</td>
                      <td className="px-4 py-3">{item.failed ?? 0}</td>
                      <td className={`px-4 py-3 font-semibold ${getScoreTone(item.compliance_score).text}`}>
                        {item.compliance_score != null ? `${Math.round(item.compliance_score)}%` : "—"}
                      </td>

                      <td className="px-4 py-3">
                        <button
                          type="button"
                          disabled={pdfBusy}
                          onClick={() => handleExport(item, "pdf")}
                          className="rounded-lg border border-zinc-700 px-3 py-1.5 text-xs text-white hover:bg-zinc-800 disabled:opacity-50"
                        >
                          {pdfBusy ? "..." : "Скачать PDF"}
                        </button>
                      </td>

                      <td className="px-4 py-3">
                        <button
                          type="button"
                          disabled={excelBusy}
                          onClick={() => handleExport(item, "excel")}
                          className="rounded-lg border border-zinc-700 px-3 py-1.5 text-xs text-white hover:bg-zinc-800 disabled:opacity-50"
                        >
                          {excelBusy ? "..." : "Скачать Excel"}
                        </button>
                      </td>

                      <td className="px-4 py-3">
                        {previous ? (
                          <Link
                            to={`/scan-compare?before=${previous.id}&after=${item.id}`}
                            className="rounded-lg border border-zinc-700 px-3 py-1.5 text-xs text-white hover:bg-zinc-800"
                          >
                            Сравнить
                          </Link>
                        ) : (
                          <span className="text-zinc-500">—</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </AppCard>
    </div>
    </OrgGate>
  );
}