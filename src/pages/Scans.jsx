import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import AppCard from "../components/ui/AppCard";
import StatCard from "../components/ui/StatCard";
import EmptyState from "../components/ui/EmptyState";
import ErrorState from "../components/ui/ErrorState";
import OrgGate from "../components/OrgGate";
import { SkeletonTable } from "../components/ui/Skeleton";
import { getScoreTone } from "../utils/score";
import { useOrganization } from "../context/OrganizationContext";
import { getSnapshotsByOrganization } from "../api/snapshots";
import { getAssetsByOrganization } from "../api/assets";
import { downloadSnapshotExport } from "../api/exports";
import { formatDateTime } from "../utils/datetime";
import { collectionSource } from "../utils/collection";

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

const PAGE_SIZE = 50;
const PAGER = "rounded-xl border border-zinc-700 px-3 py-1.5 text-sm text-zinc-200 hover:bg-zinc-800 disabled:opacity-40";
const SELECT = "rounded-xl border border-zinc-800 bg-zinc-950 px-3 py-2 text-sm text-white outline-none";
const EMPTY_SUMMARY = { total: 0, completed: 0, failed: 0, latest: null };

export default function Scans() {
  const {
    selectedOrganization,
    selectedOrganizationId,
    loading: orgLoading,
    hasOrganizations,
    error: orgError,
  } = useOrganization();

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
            История сканирований организации{" "}
            <span className="text-white">{selectedOrganization?.name || "—"}</span>.{" "}
            Устройство без агента и SSH-доступа можно проверить{" "}
            <Link to="/offline-scan" className="text-blue-300 underline hover:text-blue-200">по выгрузке конфигурации</Link>.
          </p>
        </div>
        {/* key: смена организации — фильтр, страница и выбор для сравнения с чистого листа */}
        {selectedOrganizationId ? <ScansView key={selectedOrganizationId} organizationId={selectedOrganizationId} /> : null}
      </div>
    </OrgGate>
  );
}

function ScansView({ organizationId }) {
  const [result, setResult] = useState({ key: null, items: [], total: 0, summary: EMPTY_SUMMARY, error: "" });
  const [hosts, setHosts] = useState([]);
  const [host, setHost] = useState("");
  const [offset, setOffset] = useState(0);
  const [busyKey, setBusyKey] = useState("");
  const [exportError, setExportError] = useState("");
  // Два скана для сравнения, отмеченные пользователем (любые, не только соседние; выбор переживает смену страницы).
  const [selected, setSelected] = useState([]);
  const navigate = useNavigate();

  useEffect(() => {
    let cancelled = false;
    getAssetsByOrganization(organizationId)
      .then((assets) => {
        if (!cancelled) setHosts([...new Set((assets || []).map((a) => a.hostname))].sort((a, b) => a.localeCompare(b, "ru")));
      })
      .catch(() => { if (!cancelled) setHosts([]); });
    return () => { cancelled = true; };
  }, [organizationId]);

  const requestKey = JSON.stringify([host, offset]);
  const loading = result.key !== requestKey;

  useEffect(() => {
    let cancelled = false;
    getSnapshotsByOrganization(organizationId, { host, limit: PAGE_SIZE, offset })
      .then((data) => {
        if (!cancelled) setResult({ key: requestKey, items: data.items || [], total: data.total || 0, summary: data.summary || EMPTY_SUMMARY, error: "" });
      })
      .catch((error) => {
        if (!cancelled) setResult((prev) => ({ ...prev, key: requestKey, error: error.message || "Не удалось получить данные" }));
      });
    return () => { cancelled = true; };
  }, [organizationId, host, offset, requestKey]);

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
      setExportError(`Не удалось сформировать ${format === "pdf" ? "PDF" : "Excel"}: ${error.message}`);
    } finally {
      setBusyKey("");
    }
  }

  const isSelected = (id) => selected.some((item) => item.id === id);

  function toggleSelected(snapshot) {
    setSelected((current) => {
      if (current.some((item) => item.id === snapshot.id)) return current.filter((item) => item.id !== snapshot.id);
      // Третий отмеченный скан вытесняет отмеченный первым — выбранными всегда остаются два последних.
      return [...current, snapshot].slice(-2);
    });
  }

  function compareSelected() {
    const [a, b] = selected;
    if (!a || !b) return;
    // «Было» — более ранний скан, «стало» — более поздний, в каком бы порядке их ни отметили.
    const [before, after] = new Date(a.created_at) <= new Date(b.created_at) ? [a, b] : [b, a];
    navigate(`/scan-compare?before=${before.id}&after=${after.id}`);
  }

  const { summary, items: rows, error: loadError } = result;
  const firstLoad = result.key === null;

  return (
    <>
      <div className="grid gap-4 md:grid-cols-4">
        <StatCard label="Всего сканов" value={summary.total} loading={firstLoad} hint="История сканирований" tone="info" />
        <StatCard label="Завершено" value={summary.completed} loading={firstLoad} hint="Успешно обработанные" tone="success" />
        <StatCard label="Ошибки" value={summary.failed} loading={firstLoad} hint="Неудачные запуски" tone="danger" />
        <StatCard
          label="Последнее соответствие"
          value={summary.latest?.compliance_score != null ? `${Math.round(summary.latest.compliance_score)}%` : "—"}
          loading={firstLoad}
          hint="Последний скан"
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

      <AppCard title="История сканирований" subtitle="Сравнение и экспорт по каждому запуску">
        {summary.total > 1 ? (
          <div className="mb-4 flex flex-wrap items-center gap-3 rounded-xl border border-zinc-800 bg-zinc-950/70 px-4 py-3 text-sm">
            <span className="text-zinc-400">
              Отметьте два любых скана для сравнения: выбрано {selected.length} из 2
            </span>
            <button
              type="button"
              disabled={selected.length !== 2}
              onClick={compareSelected}
              className="rounded-lg border border-blue-500/30 bg-blue-500/15 px-3 py-1.5 text-xs text-blue-200 hover:bg-blue-500/25 disabled:opacity-40"
            >
              Сравнить выбранные
            </button>
            {selected.length ? (
              <button type="button" onClick={() => setSelected([])} className="text-xs text-zinc-400 underline hover:text-white">
                сбросить
              </button>
            ) : null}
            <select
              aria-label="Хост"
              className={`${SELECT} ml-auto`}
              value={host}
              onChange={(e) => { setHost(e.target.value); setOffset(0); }}
            >
              <option value="">Все хосты</option>
              {hosts.map((name) => <option key={name} value={name}>{name}</option>)}
            </select>
          </div>
        ) : null}
        {loadError ? (
          <ErrorState title="Ошибка загрузки" description={loadError} />
        ) : firstLoad ? (
          <SkeletonTable rows={6} cols={8} />
        ) : summary.total === 0 ? (
          <EmptyState
            title="Нет сканирований"
            description="Сканы появятся после первого отчёта агента или проверки по выгрузке."
          />
        ) : rows.length === 0 ? (
          <div className="text-sm text-zinc-400">{loading ? "Загрузка…" : "У этого хоста сканов нет."}</div>
        ) : (
          <div className={`overflow-x-auto ${loading ? "opacity-60" : ""}`}>
            <table className="min-w-full text-sm">
              <thead className="border-b border-zinc-800 text-left text-zinc-400">
                <tr>
                  <th className="px-4 py-3"><span className="sr-only">Выбрать для сравнения</span></th>
                  <th className="px-4 py-3">Скан</th>
                  <th className="px-4 py-3">Хосты</th>
                  <th className="px-4 py-3">Дата</th>
                  <th className="px-4 py-3">Статус</th>
                  <th className="px-4 py-3">Активы</th>
                  <th className="px-4 py-3">ПО</th>
                  <th className="px-4 py-3">Проверок</th>
                  <th className="px-4 py-3">Нарушено</th>
                  <th className="px-4 py-3">Соответствие</th>
                  <th className="px-4 py-3">PDF</th>
                  <th className="px-4 py-3">Excel</th>
                  <th className="px-4 py-3">С предыдущим</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((item) => {
                  // Предыдущий снимок того же актива (считает бэкенд): соседняя строка может быть про другой сервер.
                  const previousId = item.previous_snapshot_id || null;
                  const pdfBusy = busyKey === `${item.id}-pdf`;
                  const excelBusy = busyKey === `${item.id}-excel`;

                  return (
                    <tr
                      key={item.id}
                      className={`border-b border-zinc-800/60 text-zinc-200 transition hover:bg-zinc-800/40 ${
                        isSelected(item.id) ? "bg-blue-500/10" : ""
                      }`}
                    >
                      <td className="px-4 py-3">
                        <input
                          type="checkbox"
                          aria-label={`Выбрать скан №${item.scan_number} для сравнения`}
                          checked={isSelected(item.id)}
                          onChange={() => toggleSelected(item)}
                          className="h-4 w-4 accent-blue-500"
                        />
                      </td>
                      <td className="px-4 py-3">
                        <div className="font-medium text-white">
                          {item.snapshot_label || `Скан №${item.scan_number}`}
                        </div>
                        {collectionSource(item.collection) ? (
                          <div
                            className="mt-1 inline-block rounded-full border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 text-xs text-amber-300"
                            title={collectionSource(item.collection).text}
                          >
                            {collectionSource(item.collection).short}
                          </div>
                        ) : null}
                        {item.notes ? (
                          <div className="mt-1 text-xs text-zinc-500">{item.notes}</div>
                        ) : null}
                      </td>

                      <td className="px-4 py-3">
                        {item.hosts?.length ? (
                          <span title={item.hosts.join(", ")}>
                            {item.hosts.slice(0, 3).join(", ")}
                            {item.hosts.length > 3 ? ` и ещё ${item.hosts.length - 3}` : ""}
                          </span>
                        ) : "—"}
                      </td>

                      <td className="px-4 py-3">
                        {formatDateTime(item.created_at)}
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
                          aria-label={`Скачать PDF скана №${item.scan_number}`}
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
                          aria-label={`Скачать Excel скана №${item.scan_number}`}
                          onClick={() => handleExport(item, "excel")}
                          className="rounded-lg border border-zinc-700 px-3 py-1.5 text-xs text-white hover:bg-zinc-800 disabled:opacity-50"
                        >
                          {excelBusy ? "..." : "Скачать Excel"}
                        </button>
                      </td>

                      <td className="px-4 py-3">
                        {previousId ? (
                          <Link
                            to={`/scan-compare?before=${previousId}&after=${item.id}`}
                            aria-label={`Сравнить скан №${item.scan_number} с предыдущим`}
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
        {result.total > PAGE_SIZE ? (
          <div className="mt-4 flex items-center gap-3 text-sm text-zinc-400">
            <button type="button" className={PAGER} disabled={offset === 0 || loading} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}>
              Назад
            </button>
            <span>{offset + 1}–{Math.min(offset + PAGE_SIZE, result.total)} из {result.total}</span>
            <button type="button" className={PAGER} disabled={offset + PAGE_SIZE >= result.total || loading} onClick={() => setOffset(offset + PAGE_SIZE)}>
              Вперёд
            </button>
          </div>
        ) : null}
      </AppCard>
    </>
  );
}
