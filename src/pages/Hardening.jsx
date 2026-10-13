import { Fragment, useEffect, useState } from "react";
import AppCard from "../components/ui/AppCard";
import StatCard from "../components/ui/StatCard";
import EmptyState from "../components/ui/EmptyState";
import ErrorState from "../components/ui/ErrorState";
import OrgGate from "../components/OrgGate";
import { SkeletonTable } from "../components/ui/Skeleton";
import SortableHeader from "../components/ui/SortableHeader";
import SeverityBadge from "../components/ui/SeverityBadge";
import CheckStatusBadge from "../components/ui/CheckStatusBadge";
import { useOrganization } from "../context/OrganizationContext";
import { getHardeningByOrganization } from "../api/hardening";
import { createRiskException, getRiskExceptions, revokeRiskException } from "../api/riskExceptions";
import { getCurrentUserRoleInOrganization } from "../api/users";
import { getRemediation, REMEDIATION_SOURCE_NOTE } from "../utils/remediation";
import { endOfLocalDayIso, formatDate, formatDateTime } from "../utils/datetime";

const INPUT = "rounded-xl border border-zinc-800 bg-zinc-950 px-3 py-2 text-sm text-white outline-none placeholder:text-zinc-500";
const PAGER = "rounded-xl border border-zinc-700 px-3 py-1.5 text-sm text-zinc-200 hover:bg-zinc-800 disabled:opacity-40";
// 36 проверок на хост, на тысячу хостов — десятки тысяч строк: фильтры, сортировка и страницы — на сервере.
const PAGE_SIZE = 100;
const EMPTY_SUMMARY = { total: 0, passed: 0, failed: 0, accepted: 0, errors: 0, mandatory: 0, hosts: [], open_by_severity: [] };
const STATUS_FILTERS = [
  { value: "", label: "Все статусы" },
  { value: "fail", label: "Нарушено" },
  { value: "pass", label: "Соблюдено" },
  { value: "error", label: "Не проверено" },
  { value: "accepted", label: "Риск принят" },
];
const SEVERITY_FILTERS = [
  { value: "", label: "Все уровни" },
  { value: "critical", label: "Критический" },
  { value: "high", label: "Высокий" },
  { value: "medium", label: "Средний" },
  { value: "low", label: "Низкий" },
];
const EXCEPTION_STATES = {
  active: { label: "Действует", tone: "border-violet-500/30 bg-violet-500/15 text-violet-300" },
  expired: { label: "Истёк срок", tone: "border-zinc-700 bg-zinc-800 text-zinc-400" },
  revoked: { label: "Отозвано", tone: "border-zinc-700 bg-zinc-800 text-zinc-400" },
};

// Нарушение с принятым риском остаётся fail (факт с хоста), но не входит в оценку и не требует устранения.
const isAccepted = (row) => row.status === "fail" && Boolean(row.risk_exception);

function RemediationCell({ row }) {
  if (isAccepted(row)) return <span className="text-violet-300">риск принят</span>;
  const remediation = getRemediation(row.status, row.rule?.severity);
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

function AcceptRiskForm({ row, onSubmit, onCancel }) {
  const [form, setForm] = useState({ reason: "", scope: "asset", expires_at: "" });

  function handleSubmit(e) {
    e.preventDefault();
    onSubmit({
      check_key: row.rule?.rule_code,
      asset_id: form.scope === "asset" ? row.asset?.id : null,
      reason: form.reason,
      expires_at: form.expires_at ? endOfLocalDayIso(form.expires_at) : null,
    });
  }

  return (
    <form onSubmit={handleSubmit} className="grid gap-3 rounded-2xl border border-violet-500/20 bg-violet-500/5 p-4 md:grid-cols-4">
      <div className="md:col-span-4 text-sm text-zinc-300">
        Принять риск: <span className="text-white">{row.rule?.title}</span>{" "}
        <span className="text-zinc-500">({row.rule?.rule_code})</span>. Нарушение останется в отчётах, но не будет
        входить в оценку соответствия.
      </div>
      <textarea
        aria-label="Обоснование"
        required
        className={`${INPUT} md:col-span-4`}
        rows={2}
        placeholder="Обоснование * (почему нарушение не устраняется и чем риск компенсирован)"
        value={form.reason}
        onChange={(e) => setForm({ ...form, reason: e.target.value })}
      />
      <select aria-label="Область" className={INPUT} value={form.scope} onChange={(e) => setForm({ ...form, scope: e.target.value })}>
        <option value="asset">Только {row.asset?.hostname}</option>
        <option value="org">Все активы организации</option>
      </select>
      <label className="flex items-center gap-2 text-sm text-zinc-400">
        До
        <input type="date" className={INPUT} value={form.expires_at} onChange={(e) => setForm({ ...form, expires_at: e.target.value })} />
      </label>
      <button type="submit" className="rounded-xl border border-violet-500/30 bg-violet-500/15 px-4 py-2 text-sm text-violet-200 hover:bg-violet-500/25">
        Принять риск
      </button>
      <button type="button" onClick={onCancel} className="rounded-xl border border-zinc-700 bg-zinc-950 px-4 py-2 text-sm text-zinc-300 hover:bg-zinc-800">
        Отмена
      </button>
    </form>
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
            Результаты проверок харденинга по организации{" "}
            <span className="text-white">{selectedOrganization?.name || "—"}</span>
          </p>
        </div>
        {/* key: смена организации — фильтры, страница и формы с чистого листа */}
        {selectedOrganizationId ? <HardeningView key={selectedOrganizationId} organizationId={selectedOrganizationId} /> : null}
      </div>
    </OrgGate>
  );
}

function HardeningView({ organizationId }) {
  const [result, setResult] = useState({ key: null, items: [], total: 0, summary: EMPTY_SUMMARY, error: "" });
  const [exceptions, setExceptions] = useState([]);
  const [showHistory, setShowHistory] = useState(false);
  const [canManage, setCanManage] = useState(false);
  const [acceptingId, setAcceptingId] = useState(null);
  const [actionError, setActionError] = useState("");
  const [reloadKey, setReloadKey] = useState(0);
  const [search, setSearch] = useState("");
  const [filters, setFilters] = useState({ q: "", host: "", status: "", severity: "" });
  const [sort, setSort] = useState({ key: "deadline", dir: "asc" });
  const [offset, setOffset] = useState(0);

  // Поиск с задержкой: запрос не на каждую букву.
  useEffect(() => {
    const timer = setTimeout(() => {
      setFilters((prev) => (prev.q === search ? prev : { ...prev, q: search }));
      setOffset(0);
    }, 300);
    return () => clearTimeout(timer);
  }, [search]);

  // Принимать и отзывать риск может администратор организации (сервер проверяет это сам, здесь — только вид).
  useEffect(() => {
    let cancelled = false;
    getCurrentUserRoleInOrganization(organizationId)
      .then((role) => { if (!cancelled) setCanManage(role === "admin"); })
      .catch(() => { if (!cancelled) setCanManage(false); });
    return () => { cancelled = true; };
  }, [organizationId]);

  useEffect(() => {
    let cancelled = false;
    getRiskExceptions(organizationId, { includeInactive: showHistory })
      .then((list) => { if (!cancelled) setExceptions(Array.isArray(list) ? list : []); })
      .catch(() => { if (!cancelled) setExceptions([]); });
    return () => { cancelled = true; };
  }, [organizationId, showHistory, reloadKey]);

  // Идёт загрузка, пока не пришёл ответ на текущий запрос; ответ на устаревший запрос отбрасывается.
  const requestKey = JSON.stringify([filters, sort, offset, reloadKey]);
  const loading = result.key !== requestKey;

  useEffect(() => {
    let cancelled = false;
    getHardeningByOrganization(organizationId, { ...filters, sort: sort.key, dir: sort.dir, limit: PAGE_SIZE, offset })
      .then((data) => {
        if (!cancelled) setResult({ key: requestKey, items: data.items || [], total: data.total || 0, summary: data.summary || EMPTY_SUMMARY, error: "" });
      })
      .catch((error) => {
        if (!cancelled) setResult((prev) => ({ ...prev, key: requestKey, error: error.message || "Не удалось получить данные" }));
      });
    return () => { cancelled = true; };
  }, [organizationId, filters, sort, offset, requestKey]);

  function setFilter(name, value) {
    setFilters((prev) => ({ ...prev, [name]: value }));
    setOffset(0);
  }

  function toggleSort(key) {
    setSort((prev) => ({ key, dir: prev.key === key && prev.dir === "asc" ? "desc" : "asc" }));
    setOffset(0);
  }

  async function runAction(action) {
    try {
      setActionError("");
      await action();
      setAcceptingId(null);
      setReloadKey((n) => n + 1);
    } catch (error) {
      setActionError(error.message);
    }
  }

  function handleRevoke(exceptionId) {
    if (!window.confirm("Отозвать принятие риска? Нарушение снова войдёт в оценку соответствия.")) return;
    runAction(() => revokeRiskException(organizationId, exceptionId));
  }

  const { summary, items: rows, error: loadError } = result;
  const firstLoad = result.key === null;
  const filtering = Boolean(filters.q.trim() || filters.host || filters.status || filters.severity);
  const header = (label, key) => (
    <SortableHeader label={label} sortKey={key} activeKey={sort.key} sortDir={sort.dir} onSort={toggleSort} />
  );

  return (
    <>
      <div className="grid gap-4 md:grid-cols-5">
        <StatCard label="Всего проверок" value={summary.total} loading={firstLoad} hint="Проверки по активам" tone="info" />
        <StatCard label="Соблюдено" value={summary.passed} loading={firstLoad} hint="Успешно выполнены" tone="success" />
        <StatCard label="Нарушено" value={summary.failed} loading={firstLoad} hint="Требуют исправления" tone="danger" />
        <StatCard label="Риск принят" value={summary.accepted} loading={firstLoad} hint="Нарушения, осознанно оставленные; не входят в оценку" tone="default" />
        <StatCard
          label="Обязательно к устранению"
          value={summary.mandatory}
          loading={firstLoad}
          hint="Нарушения критического и высокого уровня (п. 3.4.4 методики ФСТЭК)"
          tone="warning"
        />
      </div>

      {actionError ? <ErrorState title="Ошибка действия" description={actionError} /> : null}

      <AppCard title="Результаты проверок" subtitle={REMEDIATION_SOURCE_NOTE}>
        {loadError ? (
          <ErrorState title="Ошибка загрузки" description={loadError} />
        ) : firstLoad ? (
          <SkeletonTable rows={6} cols={8} />
        ) : summary.total === 0 ? (
          <EmptyState
            title="Нет результатов проверок"
            description="Результаты появятся после первого отчёта агента или проверки по выгрузке."
          />
        ) : (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center gap-3">
              <input
                type="search"
                aria-label="Поиск проверок"
                placeholder="Поиск: проверка, код, хост…"
                className={`${INPUT} min-w-[16rem] flex-1`}
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
              <select aria-label="Статус" className={INPUT} value={filters.status} onChange={(e) => setFilter("status", e.target.value)}>
                {STATUS_FILTERS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
              </select>
              <select aria-label="Уровень" className={INPUT} value={filters.severity} onChange={(e) => setFilter("severity", e.target.value)}>
                {SEVERITY_FILTERS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
              </select>
              <select aria-label="Хост" className={INPUT} value={filters.host} onChange={(e) => setFilter("host", e.target.value)}>
                <option value="">Все хосты</option>
                {summary.hosts.map((name) => <option key={name} value={name}>{name}</option>)}
              </select>
              <span className="text-sm text-zinc-400" aria-live="polite">
                {filtering ? `Найдено: ${result.total} из ${summary.total}` : `Всего: ${summary.total}`}
              </span>
            </div>

            {rows.length === 0 ? (
              <div className="text-sm text-zinc-400">{loading ? "Поиск…" : "Под фильтр не попала ни одна проверка."}</div>
            ) : (
              <div className={`overflow-x-auto ${loading ? "opacity-60" : ""}`}>
                <table className="min-w-full text-sm">
                  <thead className="border-b border-zinc-800 text-left text-zinc-400">
                    <tr>
                      {header("Актив", "asset")}
                      {header("Правило", "rule")}
                      {header("Уровень", "severity")}
                      <th className="px-4 py-3">Фактически</th>
                      <th className="px-4 py-3">Требуется</th>
                      {header("Статус", "status")}
                      {header("Срок устранения", "deadline")}
                      {header("Дата", "checked_at")}
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((item) => (
                      <Fragment key={item.id}>
                        <tr className="border-b border-zinc-800/60 text-zinc-200 transition hover:bg-zinc-800/40">
                          <td className="px-4 py-3 font-medium text-white">
                            {item.asset?.hostname || "—"}
                          </td>
                          <td className="px-4 py-3">
                            <div className="font-medium text-white">{item.rule?.title || "—"}</div>
                            <div className="text-xs text-zinc-500">{item.rule?.rule_code || "—"}</div>
                            {isAccepted(item) ? (
                              <div className="mt-1 max-w-md text-xs text-violet-300">
                                Риск принят{item.risk_exception.org_wide ? " для всех активов" : ""}
                                {item.risk_exception.expires_at ? ` до ${formatDate(item.risk_exception.expires_at)}` : ""}:{" "}
                                <span className="text-zinc-300">{item.risk_exception.reason}</span>
                              </div>
                            ) : item.status === "fail" && item.rule?.remediation ? (
                              <div className="mt-1 max-w-md text-xs text-zinc-400">Как исправить: {item.rule.remediation}</div>
                            ) : null}
                          </td>
                          <td className="px-4 py-3"><SeverityBadge value={item.rule?.severity} /></td>
                          <td className="px-4 py-3">{item.actual_value || "—"}</td>
                          <td className="px-4 py-3">{item.expected_value || item.rule?.expected_value || "—"}</td>
                          <td className="px-4 py-3">
                            <div className="flex flex-col items-start gap-2">
                              <CheckStatusBadge value={item.status} />
                              {canManage && isAccepted(item) ? (
                                <button type="button" onClick={() => handleRevoke(item.risk_exception.id)} className="text-xs text-zinc-400 underline hover:text-white">
                                  отозвать
                                </button>
                              ) : canManage && item.status === "fail" && item.rule?.rule_code ? (
                                <button
                                  type="button"
                                  aria-expanded={acceptingId === item.id}
                                  onClick={() => setAcceptingId(acceptingId === item.id ? null : item.id)}
                                  className="text-xs text-violet-300 underline hover:text-violet-200"
                                >
                                  принять риск
                                </button>
                              ) : null}
                            </div>
                          </td>
                          <td className="px-4 py-3"><RemediationCell row={item} /></td>
                          <td className="px-4 py-3">{formatDateTime(item.checked_at)}</td>
                        </tr>
                        {acceptingId === item.id ? (
                          <tr className="border-b border-zinc-800/60">
                            <td colSpan={8} className="px-4 py-3">
                              <AcceptRiskForm
                                row={item}
                                onCancel={() => setAcceptingId(null)}
                                onSubmit={(body) => runAction(() => createRiskException(organizationId, body))}
                              />
                            </td>
                          </tr>
                        ) : null}
                      </Fragment>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {result.total > PAGE_SIZE ? (
              <div className="flex items-center gap-3 text-sm text-zinc-400">
                <button type="button" className={PAGER} disabled={offset === 0 || loading} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}>
                  Назад
                </button>
                <span>{offset + 1}–{Math.min(offset + PAGE_SIZE, result.total)} из {result.total}</span>
                <button type="button" className={PAGER} disabled={offset + PAGE_SIZE >= result.total || loading} onClick={() => setOffset(offset + PAGE_SIZE)}>
                  Вперёд
                </button>
              </div>
            ) : null}
          </div>
        )}
      </AppCard>

      <AppCard
        title="Принятые риски"
        subtitle="Решения не устранять нарушение: кто принял, почему и до какого срока. Отзыв сохраняется в истории."
      >
        <label className="mb-4 flex items-center gap-2 text-sm text-zinc-400">
          <input type="checkbox" checked={showHistory} onChange={(e) => setShowHistory(e.target.checked)} />
          Показать отозванные и истёкшие
        </label>
        {exceptions.length === 0 ? (
          <EmptyState
            title="Нет принятых рисков"
            description={canManage ? "Принять риск можно в таблице выше — у проваленной проверки." : "Администратор организации ещё не принимал риски."}
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead className="border-b border-zinc-800 text-left text-zinc-400">
                <tr>
                  <th className="px-4 py-3">Проверка</th>
                  <th className="px-4 py-3">Область</th>
                  <th className="px-4 py-3">Обоснование</th>
                  <th className="px-4 py-3">Принял</th>
                  <th className="px-4 py-3">Срок</th>
                  <th className="px-4 py-3">Состояние</th>
                </tr>
              </thead>
              <tbody>
                {exceptions.map((item) => {
                  const state = EXCEPTION_STATES[item.state] || EXCEPTION_STATES.revoked;
                  return (
                    <tr key={item.id} className="border-b border-zinc-800/60 text-zinc-200">
                      <td className="px-4 py-3 font-medium text-white">{item.check_key}</td>
                      <td className="px-4 py-3">{item.asset_hostname || "все активы"}</td>
                      <td className="max-w-md px-4 py-3 text-zinc-300">{item.reason}</td>
                      <td className="px-4 py-3">
                        <div>{item.created_by_email || "—"}</div>
                        <div className="text-xs text-zinc-500">{formatDate(item.created_at)}</div>
                      </td>
                      <td className="px-4 py-3">{formatDate(item.expires_at, "бессрочно")}</td>
                      <td className="px-4 py-3">
                        <div className="flex flex-col items-start gap-2">
                          <span className={`rounded-full border px-2 py-1 text-xs ${state.tone}`}>{state.label}</span>
                          {item.state === "revoked" && item.revoked_by_email ? (
                            <span className="text-xs text-zinc-500">{item.revoked_by_email}, {formatDate(item.revoked_at)}</span>
                          ) : null}
                          {canManage && item.state === "active" ? (
                            <button type="button" onClick={() => handleRevoke(item.id)} className="text-xs text-zinc-400 underline hover:text-white">
                              отозвать
                            </button>
                          ) : null}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </AppCard>
    </>
  );
}
