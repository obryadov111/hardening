import { Fragment, useEffect, useMemo, useState } from "react";
import AppCard from "../components/ui/AppCard";
import StatCard from "../components/ui/StatCard";
import EmptyState from "../components/ui/EmptyState";
import ErrorState from "../components/ui/ErrorState";
import OrgGate from "../components/OrgGate";
import { SkeletonTable } from "../components/ui/Skeleton";
import SortableHeader from "../components/ui/SortableHeader";
import SeverityBadge from "../components/ui/SeverityBadge";
import CheckStatusBadge from "../components/ui/CheckStatusBadge";
import { useSort } from "../hooks/useSort";
import { useOrganization } from "../context/OrganizationContext";
import { getHardeningByOrganization } from "../api/hardening";
import { createRiskException, getRiskExceptions, revokeRiskException } from "../api/riskExceptions";
import { getCurrentUserRoleInOrganization } from "../api/users";
import { getRemediation, REMEDIATION_SOURCE_NOTE } from "../utils/remediation";
import { endOfLocalDayIso, formatDate, formatDateTime } from "../utils/datetime";

const INPUT = "rounded-xl border border-zinc-800 bg-zinc-950 px-3 py-2 text-sm text-white outline-none placeholder:text-zinc-500";
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
        className={`${INPUT} md:col-span-4`}
        rows={2}
        placeholder="Обоснование * (почему нарушение не устраняется и чем риск компенсирован)"
        value={form.reason}
        onChange={(e) => setForm({ ...form, reason: e.target.value })}
      />
      <select className={INPUT} value={form.scope} onChange={(e) => setForm({ ...form, scope: e.target.value })}>
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

  const [rows, setRows] = useState([]);
  const [exceptions, setExceptions] = useState([]);
  const [showHistory, setShowHistory] = useState(false);
  const [canManage, setCanManage] = useState(false);
  const [acceptingId, setAcceptingId] = useState(null);
  const [actionError, setActionError] = useState("");
  const [reloadKey, setReloadKey] = useState(0);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    async function loadData() {
      if (!selectedOrganizationId) {
        setRows([]);
        setExceptions([]);
        setCanManage(false);
        setLoading(false);
        return;
      }

      try {
        setLoading(true);
        const [data, exceptionList, role] = await Promise.all([
          getHardeningByOrganization(selectedOrganizationId),
          getRiskExceptions(selectedOrganizationId, { includeInactive: showHistory }).catch(() => []),
          getCurrentUserRoleInOrganization(selectedOrganizationId).catch(() => null),
        ]);
        setRows(data);
        setExceptions(Array.isArray(exceptionList) ? exceptionList : []);
        // Принимать и отзывать риск может администратор организации (сервер проверяет это сам, здесь — только вид).
        setCanManage(role === "admin");
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
  }, [selectedOrganizationId, orgLoading, showHistory, reloadKey]);

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
    runAction(() => revokeRiskException(selectedOrganizationId, exceptionId));
  }

  const stats = useMemo(() => {
    return {
      total: rows.length,
      passed: rows.filter((item) => item.status === "pass").length,
      failed: rows.filter((item) => item.status === "fail" && !isAccepted(item)).length,
      accepted: rows.filter(isAccepted).length,
      // Нарушения критического и высокого уровня — обязательны к устранению (п. 3.4.4 методики ФСТЭК).
      // Раньше здесь считались правила уровня critical независимо от результата, включая пройденные.
      mandatory: rows.filter((item) => !isAccepted(item) && getRemediation(item.status, item.rule?.severity)?.mandatory).length,
    };
  }, [rows]);

  const { sortedRows, activeKey, sortDir, toggleSort } = useSort(rows, {
    asset: (row) => row.asset?.hostname || "",
    rule: (row) => row.rule?.title || "",
    severity: (row) => row.rule?.severity || "",
    actual: (row) => row.actual_value || "",
    expected: (row) => row.expected_value || row.rule?.expected_value || "",
    status: (row) => (isAccepted(row) ? "fail-accepted" : row.status || ""),
    deadline: (row) => (isAccepted(row) ? 8 : getRemediation(row.status, row.rule?.severity)?.order ?? 9),
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

      <div className="grid gap-4 md:grid-cols-5">
        <StatCard label="Всего проверок" value={stats.total} loading={loading} hint="Проверки по активам" tone="info" />
        <StatCard label="Passed" value={stats.passed} loading={loading} hint="Успешно выполнены" tone="success" />
        <StatCard label="Failed" value={stats.failed} loading={loading} hint="Требуют исправления" tone="danger" />
        <StatCard label="Риск принят" value={stats.accepted} loading={loading} hint="Нарушения, осознанно оставленные; не входят в оценку" tone="default" />
        <StatCard
          label="Обязательно к устранению"
          value={stats.mandatory}
          loading={loading}
          hint="Нарушения уровня critical и high (п. 3.4.4 методики ФСТЭК)"
          tone="warning"
        />
      </div>

      {actionError ? <ErrorState title="Ошибка действия" description={actionError} /> : null}

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
                            <button type="button" onClick={() => setAcceptingId(acceptingId === item.id ? null : item.id)} className="text-xs text-violet-300 underline hover:text-violet-200">
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
                            onSubmit={(body) => runAction(() => createRiskException(selectedOrganizationId, body))}
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
    </div>
    </OrgGate>
  );
}
