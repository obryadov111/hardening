import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import AppCard from "../components/ui/AppCard";
import StatCard from "../components/ui/StatCard";
import { compareSnapshots, getSnapshotsByOrganization } from "../api/snapshots";
import { useOrganization } from "../context/OrganizationContext";
import { formatDateTime } from "../utils/datetime";

function getChangeLabel(changeType) {
  switch (changeType) {
    case "fixed":
      return "Исправлено";
    case "regressed":
      return "Ухудшилось";
    case "still_failed":
      return "Не исправлено";
    case "new":
      return "Новая запись";
    case "removed":
      return "Удалено";
    case "changed":
      return "Изменилось";
    case "accepted":
      return "Риск принят";
    default:
      return "Без изменений";
  }
}

function getChangeClass(changeType) {
  switch (changeType) {
    case "fixed":
      return "text-emerald-300";
    case "regressed":
      return "text-rose-300";
    case "still_failed":
      return "text-amber-300";
    case "new":
      return "text-blue-300";
    case "removed":
      return "text-zinc-300";
    case "changed":
      return "text-violet-300";
    case "accepted":
      return "text-fuchsia-300";
    default:
      return "text-zinc-400";
  }
}

function snapshotLabel(snapshot) {
  const date = formatDateTime(snapshot.created_at, "без даты");
  const score = snapshot.compliance_score != null ? ` · ${Math.round(snapshot.compliance_score)}%` : "";
  return `#${snapshot.scan_number}${snapshot.snapshot_label ? ` «${snapshot.snapshot_label}»` : ""} · ${date}${score}`;
}

const SELECT = "w-full rounded-xl border border-zinc-800 bg-zinc-950 px-3 py-2 text-sm text-white outline-none";

/** Выбор двух снимков: любые снимки организации, а не только «предыдущий». */
function SnapshotPicker({ snapshots, beforeId, afterId, onCompare }) {
  const [before, setBefore] = useState(beforeId || "");
  const [after, setAfter] = useState(afterId || "");

  const byId = useMemo(() => Object.fromEntries(snapshots.map((s) => [s.id, s])), [snapshots]);
  const reversed = before && after && byId[before] && byId[after]
    && new Date(byId[before].created_at) > new Date(byId[after].created_at);

  return (
    <AppCard title="Какие сканы сравнить" subtitle="Выберите любые два снимка организации: «было» — исходное состояние, «стало» — результат">
      <form
        className="grid items-end gap-3 md:grid-cols-[1fr_auto_1fr_auto]"
        onSubmit={(e) => {
          e.preventDefault();
          if (before && after) onCompare(before, after);
        }}
      >
        <label className="text-sm text-zinc-400">
          Было
          <select className={`${SELECT} mt-1`} value={before} onChange={(e) => setBefore(e.target.value)}>
            <option value="">— выберите скан —</option>
            {snapshots.map((s) => <option key={s.id} value={s.id}>{snapshotLabel(s)}</option>)}
          </select>
        </label>
        <button
          type="button"
          title="Поменять местами"
          onClick={() => { setBefore(after); setAfter(before); }}
          className="rounded-xl border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-300 hover:bg-zinc-800"
        >
          ⇄
        </button>
        <label className="text-sm text-zinc-400">
          Стало
          <select className={`${SELECT} mt-1`} value={after} onChange={(e) => setAfter(e.target.value)}>
            <option value="">— выберите скан —</option>
            {snapshots.map((s) => <option key={s.id} value={s.id}>{snapshotLabel(s)}</option>)}
          </select>
        </label>
        <button
          type="submit"
          disabled={!before || !after || before === after}
          className="rounded-xl border border-blue-500/30 bg-blue-500/15 px-4 py-2 text-sm text-blue-200 hover:bg-blue-500/25 disabled:opacity-40"
        >
          Сравнить
        </button>
      </form>
      {before && before === after ? (
        <div className="mt-3 text-sm text-amber-300">Выбран один и тот же скан — выберите два разных.</div>
      ) : reversed ? (
        <div className="mt-3 text-sm text-amber-300">
          «Было» новее, чем «стало»: изменения покажутся в обратную сторону. Нажмите ⇄, чтобы поменять местами.
        </div>
      ) : null}
    </AppCard>
  );
}

export default function ScanCompare() {
  const [searchParams, setSearchParams] = useSearchParams();
  const beforeId = searchParams.get("before");
  const afterId = searchParams.get("after");
  const { selectedOrganizationId, loading: orgLoading } = useOrganization();

  const [snapshots, setSnapshots] = useState([]);
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (orgLoading || !selectedOrganizationId) return;
    getSnapshotsByOrganization(selectedOrganizationId)
      .then((list) => setSnapshots(Array.isArray(list) ? list : []))
      .catch((err) => {
        console.error("Ошибка загрузки списка сканов:", err.message);
        setSnapshots([]);
      });
  }, [selectedOrganizationId, orgLoading]);

  // Без параметров — по умолчанию последний скан и предыдущий скан того же актива; выбор меняется в форме.
  useEffect(() => {
    if (beforeId || afterId || snapshots.length < 2) return;
    const latest = snapshots[0];
    const previous = latest.previous_snapshot_id || snapshots[1].id;
    setSearchParams({ before: previous, after: latest.id }, { replace: true });
  }, [beforeId, afterId, snapshots, setSearchParams]);

  useEffect(() => {
    async function loadData() {
      if (!beforeId || !afterId || beforeId === afterId) {
        setData(null);
        return;
      }
      try {
        setLoading(true);
        setError("");
        setData(await compareSnapshots(beforeId, afterId));
      } catch (err) {
        console.error("Ошибка сравнения сканов:", err.message);
        setData(null);
        setError(err.message);
      } finally {
        setLoading(false);
      }
    }

    loadData();
  }, [beforeId, afterId]);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-white">Сравнение сканов</h1>
        <p className="mt-1 text-sm text-zinc-400">
          {data
            ? `Snapshot #${data.beforeSnapshot?.scan_number} → Snapshot #${data.afterSnapshot?.scan_number}`
            : "Выберите два скана для сравнения"}
        </p>
      </div>

      <SnapshotPicker
        // Пересоздаётся при смене выбора в адресе (в т.ч. «Назад» в браузере) — форма показывает актуальную пару.
        key={`${beforeId}-${afterId}`}
        snapshots={snapshots}
        beforeId={beforeId}
        afterId={afterId}
        onCompare={(before, after) => setSearchParams({ before, after })}
      />

      {loading ? (
        <div className="text-zinc-400">Загрузка сравнения...</div>
      ) : error ? (
        <div className="rounded-xl border border-rose-500/20 bg-rose-500/10 px-4 py-3 text-sm text-rose-300">
          Не удалось сравнить сканы: {error}
        </div>
      ) : data ? (
        <ComparisonResult data={data} />
      ) : snapshots.length < 2 && !orgLoading ? (
        <div className="text-zinc-500">Для сравнения нужно хотя бы два скана в организации.</div>
      ) : null}
    </div>
  );
}

function ComparisonResult({ data }) {
  const { beforeSnapshot, afterSnapshot, summary, commonAssets, onlyBeforeAssets, onlyAfterAssets } = data;

  const rows = data.diffs || [];

  return (
    <div className="space-y-6">

      {commonAssets === 0 ? (
        <div className="rounded-xl border border-amber-500/20 bg-amber-500/10 px-4 py-3 text-sm text-amber-300">
          У этих снимков нет общих активов — сравнивать нечего. Снимок создаётся на каждый прогон агента и
          обычно покрывает один сервер: сравнивайте снимки одного и того же сервера.
        </div>
      ) : onlyBeforeAssets || onlyAfterAssets ? (
        <div className="rounded-xl border border-zinc-800 bg-zinc-950/70 px-4 py-3 text-sm text-zinc-400">
          Сравниваются только общие активы ({commonAssets}). Активы, которые сканировались лишь в одном из
          снимков ({onlyBeforeAssets + onlyAfterAssets}), в сравнение не входят: они не «удалены» и не «новые».
        </div>
      ) : null}

      <div className="grid gap-4 md:grid-cols-3 xl:grid-cols-6">
        <StatCard label="Исправлено" value={summary.fixed} hint="fail → pass" tone="success" />
        <StatCard label="Ухудшилось" value={summary.regressed} hint="pass → fail" tone="danger" />
        <StatCard label="Не исправлено" value={summary.stillFailed} hint="fail → fail" tone="warning" />
        <StatCard label="Новые проблемы" value={summary.newIssues} hint="Проверка появилась и провалена" tone="info" />
        <StatCard label="Риск принят" value={summary.accepted || 0} hint="Нарушение осталось, но исключено из оценки" tone="default" />
        <StatCard label="Удалено" value={summary.removed} hint="Проверки нет в новом снимке (например, изменилась версия пака)" tone="default" />
      </div>

      <AppCard title="Итоги сравнения" subtitle="Сравнение метрик двух snapshot">
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <div className="rounded-2xl border border-zinc-800 bg-zinc-950/70 p-4">
            <div className="text-sm text-zinc-400">Было</div>
            <div className="mt-2 text-lg font-semibold text-white">
              #{beforeSnapshot.scan_number} · {formatDateTime(beforeSnapshot.created_at)}
            </div>
            <div className="mt-2 text-sm text-zinc-400">
              Score: {Math.round(beforeSnapshot.compliance_score || 0)}%
            </div>
          </div>

          <div className="rounded-2xl border border-zinc-800 bg-zinc-950/70 p-4">
            <div className="text-sm text-zinc-400">Стало</div>
            <div className="mt-2 text-lg font-semibold text-white">
              #{afterSnapshot.scan_number} · {formatDateTime(afterSnapshot.created_at)}
            </div>
            <div className="mt-2 text-sm text-zinc-400">
              Score: {Math.round(afterSnapshot.compliance_score || 0)}%
            </div>
          </div>

          <div className="rounded-2xl border border-blue-500/20 bg-blue-500/10 p-4">
            <div className="text-sm text-zinc-400">Checks</div>
            <div className="mt-2 text-lg font-semibold text-blue-300">
              {beforeSnapshot.total_checks} → {afterSnapshot.total_checks}
            </div>
          </div>

          <div className="rounded-2xl border border-emerald-500/20 bg-emerald-500/10 p-4">
            <div className="text-sm text-zinc-400">Failed</div>
            <div className="mt-2 text-lg font-semibold text-emerald-300">
              {beforeSnapshot.failed} → {afterSnapshot.failed}
            </div>
            {beforeSnapshot.accepted_risks || afterSnapshot.accepted_risks ? (
              <div className="mt-2 text-xs text-zinc-400">
                риск принят: {beforeSnapshot.accepted_risks || 0} → {afterSnapshot.accepted_risks || 0}
              </div>
            ) : null}
          </div>
        </div>
      </AppCard>

      <AppCard title="Детальный diff" subtitle="Сравнение результатов по активам и правилам">
        <div className="overflow-x-auto">
          <table className="min-w-full text-sm">
            <thead className="border-b border-zinc-800 text-left text-zinc-400">
              <tr>
                <th className="px-4 py-3">Актив</th>
                <th className="px-4 py-3">Правило</th>
                <th className="px-4 py-3">Было</th>
                <th className="px-4 py-3">Стало</th>
                <th className="px-4 py-3">Expected</th>
                <th className="px-4 py-3">Изменение</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((item) => (
                <tr
                  key={item.key}
                  className="border-b border-zinc-800/60 text-zinc-200 transition hover:bg-zinc-800/40"
                >
                  <td className="px-4 py-3 font-medium text-white">
                    {item.asset?.hostname || "—"}
                  </td>
                  <td className="px-4 py-3">
                    <div className="font-medium text-white">{item.rule?.title || "—"}</div>
                    <div className="text-xs text-zinc-500">{item.rule?.rule_code || "—"}</div>
                  </td>
                  <td className="px-4 py-3">{item.beforeStatus || "—"}</td>
                  <td className="px-4 py-3">{item.afterStatus || "—"}</td>
                  <td className="px-4 py-3">{item.expectedValue || "—"}</td>
                  <td className={`px-4 py-3 font-medium ${getChangeClass(item.changeType)}`}>
                    {getChangeLabel(item.changeType)}
                    {item.afterAccepted && item.exceptionReason ? (
                      <div className="mt-1 max-w-xs text-xs font-normal text-zinc-400">{item.exceptionReason}</div>
                    ) : null}
                  </td>
                </tr>
              ))}

              {!rows.length && (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-zinc-500">
                    Нет различий или нет данных для сравнения
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </AppCard>
    </div>
  );
}