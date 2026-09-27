import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import AppCard from "../components/ui/AppCard";
import StatCard from "../components/ui/StatCard";
import { compareSnapshots } from "../api/snapshots";

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
    default:
      return "text-zinc-400";
  }
}

export default function ScanCompare() {
  const [searchParams] = useSearchParams();
  const beforeId = searchParams.get("before");
  const afterId = searchParams.get("after");

  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadData() {
      if (!beforeId || !afterId) {
        setLoading(false);
        return;
      }

      try {
        setLoading(true);
        const result = await compareSnapshots(beforeId, afterId);
        setData(result);
      } catch (error) {
        console.error("Ошибка сравнения сканов:", error.message);
        setData(null);
      } finally {
        setLoading(false);
      }
    }

    loadData();
  }, [beforeId, afterId]);

  const rows = useMemo(() => data?.diffs || [], [data]);

  if (loading) {
    return <div className="text-zinc-400">Загрузка сравнения...</div>;
  }

  if (!beforeId || !afterId) {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-semibold text-white">Сравнение сканов</h1>
        <AppCard title="Недостаточно параметров" subtitle="Нужно передать before и after">
          <div className="text-zinc-400">
            Открой страницу в формате:
            <div className="mt-2 rounded-xl border border-zinc-800 bg-zinc-950/70 p-3 font-mono text-sm text-white">
              /scan-compare?before=SNAPSHOT_ID_1&after=SNAPSHOT_ID_2
            </div>
          </div>
        </AppCard>
      </div>
    );
  }

  if (!data) {
    return <div className="text-zinc-500">Не удалось загрузить данные сравнения</div>;
  }

  const { beforeSnapshot, afterSnapshot, summary, commonAssets, onlyBeforeAssets, onlyAfterAssets } = data;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-white">Сравнение сканов</h1>
        <p className="mt-1 text-sm text-zinc-400">
          Snapshot #{beforeSnapshot?.scan_number} → Snapshot #{afterSnapshot?.scan_number}
        </p>
      </div>

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

      <div className="grid gap-4 md:grid-cols-5">
        <StatCard label="Исправлено" value={summary.fixed} hint="fail → pass" tone="success" />
        <StatCard label="Ухудшилось" value={summary.regressed} hint="pass → fail" tone="danger" />
        <StatCard label="Не исправлено" value={summary.stillFailed} hint="fail → fail" tone="warning" />
        <StatCard label="Новые проблемы" value={summary.newIssues} hint="Проверка появилась и провалена" tone="info" />
        <StatCard label="Удалено" value={summary.removed} hint="Проверки нет в новом снимке (например, изменилась версия пака)" tone="default" />
      </div>

      <AppCard title="Итоги сравнения" subtitle="Сравнение метрик двух snapshot">
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <div className="rounded-2xl border border-zinc-800 bg-zinc-950/70 p-4">
            <div className="text-sm text-zinc-400">Было</div>
            <div className="mt-2 text-lg font-semibold text-white">
              #{beforeSnapshot.scan_number} · {beforeSnapshot.created_at?.slice(0, 10)}
            </div>
            <div className="mt-2 text-sm text-zinc-400">
              Score: {Math.round(beforeSnapshot.compliance_score || 0)}%
            </div>
          </div>

          <div className="rounded-2xl border border-zinc-800 bg-zinc-950/70 p-4">
            <div className="text-sm text-zinc-400">Стало</div>
            <div className="mt-2 text-lg font-semibold text-white">
              #{afterSnapshot.scan_number} · {afterSnapshot.created_at?.slice(0, 10)}
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