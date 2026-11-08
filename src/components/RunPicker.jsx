import { useEffect, useState } from "react";
import { getScanRuns } from "../api/scanRuns";

const INPUT = "w-full rounded-xl border border-zinc-800 bg-zinc-950 px-3 py-2 text-sm text-white outline-none";
const LABEL = "mb-1 block text-xs text-zinc-400";

/** Выбор открытого прогона для выгрузки и опроса. Пустое значение — автоокно расписания. */
export default function RunPicker({ organizationId, value, onChange, disabled = false }) {
  const [runs, setRuns] = useState([]);

  useEffect(() => {
    if (!organizationId) return undefined;
    let cancelled = false;
    getScanRuns(organizationId, { status: "open", limit: 50 })
      .then((data) => { if (!cancelled) setRuns(data.items || []); })
      .catch(() => { if (!cancelled) setRuns([]); });
    return () => { cancelled = true; };
  }, [organizationId]);

  return (
    <label>
      <span className={LABEL}>Прогон</span>
      <select
        aria-label="Прогон"
        className={INPUT}
        value={value}
        disabled={disabled}
        onChange={(event) => onChange(event.target.value)}
      >
        <option value="">Автоматически, по расписанию агентов</option>
        {runs.map((run) => (
          <option key={run.id} value={run.id}>
            №{run.run_number}{run.label ? ` «${run.label}»` : ""} · открыт · хостов {run.hosts}
          </option>
        ))}
      </select>
    </label>
  );
}
