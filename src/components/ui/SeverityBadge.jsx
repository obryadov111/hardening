const TONE_MAP = {
  critical: "border-rose-500/30 bg-rose-500/15 text-rose-300",
  high: "border-amber-500/30 bg-amber-500/15 text-amber-300",
  medium: "border-blue-500/30 bg-blue-500/15 text-blue-300",
  low: "border-emerald-500/30 bg-emerald-500/15 text-emerald-300",
};

const DEFAULT_TONE = "border-zinc-700 bg-zinc-800 text-zinc-300";

/**
 * Единый бейдж для 4-уровневой шкалы critical/high/medium/low —
 * используется и для criticality актива, и для severity правила
 * (одна и та же шкала значений, один визуальный язык). label — подпись вместо значения
 * (например, «высокий»), цвет по-прежнему берётся из value.
 */
export default function SeverityBadge({ value, label }) {
  const key = (value || "").toLowerCase();

  return (
    <span
      className={`inline-flex rounded-full border px-2 py-1 text-xs font-medium ${TONE_MAP[key] || DEFAULT_TONE}`}
    >
      {label || value || "unknown"}
    </span>
  );
}
