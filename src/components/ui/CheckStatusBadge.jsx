const TONE_MAP = {
  pass: "border-emerald-500/30 bg-emerald-500/15 text-emerald-300",
  fail: "border-rose-500/30 bg-rose-500/15 text-rose-300",
  error: "border-amber-500/30 bg-amber-500/15 text-amber-300",
  skipped: "border-zinc-700 bg-zinc-800 text-zinc-300",
};

const DEFAULT_TONE = "border-zinc-700 bg-zinc-800 text-zinc-300";

const LABELS = {
  pass: "соблюдено",
  fail: "нарушено",
  error: "не проверено",
  skipped: "пропущено",
};

/** Бейдж результата проверки харденинга: pass/fail/error/skipped — по-русски, код статуса в title. */
export default function CheckStatusBadge({ value }) {
  const key = (value || "").toLowerCase();

  return (
    <span
      title={value || undefined}
      className={`inline-flex rounded-full border px-2 py-1 text-xs font-medium ${TONE_MAP[key] || DEFAULT_TONE}`}
    >
      {LABELS[key] || value || "неизвестно"}
    </span>
  );
}
