import { PieChart, Pie, Cell, ResponsiveContainer } from "recharts";
import { getScoreTone } from "../utils/score";

/**
 * Пончик pass/fail/не проверено с крупным % соответствия по центру.
 * Процент считается только по выполненным проверкам (pass/fail); невыполненные
 * (error) показаны отдельным серым сегментом и не засчитываются как пройденные.
 */
export default function ComplianceChart({ passed = 0, failed = 0, notEvaluated = 0 }) {
  const evaluated = passed + failed;
  const total = evaluated + notEvaluated;
  const score = evaluated > 0 ? Math.round((passed / evaluated) * 100) : null;
  const tone = getScoreTone(score);

  const data =
    total > 0
      ? [
          { name: "Пройдено", value: passed, color: "#34d399" },
          { name: "Провалено", value: failed, color: "#fb7185" },
          { name: "Не проверено", value: notEvaluated, color: "#71717a" },
        ].filter((entry) => entry.value > 0)
      : [{ name: "Нет данных", value: 1, color: "#3f3f46" }];

  return (
    <div className="relative" style={{ width: "100%", height: 220 }}>
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data}
            dataKey="value"
            innerRadius="72%"
            outerRadius="100%"
            startAngle={90}
            endAngle={-270}
            stroke="none"
            isAnimationActive={false}
          >
            {data.map((entry) => (
              <Cell key={entry.name} fill={entry.color} />
            ))}
          </Pie>
        </PieChart>
      </ResponsiveContainer>

      <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
        <div className={`text-4xl font-bold ${tone.text}`}>{score != null ? `${score}%` : "—"}</div>
        <div className="mt-1 text-xs text-zinc-500">
          {evaluated > 0 ? `${passed} из ${evaluated} выполненных проверок` : total > 0 ? "ни одна проверка не выполнена" : "нет проверок"}
        </div>
      </div>
    </div>
  );
}
