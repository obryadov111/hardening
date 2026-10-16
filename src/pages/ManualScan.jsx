import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import AppCard from "../components/ui/AppCard";
import OrgGate from "../components/OrgGate";
import ErrorState from "../components/ui/ErrorState";
import SeverityBadge from "../components/ui/SeverityBadge";
import { Skeleton } from "../components/ui/Skeleton";
import { useOrganization } from "../context/OrganizationContext";
import { getManualPacks, submitManualScan } from "../api/manualScans";
import { getCurrentUserRoleInOrganization } from "../api/users";

const INPUT = "w-full rounded-xl border border-zinc-800 bg-zinc-950 px-3 py-2 text-sm text-white outline-none placeholder:text-zinc-500";
const LABEL = "mb-1 block text-xs text-zinc-400";
const MATURITY = { draft: "черновик", baseline: "базовый", full: "полный", certified: "сертифицирован", inventory: "инвентаризация" };
const EMPTY_FORM = { hostname: "", ip_address: "", environment: "network", criticality: "medium", scan_label: "", firmware_version: "" };

function YesNo({ id, value, onChange }) {
  const options = [["yes", "Да"], ["no", "Нет"], ["", "Не проверено"]];
  return (
    <div role="radiogroup" aria-label={`Ответ: ${id}`} className="flex gap-2">
      {options.map(([v, label]) => (
        <button
          key={label}
          type="button"
          role="radio"
          aria-checked={value === v}
          onClick={() => onChange(v)}
          className={`rounded-lg border px-3 py-1.5 text-sm ${
            value === v ? "border-blue-500/40 bg-blue-500/15 text-blue-200" : "border-zinc-800 bg-zinc-950 text-zinc-300 hover:border-zinc-600"
          }`}
        >
          {label}
        </button>
      ))}
    </div>
  );
}

/**
 * Проверка по опросу — для оборудования, конфигурацию которого не прочитать ни агентом, ни выгрузкой
 * (Континент 4: настройки только в графическом Менеджере конфигурации). Аудитор отвечает на вопросы пака
 * по экранам системы управления; ответы оцениваются как пробы агента, снимок помечается «по опросу».
 */
export default function ManualScan() {
  const { selectedOrganization, selectedOrganizationId, loading: orgLoading, hasOrganizations, error: orgError } =
    useOrganization();

  const [packs, setPacks] = useState([]);
  const [canSubmit, setCanSubmit] = useState(false);
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState("");

  const [packId, setPackId] = useState("");
  const [answers, setAnswers] = useState({});
  const [form, setForm] = useState(EMPTY_FORM);
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState("");
  const [result, setResult] = useState(null);

  useEffect(() => {
    async function load() {
      if (!selectedOrganizationId) return;
      try {
        setLoading(true);
        setLoadError("");
        const [data, role] = await Promise.all([
          getManualPacks(selectedOrganizationId),
          getCurrentUserRoleInOrganization(selectedOrganizationId).catch(() => null),
        ]);
        setPacks(data.packs || []);
        setPackId((current) => current || data.packs?.[0]?.pack || "");
        // Отвечать может администратор организации (сервер проверяет это сам, здесь — только вид).
        setCanSubmit(role === "admin");
      } catch (error) {
        setLoadError(error.message);
      } finally {
        setLoading(false);
      }
    }
    if (!orgLoading) load();
  }, [selectedOrganizationId, orgLoading]);

  const pack = useMemo(() => packs.find((p) => p.pack === packId) || null, [packs, packId]);
  const answered = pack ? pack.questions.filter((q) => (answers[q.id]?.value ?? "") !== "").length : 0;
  const ready = canSubmit && pack && form.hostname.trim() && answered > 0;

  function setField(key, value) {
    setForm((current) => ({ ...current, [key]: value }));
  }

  function setAnswer(id, key, value) {
    setAnswers((current) => ({ ...current, [id]: { ...current[id], [key]: value } }));
  }

  function choosePack(id) {
    setPackId(id);
    setAnswers({});
    setResult(null);
    setSubmitError("");
  }

  async function submit(event) {
    event.preventDefault();
    if (!ready) return;
    setSubmitting(true);
    setSubmitError("");
    setResult(null);
    try {
      const payload = Object.fromEntries(
        pack.questions
          .filter((q) => (answers[q.id]?.value ?? "") !== "")
          .map((q) => [q.id, { value: answers[q.id].value, comment: answers[q.id].comment || null }]),
      );
      const response = await submitManualScan(selectedOrganizationId, {
        pack: pack.pack,
        hostname: form.hostname.trim(),
        ip_address: form.ip_address.trim() || null,
        environment: form.environment.trim() || "network",
        criticality: form.criticality,
        scan_label: form.scan_label.trim() || null,
        firmware_version: form.firmware_version.trim() || null,
        answers: payload,
      });
      setResult(response);
    } catch (error) {
      setSubmitError(error.message);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <OrgGate title="Проверка по опросу" orgLoading={orgLoading} orgError={orgError} hasOrganizations={hasOrganizations}>
      <div className="space-y-6">
        <div>
          <h1 className="text-2xl font-semibold text-white">Проверка по опросу</h1>
          <p className="mt-1 max-w-3xl text-sm text-zinc-400">
            Для оборудования, конфигурацию которого не прочитать ни агентом, ни выгрузкой: например, Континент 4 —
            его настройки меняются только в графическом Менеджере конфигурации. Ответьте на вопросы по экранам системы
            управления (у каждого вопроса указано, где смотреть). Вопрос без ответа будет «не проверено», а не соблюдением;
            снимок помечается «по опросу». Организация: <span className="text-white">{selectedOrganization?.name || "—"}</span>
          </p>
        </div>

        {loadError ? <ErrorState title="Не удалось загрузить список паков" description={loadError} /> : null}

        {!canSubmit && !loading && !loadError ? (
          <div className="rounded-2xl border border-amber-500/20 bg-amber-500/10 px-4 py-3 text-sm text-amber-300">
            Сохранять ответы может только администратор организации.
          </div>
        ) : null}

        {loading ? (
          <Skeleton className="h-64 w-full" />
        ) : packs.length === 0 && !loadError ? (
          <AppCard title="Нет паков">
            <p className="text-sm text-zinc-400">На сервере нет паков для проверки по опросу.</p>
          </AppCard>
        ) : (
          <form onSubmit={submit} className="space-y-6">
            <AppCard title="1. Оборудование" subtitle="Пак определяет вопросы">
              <div className="flex flex-wrap gap-2">
                {packs.map((p) => (
                  <button
                    key={p.pack}
                    type="button"
                    aria-pressed={p.pack === packId}
                    onClick={() => choosePack(p.pack)}
                    className={`rounded-xl border px-3 py-2 text-sm ${
                      p.pack === packId
                        ? "border-blue-500/40 bg-blue-500/15 text-blue-200"
                        : "border-zinc-800 bg-zinc-950 text-zinc-300 hover:border-zinc-600"
                    }`}
                  >
                    {p.pack} <span className="text-xs text-zinc-500">{p.version} · {MATURITY[p.maturity] || p.maturity}</span>
                  </button>
                ))}
              </div>
            </AppCard>

            {pack ? (
              <AppCard title="2. Вопросы" subtitle={`Отвечено ${answered} из ${pack.questions.length}`}>
                <ol className="space-y-5">
                  {pack.questions.map((q, index) => {
                    const value = answers[q.id]?.value ?? "";
                    return (
                      <li key={q.id} className="space-y-2 border-b border-zinc-800/60 pb-4 last:border-0">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="text-sm font-medium text-white">{index + 1}. {q.title}</span>
                          <SeverityBadge value={q.severity} />
                        </div>
                        <p className="text-sm text-zinc-300">{q.question}</p>
                        {q.hint ? <p className="text-xs text-zinc-500">Где смотреть: {q.hint}</p> : null}
                        <div className="grid gap-2 md:grid-cols-[minmax(0,320px)_1fr]">
                          {q.answer === "yesno" ? (
                            <YesNo id={q.title} value={value} onChange={(v) => setAnswer(q.id, "value", v)} />
                          ) : q.answer === "choice" ? (
                            <select
                              aria-label={`Ответ: ${q.title}`}
                              className={INPUT}
                              value={value}
                              onChange={(e) => setAnswer(q.id, "value", e.target.value)}
                            >
                              <option value="">— не проверено —</option>
                              {q.choices.map((c) => <option key={c} value={c}>{c}</option>)}
                            </select>
                          ) : (
                            <div className="flex items-center gap-2">
                              <input
                                aria-label={`Ответ: ${q.title}`}
                                className={INPUT}
                                inputMode={q.answer === "number" ? "decimal" : undefined}
                                value={value}
                                onChange={(e) => setAnswer(q.id, "value", e.target.value)}
                                placeholder={q.answer === "number" ? "число" : ""}
                                maxLength={100}
                              />
                              {q.unit ? <span className="text-xs text-zinc-500">{q.unit}</span> : null}
                            </div>
                          )}
                          <input
                            aria-label={`Подтверждение: ${q.title}`}
                            className={INPUT}
                            value={answers[q.id]?.comment || ""}
                            onChange={(e) => setAnswer(q.id, "comment", e.target.value)}
                            placeholder="Подтверждение: скриншот, раздел, дата (необязательно)"
                            maxLength={1000}
                          />
                        </div>
                      </li>
                    );
                  })}
                </ol>
              </AppCard>
            ) : null}

            <AppCard title="3. Устройство" subtitle="Актив создаётся или обновляется по имени в выбранном окружении">
              <div className="grid gap-4 md:grid-cols-3">
                <label>
                  <span className={LABEL}>Имя устройства *</span>
                  <input className={INPUT} value={form.hostname} onChange={(e) => setField("hostname", e.target.value)} placeholder="ub-msk-01" maxLength={255} />
                </label>
                <label>
                  <span className={LABEL}>IP-адрес</span>
                  <input className={INPUT} value={form.ip_address} onChange={(e) => setField("ip_address", e.target.value)} placeholder="10.0.0.1" maxLength={64} />
                </label>
                <label>
                  <span className={LABEL}>Окружение</span>
                  <input className={INPUT} value={form.environment} onChange={(e) => setField("environment", e.target.value)} maxLength={100} />
                </label>
                <label>
                  <span className={LABEL}>Критичность</span>
                  <select className={INPUT} value={form.criticality} onChange={(e) => setField("criticality", e.target.value)}>
                    <option value="low">низкая</option>
                    <option value="medium">средняя</option>
                    <option value="high">высокая</option>
                    <option value="critical">критическая</option>
                  </select>
                </label>
                {pack?.firmware ? (
                  <label>
                    <span className={LABEL}>{pack.firmware.question} — для сверки с БДУ ФСТЭК</span>
                    <input
                      className={INPUT}
                      value={form.firmware_version}
                      onChange={(e) => setField("firmware_version", e.target.value)}
                      placeholder="4.2.1"
                      maxLength={100}
                      title={pack.firmware.hint || ""}
                    />
                  </label>
                ) : null}
                <label>
                  <span className={LABEL}>Метка скана</span>
                  <input className={INPUT} value={form.scan_label} onChange={(e) => setField("scan_label", e.target.value)} placeholder="опрос от 16.10" maxLength={200} />
                </label>
              </div>
            </AppCard>

            {submitError ? (
              <div className="rounded-2xl border border-rose-500/20 bg-rose-500/10 px-4 py-3 text-sm text-rose-300">{submitError}</div>
            ) : null}

            {result ? (
              <div className="rounded-2xl border border-emerald-500/20 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-200">
                Снимок создан: проверок {result.checks.total}, соблюдено {result.checks.passed}, нарушений {result.checks.failed},
                не проверено {result.checks.errors}
                {result.compliance_score != null ? `, соответствие ${Math.round(result.compliance_score)}%` : ""}.{" "}
                <Link to="/scans" className="underline hover:text-white">Открыть сканирования</Link>
              </div>
            ) : null}

            <button
              type="submit"
              disabled={!ready || submitting}
              className="rounded-xl border border-blue-500/30 bg-blue-500/15 px-4 py-2 text-sm text-blue-200 hover:bg-blue-500/25 disabled:opacity-40"
            >
              {submitting ? "Сохраняю…" : "Сохранить ответы"}
            </button>
          </form>
        )}
      </div>
    </OrgGate>
  );
}
