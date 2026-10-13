import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import AppCard from "../components/ui/AppCard";
import OrgGate from "../components/OrgGate";
import ErrorState from "../components/ui/ErrorState";
import { Skeleton } from "../components/ui/Skeleton";
import { useOrganization } from "../context/OrganizationContext";
import { getOfflinePacks, uploadOfflineScan } from "../api/offlineScans";
import { getCurrentUserRoleInOrganization } from "../api/users";

const INPUT = "w-full rounded-xl border border-zinc-800 bg-zinc-950 px-3 py-2 text-sm text-white outline-none placeholder:text-zinc-500";
const LABEL = "mb-1 block text-xs text-zinc-400";
const MATURITY = { draft: "черновик", baseline: "базовый", full: "полный", certified: "сертифицирован", inventory: "инвентаризация" };
const EMPTY_FORM = { hostname: "", ip_address: "", environment: "network", criticality: "medium", scan_label: "", exported_at: "" };

/**
 * Проверка сетевого устройства по выгрузке конфигурации — без агента и без доступа к устройству.
 * Те же паки и пробы, что у агента с --offline-dir; результат — обычный снимок с отметкой «по выгрузке».
 */
export default function OfflineScan() {
  const { selectedOrganization, selectedOrganizationId, loading: orgLoading, hasOrganizations, error: orgError } =
    useOrganization();

  const [packs, setPacks] = useState([]);
  const [limits, setLimits] = useState({ max_files: 10, max_file_bytes: 5_000_000 });
  const [canUpload, setCanUpload] = useState(false);
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState("");

  const [packId, setPackId] = useState("");
  const [declared, setDeclared] = useState(false);
  const [files, setFiles] = useState({});
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
          getOfflinePacks(selectedOrganizationId),
          getCurrentUserRoleInOrganization(selectedOrganizationId).catch(() => null),
        ]);
        setPacks(data.packs || []);
        setLimits({ max_files: data.max_files, max_file_bytes: data.max_file_bytes });
        setPackId((current) => current || data.packs?.[0]?.pack || "");
        // Загружать может администратор организации (сервер проверяет это сам, здесь — только вид).
        setCanUpload(role === "admin");
      } catch (error) {
        setLoadError(error.message);
      } finally {
        setLoading(false);
      }
    }
    if (!orgLoading) load();
  }, [selectedOrganizationId, orgLoading]);

  const pack = useMemo(() => packs.find((p) => p.pack === packId) || null, [packs, packId]);
  const detectCommands = pack ? pack.commands.filter((c) => c.detect) : [];
  const hasDetect = detectCommands.some((c) => files[c.command]);
  const chosen = pack ? pack.commands.filter((c) => files[c.command]) : [];
  const tooBig = chosen.find((c) => files[c.command].size > limits.max_file_bytes);
  const missingChecks = pack ? pack.commands.filter((c) => c.checks && !files[c.command]) : [];
  const canSubmit = canUpload && pack && form.hostname.trim() && chosen.length && !tooBig && (hasDetect || declared);

  function setField(key, value) {
    setForm((current) => ({ ...current, [key]: value }));
  }

  function choosePack(id) {
    setPackId(id);
    setFiles({});
    setDeclared(false);
    setResult(null);
    setSubmitError("");
  }

  async function submit(event) {
    event.preventDefault();
    if (!canSubmit) return;
    setSubmitting(true);
    setSubmitError("");
    setResult(null);
    try {
      const response = await uploadOfflineScan(selectedOrganizationId, {
        ...form,
        hostname: form.hostname.trim(),
        // <input type="datetime-local"> — местное время без пояса; серверу — в UTC.
        exported_at: form.exported_at ? new Date(form.exported_at).toISOString() : "",
        // Пак передаётся явно, только если оператор подтвердил это без выгрузки show version:
        // иначе сервер сам распознаёт платформу и откажет, если выгрузка не похожа на пак.
        pack: hasDetect ? "" : pack.pack,
        files: chosen.map((c) => ({ command: c.command, file: files[c.command] })),
      });
      setResult(response);
    } catch (error) {
      setSubmitError(error.message);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <OrgGate title="Проверка по выгрузке" orgLoading={orgLoading} orgError={orgError} hasOrganizations={hasOrganizations}>
      <div className="space-y-6">
        <div>
          <h1 className="text-2xl font-semibold text-white">Проверка по выгрузке конфигурации</h1>
          <p className="mt-1 max-w-3xl text-sm text-zinc-400">
            Для сетевого оборудования без SSH-доступа или без агента: загрузите сохранённый вывод команд
            (из бэкапа Oxidized/RANCID, по TFTP или от администратора). Проверки — те же, что у агента; снимок
            будет помечен «по выгрузке»: проверено состояние на момент выгрузки, а не живое устройство.
            Организация: <span className="text-white">{selectedOrganization?.name || "—"}</span>
          </p>
        </div>

        {loadError ? <ErrorState title="Не удалось загрузить список паков" description={loadError} /> : null}

        {!canUpload && !loading && !loadError ? (
          <div className="rounded-2xl border border-amber-500/20 bg-amber-500/10 px-4 py-3 text-sm text-amber-300">
            Загружать выгрузки может только администратор организации.
          </div>
        ) : null}

        {loading ? (
          <Skeleton className="h-64 w-full" />
        ) : packs.length === 0 && !loadError ? (
          <AppCard title="Нет паков">
            <p className="text-sm text-zinc-400">На сервере нет паков для сетевых устройств.</p>
          </AppCard>
        ) : (
          <form onSubmit={submit} className="space-y-6">
            <AppCard title="1. Оборудование" subtitle="Пак определяет, выгрузки каких команд нужны">
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
              <AppCard
                title="2. Файлы выгрузки"
                subtitle={`Один файл на команду, до ${Math.round(limits.max_file_bytes / 1_000_000)} МБ каждый`}
              >
                <div className="space-y-3">
                  {pack.commands.map((c) => (
                    <div key={c.command} className="grid items-center gap-2 md:grid-cols-[260px_1fr]">
                      <div>
                        <code className="text-sm text-white">{c.command}</code>
                        <div className="text-xs text-zinc-500">
                          {c.detect ? "распознавание платформы" : "проверки"} · обычно {c.file}
                        </div>
                      </div>
                      <input
                        type="file"
                        aria-label={`Файл выгрузки «${c.command}»`}
                        accept=".txt,.cfg,.conf,.log,text/plain"
                        onChange={(e) => {
                          const file = e.target.files?.[0];
                          setFiles((current) => {
                            const next = { ...current };
                            if (file) next[c.command] = file;
                            else delete next[c.command];
                            return next;
                          });
                        }}
                        className="text-sm text-zinc-300 file:mr-3 file:rounded-lg file:border-0 file:bg-zinc-800 file:px-3 file:py-1.5 file:text-zinc-200"
                      />
                    </div>
                  ))}
                </div>

                {tooBig ? (
                  <p className="mt-3 text-sm text-rose-300">Файл для «{tooBig.command}» больше допустимого размера.</p>
                ) : null}
                {missingChecks.length ? (
                  <p className="mt-3 text-sm text-zinc-400">
                    Без выгрузки {missingChecks.map((c) => `«${c.command}»`).join(", ")} проверки по ней будут «не проверено».
                  </p>
                ) : null}
                {!hasDetect && detectCommands.length ? (
                  <label className="mt-3 flex items-start gap-2 rounded-xl border border-amber-500/20 bg-amber-500/10 px-3 py-2 text-sm text-amber-200">
                    <input type="checkbox" checked={declared} onChange={(e) => setDeclared(e.target.checked)} className="mt-1" />
                    <span>
                      Выгрузки {detectCommands.map((c) => `«${c.command}»`).join(", ")} нет — подтверждаю, что это{" "}
                      <b>{pack.pack}</b>. В отчёте будет отмечено: пак задан оператором, платформа по выгрузке не подтверждена.
                    </span>
                  </label>
                ) : null}
              </AppCard>
            ) : null}

            <AppCard title="3. Устройство" subtitle="Актив создаётся или обновляется по имени в выбранном окружении">
              <div className="grid gap-4 md:grid-cols-3">
                <label>
                  <span className={LABEL}>Имя устройства *</span>
                  <input className={INPUT} value={form.hostname} onChange={(e) => setField("hostname", e.target.value)} placeholder="sw-core-01" maxLength={255} />
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
                <label>
                  <span className={LABEL}>Когда снята выгрузка</span>
                  <input type="datetime-local" className={INPUT} value={form.exported_at} onChange={(e) => setField("exported_at", e.target.value)} />
                </label>
                <label>
                  <span className={LABEL}>Метка скана</span>
                  <input className={INPUT} value={form.scan_label} onChange={(e) => setField("scan_label", e.target.value)} placeholder="бэкап от 01.10" maxLength={200} />
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
              disabled={!canSubmit || submitting}
              className="rounded-xl border border-blue-500/30 bg-blue-500/15 px-4 py-2 text-sm text-blue-200 hover:bg-blue-500/25 disabled:opacity-40"
            >
              {submitting ? "Проверяю…" : "Проверить выгрузку"}
            </button>
          </form>
        )}
      </div>
    </OrgGate>
  );
}
