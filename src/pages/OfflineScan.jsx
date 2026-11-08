import { useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import AppCard from "../components/ui/AppCard";
import OrgGate from "../components/OrgGate";
import ErrorState from "../components/ui/ErrorState";
import { Skeleton } from "../components/ui/Skeleton";
import { useOrganization } from "../context/OrganizationContext";
import { getOfflinePacks, previewOfflineScan, uploadOfflineScan } from "../api/offlineScans";
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
  const [bundleFile, setBundleFile] = useState(null);
  const [preview, setPreview] = useState(null);
  const [previewError, setPreviewError] = useState("");
  const [previewLoading, setPreviewLoading] = useState(false);
  const previewSeq = useRef(0);
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
  const perCommand = chosen.length > 0;
  const tooBig = perCommand
    ? chosen.find((c) => files[c.command].size > limits.max_file_bytes)
    : bundleFile && bundleFile.size > limits.max_file_bytes ? { command: "файл выгрузки" } : null;
  const found = new Set(preview?.found || []);
  const missingFromBundle = pack && preview && !perCommand
    ? pack.commands.filter((c) => c.checks && !found.has(c.command) && preview.format !== "json")
    : [];
  const missingChecks = perCommand ? pack.commands.filter((c) => c.checks && !files[c.command]) : missingFromBundle;
  const bundleReady = Boolean(
    bundleFile && !previewLoading && !previewError && preview
    && (preview.needs_declared ? declared : preview.pack || declared),
  );
  const canSubmit = canUpload && pack && form.hostname.trim() && !tooBig && (
    perCommand ? chosen.length && (hasDetect || declared) : bundleReady
  );

  async function inspect(file, packForPreview) {
    const seq = ++previewSeq.current;
    setPreviewLoading(true);
    setPreviewError("");
    setPreview(null);
    try {
      const data = await previewOfflineScan(selectedOrganizationId, file, packForPreview || "");
      if (seq !== previewSeq.current) return;
      setPreview(data);
      if (data.pack && !data.needs_declared) setPackId(data.pack);
    } catch (error) {
      if (seq !== previewSeq.current) return;
      setPreviewError(error.message);
    } finally {
      if (seq === previewSeq.current) setPreviewLoading(false);
    }
  }

  function setField(key, value) {
    setForm((current) => ({ ...current, [key]: value }));
  }

  function choosePack(id) {
    setPackId(id);
    setFiles({});
    setDeclared(false);
    setResult(null);
    setSubmitError("");
    if (bundleFile) inspect(bundleFile, id);
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
        pack: perCommand ? (hasDetect ? "" : pack.pack) : (preview?.needs_declared ? pack.pack : ""),
        files: perCommand ? chosen.map((c) => ({ command: c.command, file: files[c.command] })) : [],
        bundle: perCommand ? null : bundleFile,
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
            Для сетевого оборудования без SSH-доступа или без агента: загрузите один файл — журнал сессии,
            бэкап Oxidized/RANCID, конфигурацию или архив выгрузки. Сервер сам разрежет его по командам.
            Проверки те же, что у агента; снимок помечен «по выгрузке»: это состояние на момент выгрузки, а не живое устройство.
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
                title="2. Файл выгрузки"
                subtitle={pack.single_file_hint || `До ${Math.round(limits.max_file_bytes / 1_000_000)} МБ`}
              >
                <label className="block">
                  <span className={LABEL}>Файл выгрузки</span>
                  <input
                    type="file"
                    aria-label="Файл выгрузки"
                    accept=".txt,.cfg,.conf,.log,.zip,.tar,.gz,.tgz,.json,text/plain,application/zip,application/json,application/gzip"
                    onChange={(e) => {
                      const file = e.target.files?.[0] || null;
                      setBundleFile(file);
                      setDeclared(false);
                      setResult(null);
                      setSubmitError("");
                      if (file) inspect(file, "");
                      else {
                        previewSeq.current += 1;
                        setPreview(null);
                        setPreviewError("");
                      }
                    }}
                    className="text-sm text-zinc-300 file:mr-3 file:rounded-lg file:border-0 file:bg-zinc-800 file:px-3 file:py-1.5 file:text-zinc-200"
                  />
                </label>

                {previewLoading ? <p className="mt-3 text-sm text-zinc-400">Разбираю файл…</p> : null}
                {preview && !perCommand ? (
                  <div className="mt-3 space-y-2 rounded-xl border border-zinc-800 bg-zinc-950 px-3 py-3 text-sm">
                    <p className="text-zinc-300">
                      Формат: {preview.format_label}.{" "}
                      {preview.pack && !preview.needs_declared
                        ? <>Пак: <b className="text-white">{preview.pack}</b>.</>
                        : "Платформа по файлу не узнана — выберите пак и подтвердите его."}
                    </p>
                    {preview.found?.length ? (
                      <p className="text-emerald-200">В файле: {preview.found.map((c) => `«${c}»`).join(", ")}</p>
                    ) : null}
                    {missingChecks.length ? (
                      <p className="text-zinc-400">
                        Нет {missingChecks.map((c) => `«${c.command}»`).join(", ")} — проверки по ним будут «не проверено».
                      </p>
                    ) : null}
                    {preview.notes?.map((note) => <p key={note} className="text-zinc-400">{note}</p>)}
                  </div>
                ) : null}
                {previewError ? <p className="mt-3 text-sm text-rose-300">{previewError}</p> : null}

                <details className="mt-4 rounded-xl border border-zinc-800 px-3 py-2">
                  <summary className="cursor-pointer text-sm text-zinc-300">Файл на каждую команду</summary>
                  <div className="mt-3 space-y-3">
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
                            setResult(null);
                            setSubmitError("");
                          }}
                          className="text-sm text-zinc-300 file:mr-3 file:rounded-lg file:border-0 file:bg-zinc-800 file:px-3 file:py-1.5 file:text-zinc-200"
                        />
                      </div>
                    ))}
                  </div>
                  {perCommand ? (
                    <p className="mt-3 text-xs text-zinc-500">Будут загружены отдельные файлы команд, а не общий файл выше.</p>
                  ) : null}
                </details>

                {tooBig ? (
                  <p className="mt-3 text-sm text-rose-300">Файл для «{tooBig.command}» больше допустимого размера.</p>
                ) : null}
                {perCommand && missingChecks.length ? (
                  <p className="mt-3 text-sm text-zinc-400">
                    Без выгрузки {missingChecks.map((c) => `«${c.command}»`).join(", ")} проверки по ней будут «не проверено».
                  </p>
                ) : null}
                {(perCommand ? !hasDetect && detectCommands.length : preview?.needs_declared) ? (
                  <label className="mt-3 flex items-start gap-2 rounded-xl border border-amber-500/20 bg-amber-500/10 px-3 py-2 text-sm text-amber-200">
                    <input type="checkbox" checked={declared} onChange={(e) => setDeclared(e.target.checked)} className="mt-1" />
                    <span>
                      Подтверждаю, что это <b>{pack.pack}</b>
                      {perCommand ? " — выгрузки команды распознавания нет" : " — по файлу платформа не узнана"}.
                      В отчёте будет отмечено: пак задан оператором, платформа по выгрузке не подтверждена.
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
