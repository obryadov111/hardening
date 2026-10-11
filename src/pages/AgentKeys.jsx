import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import AppCard from "../components/ui/AppCard";
import OrgGate from "../components/OrgGate";
import ErrorState from "../components/ui/ErrorState";
import { Skeleton } from "../components/ui/Skeleton";
import { useOrganization } from "../context/OrganizationContext";
import { createAgentKey, getAgentKeys, revokeAgentKey, uploadAgentReport } from "../api/agentKeys";
import { getCurrentUserRoleInOrganization } from "../api/users";
import { formatDate, formatDateTime } from "../utils/datetime";

const INPUT = "w-full rounded-xl border border-zinc-800 bg-zinc-950 px-3 py-2 text-sm text-white outline-none placeholder:text-zinc-500";
const LABEL = "mb-1 block text-xs text-zinc-400";
const BUTTON = "rounded-xl border border-blue-500/30 bg-blue-500/15 px-4 py-2 text-sm text-blue-200 hover:bg-blue-500/25 disabled:opacity-40";
const STATE = {
  active: ["действует", "border-emerald-500/20 bg-emerald-500/10 text-emerald-300"],
  expired: ["истёк", "border-amber-500/20 bg-amber-500/10 text-amber-300"],
  revoked: ["отозван", "border-zinc-700 bg-zinc-800 text-zinc-400"],
};
const EXPIRY = [
  { value: 90, label: "90 дней" },
  { value: 365, label: "1 год" },
  { value: 730, label: "2 года" },
  { value: null, label: "бессрочно" },
];

function CopyBlock({ text }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="relative">
      <pre className="overflow-x-auto whitespace-pre-wrap break-all rounded-xl border border-zinc-800 bg-zinc-950 p-3 pr-24 text-xs text-zinc-200">
        {text}
      </pre>
      <button
        type="button"
        onClick={() => navigator.clipboard?.writeText(text).then(() => setCopied(true))}
        className="absolute right-2 top-2 rounded-lg border border-zinc-700 bg-zinc-900 px-2 py-1 text-xs text-zinc-300 hover:text-white"
      >
        {copied ? "скопировано" : "копировать"}
      </button>
    </div>
  );
}

/** Настройки агента для объекта: файл окружения службы systemd (/etc/hardening-agent/<имя>.env). */
function agentConfig(key, publicKey) {
  return [
    `HARDENING_API_URL=${window.location.origin}`,
    `HARDENING_AGENT_API_KEY=${key}`,
    publicKey ? `HARDENING_PACK_PUBLIC_KEY=${publicKey}` : "# HARDENING_PACK_PUBLIC_KEY — ключ подписи Ed25519 на сервере не настроен",
    "HARDENING_ENVIRONMENT=prod",
    "HARDENING_CRITICALITY=medium",
    "HARDENING_SCAN_LABEL=плановый",
    "# при TLS-инспекции или своём корневом сертификате: HARDENING_CA_FILE=/etc/hardening-agent/ca.pem",
    "# закрепление ключа сервера (агент: --show-server-pin): HARDENING_PIN_SHA256=sha256//...",
    "# прокси: HARDENING_PROXY=http://proxy.corp:3128",
    "HARDENING_EXTRA_ARGS=",
  ].join("\n");
}

/**
 * Агенты организации: ключи на объекты заказчика (со сроком действия, отзывом и последним
 * использованием), открытый ключ подписи паков и загрузка отчёта агента, перенесённого файлом.
 */
export default function AgentKeys() {
  const { selectedOrganization, selectedOrganizationId, loading: orgLoading, hasOrganizations, error: orgError } =
    useOrganization();

  const [data, setData] = useState({ keys: [], pack_public_key: null });
  const [isAdmin, setIsAdmin] = useState(false);
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState("");

  const [name, setName] = useState("");
  const [expiry, setExpiry] = useState(365);
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState("");
  const [created, setCreated] = useState(null);

  const [reportFile, setReportFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState("");
  const [uploadResult, setUploadResult] = useState(null);

  const load = useCallback(async () => {
    if (!selectedOrganizationId) return;
    try {
      setLoading(true);
      setLoadError("");
      const role = await getCurrentUserRoleInOrganization(selectedOrganizationId).catch(() => null);
      setIsAdmin(role === "admin");
      if (role !== "admin") return;
      setData(await getAgentKeys(selectedOrganizationId));
    } catch (error) {
      setLoadError(error.message);
    } finally {
      setLoading(false);
    }
  }, [selectedOrganizationId]);

  useEffect(() => {
    if (!orgLoading) load();
  }, [orgLoading, load]);

  async function create(event) {
    event.preventDefault();
    if (!name.trim()) return;
    setCreating(true);
    setCreateError("");
    try {
      const key = await createAgentKey(selectedOrganizationId, { name: name.trim(), expiresInDays: expiry });
      setCreated(key);
      setName("");
      await load();
    } catch (error) {
      setCreateError(error.message);
    } finally {
      setCreating(false);
    }
  }

  async function revoke(key) {
    if (!window.confirm(`Отозвать ключ «${key.name}»? Агенты с этим ключом перестанут отправлять данные.`)) return;
    try {
      await revokeAgentKey(selectedOrganizationId, key.id);
      await load();
    } catch (error) {
      setLoadError(error.message);
    }
  }

  async function upload(event) {
    event.preventDefault();
    if (!reportFile) return;
    setUploading(true);
    setUploadError("");
    setUploadResult(null);
    try {
      setUploadResult(await uploadAgentReport(selectedOrganizationId, reportFile));
    } catch (error) {
      setUploadError(error.message);
    } finally {
      setUploading(false);
    }
  }

  return (
    <OrgGate title="Агенты" orgLoading={orgLoading} orgError={orgError} hasOrganizations={hasOrganizations}>
      <div className="space-y-6">
        <div>
          <h1 className="text-2xl font-semibold text-white">Агенты</h1>
          <p className="mt-1 max-w-3xl text-sm text-zinc-400">
            Агент сам обращается к серверу по HTTPS — от объекта заказчика нужен только исходящий доступ к{" "}
            <code className="text-zinc-200">{window.location.host}:443</code>. Выдавайте отдельный ключ на каждый объект
            (площадку, сегмент): его можно отозвать, не затрагивая остальные. Организация:{" "}
            <span className="text-white">{selectedOrganization?.name || "—"}</span>
          </p>
        </div>

        {loadError ? <ErrorState title="Не удалось загрузить ключи агентов" description={loadError} /> : null}

        {!isAdmin && !loading && !loadError ? (
          <div className="rounded-2xl border border-amber-500/20 bg-amber-500/10 px-4 py-3 text-sm text-amber-300">
            Управлять агентами может только администратор организации.
          </div>
        ) : null}

        {loading ? <Skeleton className="h-64 w-full" /> : null}

        {isAdmin && !loading ? (
          <>
            <AppCard title="Новый ключ агента" subtitle="Ключ показывается один раз — сервер хранит только его хэш">
              <form onSubmit={create} className="grid gap-4 md:grid-cols-[1fr_200px_auto] md:items-end">
                <label>
                  <span className={LABEL}>Объект *</span>
                  <input className={INPUT} value={name} onChange={(e) => setName(e.target.value)} placeholder="Казань, ЦОД, сегмент АСУ" maxLength={100} />
                </label>
                <label>
                  <span className={LABEL}>Срок действия</span>
                  <select className={INPUT} value={expiry ?? ""} onChange={(e) => setExpiry(e.target.value ? Number(e.target.value) : null)}>
                    {EXPIRY.map((o) => (
                      <option key={o.label} value={o.value ?? ""}>{o.label}</option>
                    ))}
                  </select>
                </label>
                <button type="submit" disabled={!name.trim() || creating} className={BUTTON}>
                  {creating ? "Создаю…" : "Создать ключ"}
                </button>
              </form>
              {createError ? <p className="mt-3 text-sm text-rose-300">{createError}</p> : null}
              {created ? (
                <div className="mt-4 space-y-3 rounded-2xl border border-emerald-500/20 bg-emerald-500/5 p-4">
                  <p className="text-sm text-emerald-200">
                    Ключ «{created.name}» создан{created.expires_at ? `, действует до ${formatDate(created.expires_at)}` : ", бессрочный"}.
                    Сохраните его сейчас — повторно он не показывается.
                  </p>
                  <CopyBlock text={created.key} />
                  <p className="text-xs text-zinc-400">
                    Настройки агента на объекте (Linux — файл <code>/etc/hardening-agent/&lt;имя&gt;.env</code> для службы{" "}
                    <code>hardening-agent@&lt;имя&gt;</code>; Windows — те же переменные для задачи планировщика):
                  </p>
                  <CopyBlock text={agentConfig(created.key, data.pack_public_key)} />
                  <button type="button" onClick={() => setCreated(null)} className="text-xs text-zinc-400 underline hover:text-white">
                    Скрыть ключ
                  </button>
                </div>
              ) : null}
            </AppCard>

            <AppCard title="Ключи агентов" subtitle="Последнее использование — время и адрес, с которого агент обращался к серверу">
              {data.keys.length === 0 ? (
                <p className="text-sm text-zinc-400">Ключей пока нет.</p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-sm">
                    <thead className="text-xs text-zinc-500">
                      <tr>
                        <th className="py-2 pr-4 font-normal">Объект</th>
                        <th className="py-2 pr-4 font-normal">Состояние</th>
                        <th className="py-2 pr-4 font-normal">Создан</th>
                        <th className="py-2 pr-4 font-normal">Действует до</th>
                        <th className="py-2 pr-4 font-normal">Последнее использование</th>
                        <th className="py-2 font-normal" />
                      </tr>
                    </thead>
                    <tbody>
                      {data.keys.map((key) => {
                        const [label, cls] = STATE[key.state] || [key.state, ""];
                        return (
                          <tr key={key.id} className="border-t border-zinc-800 text-zinc-300">
                            <td className="py-2 pr-4 text-white">{key.name}</td>
                            <td className="py-2 pr-4">
                              <span className={`rounded-lg border px-2 py-0.5 text-xs ${cls}`}>{label}</span>
                            </td>
                            <td className="py-2 pr-4">{formatDate(key.created_at)}</td>
                            <td className="py-2 pr-4">{key.expires_at ? formatDate(key.expires_at) : "бессрочно"}</td>
                            <td className="py-2 pr-4">
                              {key.last_used_at ? `${formatDateTime(key.last_used_at)} · ${key.last_used_ip || "адрес неизвестен"}` : "не использовался"}
                            </td>
                            <td className="py-2 text-right">
                              {key.state === "active" ? (
                                <button type="button" onClick={() => revoke(key)} className="text-xs text-rose-300 hover:text-rose-200">
                                  Отозвать
                                </button>
                              ) : null}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </AppCard>

            <AppCard
              title="Открытый ключ подписи паков"
              subtitle="Агент принимает с сервера только паки с этой подписью (Ed25519); подписать им нельзя — передавать можно открыто"
            >
              {data.pack_public_key ? (
                <CopyBlock text={data.pack_public_key} />
              ) : (
                <p className="text-sm text-amber-300">
                  На сервере не настроен ключ Ed25519 (PACK_SIGNING_ED25519_KEY) — агенты проверяют паки старым общим ключом.
                </p>
              )}
            </AppCard>

            <AppCard
              title="Отчёт агента из файла"
              subtitle="Для изолированных сегментов без связи с сервером: агент с --out сохраняет прогон в файл, подписанный ключом агента"
            >
              <form onSubmit={upload} className="space-y-3">
                <input
                  type="file"
                  accept=".json,application/json"
                  onChange={(e) => {
                    setReportFile(e.target.files?.[0] || null);
                    setUploadResult(null);
                    setUploadError("");
                  }}
                  className="text-sm text-zinc-300 file:mr-3 file:rounded-lg file:border-0 file:bg-zinc-800 file:px-3 file:py-1.5 file:text-zinc-200"
                />
                <p className="text-xs text-zinc-500">
                  Сервер проверяет подпись ключом агента этой организации: изменённый при переносе файл не будет принят.
                </p>
                {uploadError ? <p className="text-sm text-rose-300">{uploadError}</p> : null}
                {uploadResult ? (
                  <div className="rounded-2xl border border-emerald-500/20 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-200">
                    Снимок создан: проверок {uploadResult.checks.total}, соблюдено {uploadResult.checks.passed}, нарушений{" "}
                    {uploadResult.checks.failed}, не проверено {uploadResult.checks.errors}
                    {uploadResult.compliance_score != null ? `, соответствие ${Math.round(uploadResult.compliance_score)}%` : ""}.{" "}
                    <Link to="/scans" className="underline hover:text-white">Открыть сканирования</Link>
                  </div>
                ) : null}
                <button type="submit" disabled={!reportFile || uploading} className={BUTTON}>
                  {uploading ? "Проверяю…" : "Загрузить отчёт"}
                </button>
              </form>
            </AppCard>
          </>
        ) : null}
      </div>
    </OrgGate>
  );
}
