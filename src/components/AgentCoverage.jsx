import { useCallback, useEffect, useMemo, useState } from "react";
import CopyButton from "./ui/CopyButton";
import { deleteExpectedHosts, getCoverage, uploadExpectedHosts } from "../api/agentKeys";
import { formatDateTime } from "../utils/datetime";

const INPUT = "w-full rounded-xl border border-zinc-800 bg-zinc-950 px-3 py-2 text-sm text-white outline-none placeholder:text-zinc-500";
const BUTTON = "rounded-xl border border-blue-500/30 bg-blue-500/15 px-4 py-2 text-sm text-blue-200 hover:bg-blue-500/25 disabled:opacity-40";
const AD_EXPORT = [
  "Get-ADComputer -Filter * -Properties OperatingSystem,LastLogonDate |",
  "  Select-Object Name,DNSHostName,OperatingSystem,LastLogonDate,Enabled |",
  "  Export-Csv computers.csv -NoTypeInformation -Encoding UTF8",
].join("\n");
const PERIODS = [1, 7, 30];

const STATUS = {
  reporting: { label: "отчитывается", tile: "Отчитываются", cls: "border-emerald-500/30 bg-emerald-500/10 text-emerald-300" },
  stale: { label: "давно молчит", tile: "Давно молчат", cls: "border-amber-500/30 bg-amber-500/10 text-amber-300" },
  not_installed: { label: "агента нет", tile: "Агент не установлен", cls: "border-rose-500/30 bg-rose-500/10 text-rose-300" },
  revoked: { label: "отозван", tile: "Отозваны", cls: "border-zinc-600 bg-zinc-800 text-zinc-300" },
  unexpected: { label: "нет в списке", tile: "Нет в списке", cls: "border-sky-500/30 bg-sky-500/10 text-sky-300" },
};

function toCsv(rows) {
  const quote = (v) => `"${String(v ?? "").replaceAll('"', '""')}"`;
  const lines = [["Хост", "ОС", "Состояние", "Последний отчёт", "Последний вход (AD)"].map(quote).join(";")];
  for (const r of rows) {
    lines.push([r.hostname, r.os, STATUS[r.status]?.label, r.last_report ? formatDateTime(r.last_report) : "", r.last_logon].map(quote).join(";"));
  }
  return "﻿" + lines.join("\r\n"); // BOM — Excel открывает кириллицу правильно
}

function downloadCsv(rows, name) {
  const url = URL.createObjectURL(new Blob([toCsv(rows)], { type: "text/csv;charset=utf-8" }));
  const link = Object.assign(document.createElement("a"), { href: url, download: name });
  link.click();
  URL.revokeObjectURL(url);
}

/**
 * Охват: список компьютеров (выгрузка AD или CSV) против хостов, приславших отчёт. Для тысячи хостов главный
 * вопрос после раскатки — кто молчит: агент не установлен, ПК давно выключен, регистрация отозвана.
 */
export default function AgentCoverage({ organizationId }) {
  const [days, setDays] = useState(7);
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [file, setFile] = useState(null);
  const [busy, setBusy] = useState(false);
  const [uploaded, setUploaded] = useState(null);
  const [filter, setFilter] = useState(null);
  const [query, setQuery] = useState("");

  const load = useCallback(async () => {
    try {
      setError("");
      setData(await getCoverage(organizationId, days));
    } catch (e) {
      setError(e.message);
    }
  }, [organizationId, days]);

  useEffect(() => {
    load();
  }, [load]);

  async function upload(event) {
    event.preventDefault();
    if (!file) return;
    setBusy(true);
    setError("");
    try {
      setUploaded(await uploadExpectedHosts(organizationId, file));
      setFile(null);
      setFilter(null);
      await load();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  async function remove() {
    if (!window.confirm("Удалить список ожидаемых хостов? Отчёты и регистрации хостов не затрагиваются.")) return;
    try {
      await deleteExpectedHosts(organizationId);
      setUploaded(null);
      await load();
    } catch (e) {
      setError(e.message);
    }
  }

  const rows = useMemo(() => {
    if (!data) return [];
    const all = [...data.hosts, ...data.unexpected.map((h) => ({ ...h, status: "unexpected" }))];
    const q = query.trim().toLowerCase();
    return all.filter((h) => (filter ? h.status === filter : h.status !== "unexpected") && (!q || [h.hostname, h.os].some((v) => v?.toLowerCase().includes(q))));
  }, [data, filter, query]);

  const uploadForm = (
    <form onSubmit={upload} className="flex flex-wrap items-center gap-3">
      <input
        type="file"
        aria-label="Файл списка компьютеров"
        accept=".csv,.txt,text/csv,text/plain"
        onChange={(e) => setFile(e.target.files?.[0] || null)}
        className="text-sm text-zinc-300 file:mr-3 file:rounded-lg file:border-0 file:bg-zinc-800 file:px-3 file:py-1.5 file:text-zinc-200"
      />
      <button type="submit" disabled={!file || busy} className={BUTTON}>
        {busy ? "Загружаю…" : data?.list ? "Заменить список" : "Загрузить список"}
      </button>
    </form>
  );

  if (!data) {
    return error ? <p className="text-sm text-rose-300">{error}</p> : <p className="text-sm text-zinc-400">Загрузка…</p>;
  }

  if (!data.list) {
    return (
      <div className="space-y-3 text-sm">
        <p className="text-zinc-400">
          Загрузите список компьютеров, которые должны отчитываться: выгрузку из AD (PowerShell на контроллере домена или
          ПК с RSAT) или любую таблицу CSV с колонкой имени (Name, Hostname, «Имя»), либо список имён по одному в строке.
        </p>
        <div className="relative">
          <pre className="overflow-x-auto whitespace-pre-wrap rounded-xl border border-zinc-800 bg-zinc-950 p-3 pr-24 text-xs text-zinc-200">{AD_EXPORT}</pre>
          <CopyButton text={AD_EXPORT} label="копировать" className="absolute right-2 top-2 rounded-lg border border-zinc-700 bg-zinc-900 px-2 py-1 text-xs text-zinc-300 hover:text-white" />
        </div>
        {uploadForm}
        {error ? <p className="text-rose-300">{error}</p> : null}
      </div>
    );
  }

  const tiles = ["reporting", "stale", "not_installed", "revoked", "unexpected"].filter((s) => s !== "revoked" || data.summary.revoked);
  const covered = data.list.total ? Math.round((data.summary.reporting / data.list.total) * 100) : 0;

  return (
    <div className="space-y-4 text-sm">
      <div className="flex flex-wrap items-center justify-between gap-3 text-zinc-400">
        <span>
          Список: {data.list.total} хостов · {data.list.source || "файл"} · загружен {formatDateTime(data.list.imported_at)}
          {data.list.imported_by ? ` (${data.list.imported_by})` : ""}
        </span>
        <span className="flex items-center gap-2">
          отчитался за
          {PERIODS.map((d) => (
            <button key={d} type="button" aria-pressed={days === d} onClick={() => setDays(d)} className={`rounded-lg border px-2 py-0.5 text-xs ${days === d ? "border-blue-500 text-white" : "border-zinc-700 text-zinc-400 hover:text-white"}`}>
              {d === 1 ? "сутки" : `${d} дн.`}
            </button>
          ))}
        </span>
      </div>

      <div className="grid gap-3 sm:grid-cols-3 xl:grid-cols-5">
        {tiles.map((status) => (
          <button
            key={status}
            type="button"
            aria-pressed={filter === status}
            onClick={() => setFilter(filter === status ? null : status)}
            className={`rounded-2xl border p-3 text-left transition ${filter === status ? "border-blue-500 bg-blue-500/10" : "border-zinc-800 bg-zinc-950 hover:border-zinc-700"}`}
          >
            <div className="text-xs text-zinc-400">{STATUS[status].tile}</div>
            <div className="mt-1 text-2xl font-semibold text-white">{data.summary[status]}</div>
            {status === "reporting" ? <div className="text-xs text-zinc-500">{covered}% списка</div> : null}
          </button>
        ))}
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <input type="search" aria-label="Поиск в охвате" className={`${INPUT} max-w-xs`} value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Поиск: имя, ОС" />
        <span className="text-zinc-400">{filter ? STATUS[filter].tile.toLowerCase() : "весь список"}: {rows.length}</span>
        <button type="button" disabled={!rows.length} onClick={() => downloadCsv(rows, `охват-${filter || "все"}.csv`)} className="text-xs text-zinc-300 underline hover:text-white disabled:opacity-40">
          Скачать CSV
        </button>
      </div>

      <div className="max-h-[28rem] overflow-auto">
        <table className="w-full text-left">
          <thead className="sticky top-0 bg-zinc-900 text-xs text-zinc-500">
            <tr>
              <th className="py-2 pr-4 font-normal">Хост</th>
              <th className="py-2 pr-4 font-normal">Состояние</th>
              <th className="py-2 pr-4 font-normal">Последний отчёт</th>
              <th className="py-2 font-normal">Последний вход (AD)</th>
            </tr>
          </thead>
          <tbody>
            {rows.slice(0, 1000).map((h) => (
              <tr key={`${h.status}-${h.hostname}`} className="border-t border-zinc-800 text-zinc-300">
                <td className="py-2 pr-4">
                  <div className="text-white">{h.hostname}</div>
                  <div className="text-xs text-zinc-500">{h.os || "ОС не указана"}</div>
                </td>
                <td className="py-2 pr-4">
                  <span className={`rounded-lg border px-2 py-0.5 text-xs ${STATUS[h.status].cls}`}>{STATUS[h.status].label}</span>
                </td>
                <td className="py-2 pr-4">{h.last_report ? formatDateTime(h.last_report) : "—"}</td>
                <td className="py-2">{h.last_logon || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {rows.length > 1000 ? <p className="py-2 text-xs text-zinc-500">Показаны первые 1000 — полный список в CSV.</p> : null}
        {!rows.length ? <p className="py-3 text-zinc-400">Нет хостов.</p> : null}
      </div>

      <div className="flex flex-wrap items-center gap-4 border-t border-zinc-800 pt-3">
        {uploadForm}
        <button type="button" onClick={remove} className="text-xs text-zinc-400 hover:text-white">Удалить список</button>
      </div>
      {uploaded ? (
        <p className="text-emerald-300">
          Загружено хостов: {uploaded.imported}
          {uploaded.duplicates ? `, повторов пропущено: ${uploaded.duplicates}` : ""}
          {uploaded.skipped_disabled ? `, отключённых в AD пропущено: ${uploaded.skipped_disabled}` : ""}.
        </p>
      ) : null}
      {error ? <p className="text-rose-300">{error}</p> : null}
    </div>
  );
}
