import { useCallback, useEffect, useState } from "react";
import AppCard from "../components/ui/AppCard";
import ErrorState from "../components/ui/ErrorState";
import { confirmTwoFactor, disableTwoFactor, getTwoFactorStatus, setupTwoFactor } from "../api/twofa";

const INPUT = "w-full rounded-xl border border-zinc-800 bg-zinc-950 px-3 py-2 text-white outline-none placeholder:text-zinc-500 focus:border-blue-500";
const BUTTON = "rounded-xl bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500 disabled:opacity-60";

/** Резервные коды показываются один раз — после этого на сервере остаются только их хэши. */
function BackupCodes({ codes, onDone }) {
  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-amber-500/20 bg-amber-500/10 p-4 text-sm text-amber-200">
        2FA включена. Сохраните резервные коды в надёжном месте (не на том же телефоне): каждый код
        одноразовый и заменяет код из приложения, если телефона нет под рукой. Больше они показаны не будут.
      </div>
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        {codes.map((code) => (
          <code key={code} className="rounded-lg bg-zinc-950 px-3 py-2 text-center font-mono text-white">{code}</code>
        ))}
      </div>
      <div className="flex gap-3">
        <button type="button" onClick={() => navigator.clipboard?.writeText(codes.join("\n"))} className="rounded-xl border border-zinc-700 px-4 py-2 text-sm text-white hover:bg-zinc-800">
          Скопировать все
        </button>
        <button type="button" onClick={onDone} className={BUTTON}>Я сохранил коды</button>
      </div>
    </div>
  );
}

export default function TwoFactor() {
  const [status, setStatus] = useState(null);
  const [setup, setSetup] = useState(null);
  const [backupCodes, setBackupCodes] = useState(null);
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      setStatus(await getTwoFactorStatus());
    } catch (err) {
      setError(err.message);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function run(action) {
    setBusy(true);
    setError("");
    try {
      await action();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  const startSetup = () => run(async () => setSetup(await setupTwoFactor()));

  const confirm = (e) => {
    e.preventDefault();
    run(async () => {
      const result = await confirmTwoFactor(code);
      setBackupCodes(result.backup_codes);
      setSetup(null);
      setCode("");
      await load();
    });
  };

  const disable = (e) => {
    e.preventDefault();
    run(async () => {
      await disableTwoFactor(password, code);
      setPassword("");
      setCode("");
      await load();
    });
  };

  return (
    <div className="max-w-2xl space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-white">Двухфакторная защита</h1>
        <p className="mt-1 text-sm text-zinc-400">
          При входе кроме пароля понадобится код из приложения-аутентификатора (Google Authenticator,
          «Яндекс Ключ», FreeOTP и т. п.).
        </p>
      </div>

      {error ? <ErrorState title="Ошибка" description={error} /> : null}

      {backupCodes ? (
        <AppCard title="Резервные коды">
          <BackupCodes codes={backupCodes} onDone={() => setBackupCodes(null)} />
        </AppCard>
      ) : status === null ? (
        <div className="text-zinc-400">Загрузка...</div>
      ) : status.enabled ? (
        <AppCard title="2FA включена" subtitle={`Осталось резервных кодов: ${status.backup_codes_left}`}>
          <form onSubmit={disable} className="space-y-3">
            <div className="text-sm text-zinc-400">Чтобы отключить, введите пароль и код из приложения (или резервный код).</div>
            <input className={INPUT} type="password" autoComplete="current-password" required placeholder="Пароль" value={password} onChange={(e) => setPassword(e.target.value)} />
            <input className={INPUT} required autoComplete="one-time-code" placeholder="Код 2FA или резервный код" value={code} onChange={(e) => setCode(e.target.value)} />
            <button type="submit" disabled={busy} className="rounded-xl border border-rose-500/20 bg-rose-500/10 px-4 py-2 text-sm text-rose-300 hover:bg-rose-500/20 disabled:opacity-60">
              Отключить 2FA
            </button>
          </form>
        </AppCard>
      ) : setup ? (
        <AppCard title="Подключение: шаг 2 из 2" subtitle="Отсканируйте QR-код в приложении и введите показанный код">
          <form onSubmit={confirm} className="space-y-4">
            <img src={`data:image/png;base64,${setup.qr_png_base64}`} alt="QR-код для приложения-аутентификатора" className="h-48 w-48 rounded-xl bg-white p-2" />
            <div className="text-xs text-zinc-400">
              Не сканируется? Введите ключ вручную: <code className="break-all text-zinc-200">{setup.secret}</code>
            </div>
            <input className={INPUT} required inputMode="numeric" autoComplete="one-time-code" maxLength={6} placeholder="Код из приложения (6 цифр)" value={code} onChange={(e) => setCode(e.target.value)} />
            <div className="flex gap-3">
              <button type="submit" disabled={busy} className={BUTTON}>Включить 2FA</button>
              <button type="button" onClick={() => { setSetup(null); setCode(""); }} className="text-sm text-zinc-400 hover:text-white">Отмена</button>
            </div>
          </form>
        </AppCard>
      ) : (
        <AppCard title="2FA выключена" subtitle="Рекомендуется для всех, у кого есть доступ к результатам аудита">
          <button type="button" disabled={busy} onClick={startSetup} className={BUTTON}>Подключить 2FA</button>
        </AppCard>
      )}
    </div>
  );
}
