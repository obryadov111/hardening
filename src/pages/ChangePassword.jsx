import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { authApi } from "../api/auth";

const INPUT = "w-full rounded-xl border border-zinc-800 bg-zinc-950 px-3 py-2 text-white outline-none placeholder:text-zinc-500 focus:border-blue-500";

/**
 * Смена своего пароля. forced — пароль временный (выдан администратором): пока он не сменён,
 * сервер закрывает остальные разделы, поэтому страница показывается без меню.
 */
export default function ChangePassword({ forced = false }) {
  const navigate = useNavigate();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [repeat, setRepeat] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");
    if (next !== repeat) {
      setError("Новый пароль и повтор не совпадают");
      return;
    }
    try {
      setLoading(true);
      await authApi.changePassword(current, next);
      navigate("/", { replace: true });
    } catch (err) {
      setError(err.message || "Не удалось сменить пароль");
    } finally {
      setLoading(false);
    }
  }

  const form = (
    <form onSubmit={handleSubmit} className="space-y-4 rounded-2xl border border-zinc-800 bg-zinc-900 p-6">
      <div>
        <label htmlFor="current-password" className="mb-1 block text-sm text-zinc-400">
          {forced ? "Временный пароль" : "Текущий пароль"}
        </label>
        <input id="current-password" type="password" autoComplete="current-password" required className={INPUT} value={current} onChange={(e) => setCurrent(e.target.value)} />
      </div>
      <div>
        <label htmlFor="new-password" className="mb-1 block text-sm text-zinc-400">Новый пароль (от 12 символов)</label>
        <input id="new-password" type="password" autoComplete="new-password" required minLength={12} className={INPUT} value={next} onChange={(e) => setNext(e.target.value)} />
      </div>
      <div>
        <label htmlFor="repeat-password" className="mb-1 block text-sm text-zinc-400">Повторите новый пароль</label>
        <input id="repeat-password" type="password" autoComplete="new-password" required minLength={12} className={INPUT} value={repeat} onChange={(e) => setRepeat(e.target.value)} />
      </div>
      {error ? <div className="rounded-lg border border-red-900 bg-red-950/40 px-4 py-2 text-sm text-red-300">{error}</div> : null}
      <div className="flex items-center gap-3">
        <button type="submit" disabled={loading} className="rounded-xl bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500 disabled:opacity-60">
          {loading ? "Сохраняем..." : "Сменить пароль"}
        </button>
        {forced ? (
          <button type="button" onClick={() => authApi.logout()} className="text-sm text-zinc-400 hover:text-white">Выйти</button>
        ) : null}
      </div>
      <div className="text-xs text-zinc-500">После смены все остальные сеансы с этой учётной записью будут завершены.</div>
    </form>
  );

  if (!forced) {
    return (
      <div className="max-w-xl space-y-6">
        <h1 className="text-2xl font-semibold text-white">Смена пароля</h1>
        {form}
      </div>
    );
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-zinc-950 px-4 text-white">
      <div className="w-full max-w-md space-y-4">
        <div>
          <h1 className="text-2xl font-semibold">Задайте свой пароль</h1>
          <p className="mt-1 text-sm text-zinc-400">
            Вам выдан временный пароль. Чтобы продолжить работу, смените его — после этого временный перестанет действовать.
          </p>
        </div>
        {form}
      </div>
    </div>
  );
}
