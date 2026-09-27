import { Navigate, Outlet, useLocation } from "react-router-dom";
import { useEffect, useState } from "react";
import { authApi } from "../api/auth";
import { getStoredAccessToken } from "../api/client";

// Состояния проверки доступа:
//  "checking" — ждём /auth/me;
//  "ok" — токен принят;
//  "unauth" — токена нет или сервер его отклонил (401 стирает токен в apiFetch);
//  "unreachable" — сервер не ответил / ответил не 401 (сеть, прокси, 5xx), а токен остался.
// Раньше "unreachable" трактовался как "unauth": редирект на /login, а Login, видя токен,
// сразу возвращал на / — бесконечная петля «Проверка доступа...» ↔ страница входа.
export default function ProtectedRoute() {
  const [state, setState] = useState("checking");
  const [attempt, setAttempt] = useState(0);
  const location = useLocation();

  useEffect(() => {
    let mounted = true;

    async function verify() {
      if (!(await authApi.getSession())) {
        if (mounted) setState("unauth");
        return;
      }
      try {
        await authApi.getMyProfile();
        if (mounted) setState("ok");
      } catch {
        if (mounted) setState(getStoredAccessToken() ? "unreachable" : "unauth");
      }
    }

    verify();

    const subscription = authApi.onAuthStateChange((event, session) => {
      if (!mounted || event === "INITIAL_SESSION") return;
      if (!session) {
        setState("unauth");
        return;
      }
      verify();
    });

    return () => {
      mounted = false;
      subscription?.data?.subscription?.unsubscribe?.();
    };
  }, [attempt]);

  if (state === "checking") {
    return <div className="p-6 text-zinc-400">Проверка доступа...</div>;
  }

  if (state === "unreachable") {
    return (
      <div className="p-6 text-zinc-300">
        <div className="text-white">Сервер недоступен</div>
        <div className="mt-1 text-sm text-zinc-400">
          Не удалось проверить доступ: API не ответил. Проверьте, что бэкенд запущен.
        </div>
        <div className="mt-4 flex gap-3">
          <button
            type="button"
            className="rounded-lg border border-zinc-700 px-3 py-1.5 text-sm hover:bg-zinc-800"
            onClick={() => {
              setState("checking");
              setAttempt((n) => n + 1);
            }}
          >
            Повторить
          </button>
          <button
            type="button"
            className="rounded-lg px-3 py-1.5 text-sm text-zinc-400 hover:text-white"
            onClick={() => authApi.logout()}
          >
            Выйти
          </button>
        </div>
      </div>
    );
  }

  if (state === "unauth") {
    return <Navigate to="/login" replace state={{ from: location }} />;
  }

  return <Outlet />;
}
