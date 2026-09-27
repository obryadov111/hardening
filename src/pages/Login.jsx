import { useEffect, useState } from "react";
import { Navigate, useNavigate } from "react-router-dom";
import { Shield } from "lucide-react";
import { authApi } from "../api/auth";

export default function Login() {
  const navigate = useNavigate();

  const [step, setStep] = useState("credentials"); // "credentials" | "2fa"
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const [tempToken, setTempToken] = useState("");
  const [code, setCode] = useState("");

  const [hasCheckedSession, setHasCheckedSession] = useState(false);
  const [hasSession, setHasSession] = useState(false);

  useEffect(() => {
    authApi
      .getSession()
      .then((session) => {
        setHasSession(Boolean(session));
      })
      .catch(() => setHasSession(false))
      .finally(() => setHasCheckedSession(true));
  }, []);

  async function handleLogin(e) {
    e.preventDefault();
    setError("");

    try {
      if (!email.trim()) {
        throw new Error("Введите email");
      }

      if (!password.trim()) {
        throw new Error("Введите пароль");
      }

      setLoading(true);
      const data = await authApi.login(email, password);

      if (data.two_factor_required) {
        setTempToken(data.temp_token);
        setStep("2fa");
        return;
      }

      navigate("/", { replace: true });
    } catch (err) {
      console.error("Ошибка входа:", err.message);
      setError(err.message || "Ошибка входа");
    } finally {
      setLoading(false);
    }
  }

  async function handleVerify2FA(e) {
    e.preventDefault();
    setError("");

    try {
      if (!code.trim()) {
        throw new Error("Введите код из приложения-аутентификатора");
      }

      setLoading(true);
      await authApi.verify2FA(tempToken, code);
      navigate("/", { replace: true });
    } catch (err) {
      console.error("Ошибка проверки кода:", err.message);
      setError(err.message || "Неверный код");
    } finally {
      setLoading(false);
    }
  }

  if (hasCheckedSession && hasSession) {
    return <Navigate to="/" replace />;
  }

  return (
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden bg-zinc-950 px-4 text-white">
      {/* точечная сетка + мягкое свечение — визуальная идентичность продукта */}
      <div
        className="pointer-events-none absolute inset-0 opacity-40"
        style={{
          backgroundImage: "radial-gradient(circle, rgba(63,63,70,.6) 1px, transparent 1px)",
          backgroundSize: "28px 28px",
        }}
      />
      <div
        className="pointer-events-none absolute left-1/2 top-1/2 h-[560px] w-[560px] -translate-x-1/2 -translate-y-1/2 rounded-full"
        style={{ background: "radial-gradient(circle, rgba(59,130,246,.18), transparent 70%)" }}
      />

      <div className="relative w-full max-w-md">
        <div className="mb-6 flex flex-col items-center text-center">
          <div className="mb-4 flex h-14 w-14 items-center justify-center rounded-2xl border border-blue-500/20 bg-blue-500/10 text-blue-300">
            <Shield size={28} />
          </div>
          <h1 className="text-3xl font-bold">Харденинг</h1>
          <p className="mt-2 text-sm text-zinc-400">Автоматизация харденинга ИБ-инфраструктуры</p>
        </div>

      <div className="w-full max-w-md rounded-2xl border border-zinc-800 bg-zinc-900 p-6 shadow-xl">
        {error && (
          <div className="mb-4 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-300">
            {error}
          </div>
        )}

        {step === "credentials" ? (
          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <label className="mb-1 block text-sm text-zinc-300">Email</label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="field-input"
                placeholder="admin@hardening.local"
                autoComplete="username"
              />
            </div>

            <div>
              <label className="mb-1 block text-sm text-zinc-300">Пароль</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="field-input"
                placeholder="Введите пароль"
                autoComplete="current-password"
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full rounded-lg bg-blue-600 px-4 py-2 font-medium text-white hover:bg-blue-500 disabled:opacity-60"
            >
              {loading ? "Вход..." : "Войти"}
            </button>

            <p className="text-center text-xs text-zinc-500">
              Аккаунты создаются администратором системы
            </p>
          </form>
        ) : (
          <form onSubmit={handleVerify2FA} className="space-y-4">
            <p className="text-sm text-zinc-400">
              Введите 6-значный код из приложения-аутентификатора или один из резервных кодов
            </p>

            <div>
              <label className="mb-1 block text-sm text-zinc-300">Код 2FA или резервный код</label>
              <input
                type="text"
                autoFocus
                autoComplete="one-time-code"
                value={code}
                onChange={(e) => setCode(e.target.value)}
                className="field-input text-center text-lg tracking-[0.4em]"
                placeholder="000000"
                maxLength={11}
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full rounded-lg bg-blue-600 px-4 py-2 font-medium text-white hover:bg-blue-500 disabled:opacity-60"
            >
              {loading ? "Проверка..." : "Подтвердить"}
            </button>

            <button
              type="button"
              onClick={() => {
                setStep("credentials");
                setCode("");
                setError("");
              }}
              className="w-full text-center text-sm text-zinc-400 hover:text-zinc-200"
            >
              Назад
            </button>
          </form>
        )}
      </div>
      </div>
    </div>
  );
}
