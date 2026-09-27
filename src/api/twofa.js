import { apiFetch } from "./client";

export async function getTwoFactorStatus() {
  return apiFetch("/auth/2fa");
}

/** Новый секрет (неактивный до confirm): { secret, otpauth_uri, qr_png_base64 }. */
export async function setupTwoFactor() {
  return apiFetch("/auth/2fa/setup", { method: "POST" });
}

/** Включает 2FA по коду из приложения; возвращает одноразовые резервные коды (показать один раз). */
export async function confirmTwoFactor(code) {
  return apiFetch("/auth/2fa/confirm", { method: "POST", body: JSON.stringify({ code: code.trim() }) });
}

export async function disableTwoFactor(password, code) {
  return apiFetch("/auth/2fa/disable", { method: "POST", body: JSON.stringify({ password, code: code.trim() }) });
}
