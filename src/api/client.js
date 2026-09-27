const API_BASE = import.meta.env.VITE_API_BASE_URL || "/api";

let accessToken = localStorage.getItem("volkodav_access_token") || null;
const listeners = new Set();

function notifyAuthChanged(session) {
  for (const listener of listeners) {
    try {
      listener("SIGNED_IN", session);
    } catch (error) {
      console.error("auth listener error", error);
    }
  }
}

function notifySignedOut() {
  for (const listener of listeners) {
    try {
      listener("SIGNED_OUT", null);
    } catch (error) {
      console.error("auth listener error", error);
    }
  }
}

export function onClientAuthStateChange(callback) {
  listeners.add(callback);
  callback("INITIAL_SESSION", accessToken ? { access_token: accessToken } : null);

  return {
    data: {
      subscription: {
        unsubscribe() {
          listeners.delete(callback);
        },
      },
    },
  };
}

export function getStoredAccessToken() {
  return accessToken;
}

export function setStoredAccessToken(token) {
  accessToken = token;
  if (token) {
    localStorage.setItem("volkodav_access_token", token);
    notifyAuthChanged({ access_token: token });
  } else {
    localStorage.removeItem("volkodav_access_token");
    notifySignedOut();
  }
}

export function clearStoredAccessToken() {
  setStoredAccessToken(null);
}

// FastAPI отдаёт ошибки валидации (422) как массив объектов в detail; без разбора
// new Error(detail) превращал его в строку "[object Object]".
const FIELD_NAMES = { email: "Email", password: "Пароль" };

function formatErrorDetail(detail) {
  if (Array.isArray(detail)) {
    return detail
      .map((item) => {
        const field = Array.isArray(item?.loc) ? item.loc[item.loc.length - 1] : null;
        const msg = item?.loc?.includes("email") && item?.type === "value_error"
          ? "некорректный адрес электронной почты"
          : item?.msg || JSON.stringify(item);
        return field ? `${FIELD_NAMES[field] || field}: ${msg}` : msg;
      })
      .join("; ");
  }
  if (detail && typeof detail === "object") return detail.message || JSON.stringify(detail);
  return detail;
}

export async function apiFetch(path, options = {}) {
  const headers = {
    ...(options.headers || {}),
  };

  const isFormData = options.body instanceof FormData;

  if (!isFormData && !headers["Content-Type"] && options.body != null) {
    headers["Content-Type"] = "application/json";
  }

  if (accessToken) {
    headers.Authorization = `Bearer ${accessToken}`;
  }

  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
  });

  if (response.status === 401) {
    clearStoredAccessToken();
  }

  const contentType = response.headers.get("content-type") || "";

  if (!response.ok) {
    let detail = "Ошибка запроса";
    try {
      if (contentType.includes("application/json")) {
        const data = await response.json();
        detail = formatErrorDetail(data.detail || data.message) || detail;
      } else {
        detail = await response.text();
      }
    } catch {
      // ответ не распарсился как JSON/текст — используем detail по умолчанию
    }
    throw new Error(detail || "Ошибка запроса");
  }

  if (response.status === 204) {
    return null;
  }

  if (contentType.includes("application/json")) {
    return response.json();
  }

  return response.text();
}

/** Скачивание файла: { blob, filename } (имя — из Content-Disposition, если сервер его дал). */
export async function apiDownload(path, options = {}) {
  const headers = {
    ...(options.headers || {}),
  };

  if (accessToken) {
    headers.Authorization = `Bearer ${accessToken}`;
  }

  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
  });

  if (response.status === 401) {
    clearStoredAccessToken();
  }

  if (!response.ok) {
    let detail = "Ошибка скачивания";
    try {
      const contentType = response.headers.get("content-type") || "";
      if (contentType.includes("application/json")) {
        const data = await response.json();
        detail = formatErrorDetail(data.detail || data.message) || detail;
      } else {
        detail = (await response.text()) || detail;
      }
    } catch {
      // ответ не распарсился как JSON/текст — используем detail по умолчанию
    }
    throw new Error(detail);
  }

  const disposition = response.headers.get("content-disposition") || "";
  const match = disposition.match(/filename="?([^";]+)"?/i);
  return { blob: await response.blob(), filename: match ? match[1] : null };
}
