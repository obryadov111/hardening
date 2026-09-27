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
        detail = data.detail || data.message || detail;
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

  if (!response.ok) {
    let detail = "Ошибка скачивания";
    try {
      detail = await response.text();
    } catch {
      // ответ не распарсился как JSON/текст — используем detail по умолчанию
    }
    throw new Error(detail || "Ошибка скачивания");
  }

  return response.blob();
}