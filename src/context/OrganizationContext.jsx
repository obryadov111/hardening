import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { getOrganizations } from "../api/organizations";
import { onClientAuthStateChange } from "../api/client";

const OrganizationContext = createContext(null);
const STORAGE_KEY = "selected_organization_id";

export function OrganizationProvider({ children }) {
  const [organizations, setOrganizations] = useState([]);
  const [selectedOrganizationId, setSelectedOrganizationId] = useState(
    localStorage.getItem(STORAGE_KEY) || null
  );
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [reloadKey, setReloadKey] = useState(0);

  // После создания организации: список перезапрашивается, selectId (если задан) становится выбранной.
  const reloadOrganizations = useCallback((selectId) => {
    if (selectId) localStorage.setItem(STORAGE_KEY, selectId);
    setReloadKey((n) => n + 1);
  }, []);

  // Организации грузятся по состоянию входа, а не один раз при старте: провайдер
  // живёт выше /login, и раньше запрос до входа получал 403, ошибка запоминалась и
  // после успешного входа страницы показывали её вместо данных.
  useEffect(() => {
    let requestId = 0;

    async function loadOrganizations() {
      const current = ++requestId;
      try {
        setLoading(true);
        setError("");

        const rows = await getOrganizations();
        if (current !== requestId) return;
        setOrganizations(rows);

        if (!rows.length) {
          setSelectedOrganizationId(null);
          localStorage.removeItem(STORAGE_KEY);
          return;
        }

        const savedId = localStorage.getItem(STORAGE_KEY);
        const hasValidSavedId = rows.some((org) => org.id === savedId);

        if (hasValidSavedId) {
          setSelectedOrganizationId(savedId);
        } else {
          const firstId = rows[0].id;
          setSelectedOrganizationId(firstId);
          localStorage.setItem(STORAGE_KEY, firstId);
        }
      } catch (err) {
        if (current !== requestId) return;
        // Выбор организации не сбрасывается: сбой сети или 403 до смены временного пароля и подключения
        // обязательной 2FA — не повод забыть, с какой организацией работал пользователь. Ошибку показывают страницы.
        setOrganizations([]);
        setError(err?.message || "Не удалось загрузить организации");
      } finally {
        if (current === requestId) setLoading(false);
      }
    }

    const subscription = onClientAuthStateChange((_event, session) => {
      if (session) {
        loadOrganizations();
        return;
      }
      requestId++;
      setOrganizations([]);
      setError("");
      setLoading(false);
    });

    return () => {
      requestId++;
      subscription.data.subscription.unsubscribe();
    };
  }, [reloadKey]);

  useEffect(() => {
    if (!selectedOrganizationId) {
      localStorage.removeItem(STORAGE_KEY);
      return;
    }

    const exists = organizations.some((org) => org.id === selectedOrganizationId);

    if (exists) {
      localStorage.setItem(STORAGE_KEY, selectedOrganizationId);
    }
  }, [selectedOrganizationId, organizations]);

  const selectedOrganization =
    organizations.find((org) => org.id === selectedOrganizationId) || null;

  const value = useMemo(
    () => ({
      organizations,
      selectedOrganizationId,
      setSelectedOrganizationId,
      selectedOrganization,
      loading,
      error,
      hasOrganizations: organizations.length > 0,
      reloadOrganizations,
    }),
    [
      organizations,
      selectedOrganizationId,
      selectedOrganization,
      loading,
      error,
      reloadOrganizations,
    ]
  );

  return (
    <OrganizationContext.Provider value={value}>
      {children}
    </OrganizationContext.Provider>
  );
}

// eslint-disable-next-line react-refresh/only-export-components -- хук и провайдер намеренно живут в одном файле
export function useOrganization() {
  const context = useContext(OrganizationContext);

  if (!context) {
    throw new Error("useOrganization must be used within OrganizationProvider");
  }

  return context;
}