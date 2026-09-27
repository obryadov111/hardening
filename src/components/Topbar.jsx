import { useEffect, useRef, useState } from "react";
import { AnimatePresence, motion as Motion } from "framer-motion";
import {
  Building2,
  ChevronDown,
  KeyRound,
  LogOut,
  Menu,
  Shield,
  ShieldCheck,
  UserCog,
  Users,
} from "lucide-react";
import { useNavigate } from "react-router-dom";
import { authApi } from "../api/auth";
import {
  getCurrentUserProfile,
  getCurrentUserRoleInOrganization,
} from "../api/users";
import { useOrganization } from "../context/OrganizationContext";

export default function Topbar({ onMenuClick }) {
  const navigate = useNavigate();
  const menuRef = useRef(null);

  const {
    organizations,
    selectedOrganizationId,
    setSelectedOrganizationId,
    selectedOrganization,
    loading: orgLoading,
    hasOrganizations,
  } = useOrganization();

  const [menuOpen, setMenuOpen] = useState(false);
  const [profile, setProfile] = useState(null);
  const [currentRole, setCurrentRole] = useState(null);

  useEffect(() => {
    async function loadProfile() {
      try {
        const data = await getCurrentUserProfile();
        setProfile(data);
      } catch (error) {
        console.error("Ошибка загрузки профиля:", error.message);
      }
    }

    loadProfile();
  }, []);

  useEffect(() => {
    async function loadRole() {
      try {
        if (!selectedOrganizationId) {
          setCurrentRole(null);
          return;
        }

        const role = await getCurrentUserRoleInOrganization(selectedOrganizationId);
        setCurrentRole(role);
      } catch (error) {
        console.error("Ошибка загрузки роли:", error.message);
        setCurrentRole(null);
      }
    }

    loadRole();
  }, [selectedOrganizationId]);

  useEffect(() => {
    function handleClickOutside(event) {
      if (menuRef.current && !menuRef.current.contains(event.target)) {
        setMenuOpen(false);
      }
    }

    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  const handleLogout = async () => {
    try {
      await authApi.logout();
      navigate("/login", { replace: true });
    } catch (error) {
      console.error("Ошибка выхода:", error.message);
    }
  };

  const roleLabel = currentRole || "viewer";

  return (
    <header className="sticky top-0 z-10 border-b border-zinc-800 bg-[#0b0f14]/95 backdrop-blur">
      <div className="flex flex-col gap-4 px-6 py-4 xl:flex-row xl:items-center xl:justify-between">
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={onMenuClick}
            className="rounded-xl border border-zinc-800 bg-zinc-900 p-2 text-zinc-300 hover:bg-zinc-800 hover:text-white md:hidden"
            aria-label="Открыть меню"
          >
            <Menu size={18} />
          </button>

          <div>
            <div className="text-lg font-semibold text-white">Volkodav</div>
            <div className="text-sm text-zinc-400">
              {selectedOrganization
                ? `Текущая организация: ${selectedOrganization.name}`
                : "Панель мониторинга харденинга"}
            </div>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2 rounded-xl border border-zinc-800 bg-zinc-900 px-3 py-2">
            <Building2 size={16} className="text-zinc-500" />

            <select
              value={selectedOrganizationId || ""}
              onChange={(e) => setSelectedOrganizationId(e.target.value)}
              disabled={orgLoading || !hasOrganizations}
              className="min-w-[220px] bg-transparent text-sm text-white outline-none disabled:text-zinc-500"
            >
              {orgLoading ? (
                <option value="">Загрузка организаций...</option>
              ) : !hasOrganizations ? (
                <option value="">Нет организаций</option>
              ) : (
                organizations.map((org) => (
                  <option
                    key={org.id}
                    value={org.id}
                    className="bg-zinc-900 text-white"
                  >
                    {org.name}
                  </option>
                ))
              )}
            </select>
          </div>

          <div className="relative" ref={menuRef}>
            <button
              type="button"
              onClick={() => setMenuOpen((prev) => !prev)}
              className="flex items-center gap-3 rounded-xl border border-zinc-800 bg-zinc-900 px-3 py-2 text-left hover:bg-zinc-800/80"
            >
              <div className="flex h-9 w-9 items-center justify-center rounded-full bg-blue-500/15 text-blue-300">
                <Shield size={16} />
              </div>

              <div className="leading-tight">
                <div className="text-sm font-medium text-white">
                  {profile?.email || "Пользователь"}
                </div>
                <div className="text-xs text-zinc-400">
                  {roleLabel}
                </div>
              </div>

              <ChevronDown size={16} className="text-zinc-500" />
            </button>

            <AnimatePresence>
              {menuOpen ? (
                <Motion.div
                  initial={{ opacity: 0, y: -6, scale: 0.98 }}
                  animate={{ opacity: 1, y: 0, scale: 1 }}
                  exit={{ opacity: 0, y: -6, scale: 0.98 }}
                  transition={{ duration: 0.15 }}
                  className="absolute right-0 mt-2 w-72 rounded-2xl border border-zinc-800 bg-zinc-900 p-2 shadow-2xl"
                >
                  <div className="rounded-xl border border-zinc-800 bg-zinc-950/70 p-3">
                    <div className="text-sm font-medium text-white">
                      {profile?.email || "Без email"}
                    </div>
                    <div className="mt-1 text-xs text-zinc-400">
                      Роль: {roleLabel}
                    </div>
                    <div className="mt-1 text-xs text-zinc-400">
                      Организация: {selectedOrganization?.name || "—"}
                    </div>
                  </div>

                  <div className="mt-2 flex flex-col gap-1">
                    {currentRole === "admin" ? (
                      <button
                        type="button"
                        onClick={() => {
                          setMenuOpen(false);
                          navigate("/organization-users");
                        }}
                        className="flex items-center gap-2 rounded-xl px-3 py-2 text-sm text-zinc-200 hover:bg-zinc-800"
                      >
                        <UserCog size={16} />
                        <span>Управление доступом</span>
                      </button>
                    ) : null}

                    {profile?.is_superadmin ? (
                      <button
                        type="button"
                        onClick={() => {
                          setMenuOpen(false);
                          navigate("/admin/users");
                        }}
                        className="flex items-center gap-2 rounded-xl px-3 py-2 text-sm text-zinc-200 hover:bg-zinc-800"
                      >
                        <Users size={16} />
                        <span>Пользователи системы</span>
                      </button>
                    ) : null}

                    <button
                      type="button"
                      onClick={() => {
                        setMenuOpen(false);
                        navigate("/change-password");
                      }}
                      className="flex items-center gap-2 rounded-xl px-3 py-2 text-sm text-zinc-200 hover:bg-zinc-800"
                    >
                      <KeyRound size={16} />
                      <span>Сменить пароль</span>
                    </button>

                    <button
                      type="button"
                      onClick={() => {
                        setMenuOpen(false);
                        navigate("/two-factor");
                      }}
                      className="flex items-center gap-2 rounded-xl px-3 py-2 text-sm text-zinc-200 hover:bg-zinc-800"
                    >
                      <ShieldCheck size={16} />
                      <span>Двухфакторная защита</span>
                    </button>

                    <button
                      type="button"
                      onClick={handleLogout}
                      className="flex items-center gap-2 rounded-xl px-3 py-2 text-sm text-rose-300 hover:bg-zinc-800"
                    >
                      <LogOut size={16} />
                      <span>Выйти</span>
                    </button>
                  </div>
                </Motion.div>
              ) : null}
            </AnimatePresence>
          </div>
        </div>
      </div>
    </header>
  );
}