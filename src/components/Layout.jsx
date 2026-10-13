import { useState } from "react";
import { Outlet, useLocation } from "react-router-dom";
import { useOrganization } from "../context/OrganizationContext";
import Sidebar from "./Sidebar";
import Topbar from "./Topbar";

const ORG_INDEPENDENT = ["/admin/", "/change-password", "/two-factor"];

export default function Layout() {
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const { selectedOrganizationId } = useOrganization();
  const { pathname } = useLocation();
  // Смена организации пересоздаёт страницу организации: фильтры, формы и показанный ключ агента прежней
  // организации не остаются на экране новой. Страницы вне организации (учётные записи, свой пароль, 2FA)
  // не пересоздаются: иначе «Организация создана» пропадало бы — новая организация сразу становится выбранной.
  const pageKey = ORG_INDEPENDENT.some((path) => pathname.startsWith(path)) ? pathname : selectedOrganizationId || "none";

  return (
    <div className="min-h-screen bg-[#0b0f14] text-white">
      <div className="flex min-h-screen">
        <Sidebar open={mobileNavOpen} onClose={() => setMobileNavOpen(false)} />

        <div className="flex min-w-0 flex-1 flex-col">
          <Topbar onMenuClick={() => setMobileNavOpen(true)} />

          <main className="flex-1 overflow-y-auto p-6">
            <Outlet key={pageKey} />
          </main>
        </div>
      </div>
    </div>
  );
}
