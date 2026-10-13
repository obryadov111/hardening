import { useState } from "react";
import { Outlet } from "react-router-dom";
import { useOrganization } from "../context/OrganizationContext";
import Sidebar from "./Sidebar";
import Topbar from "./Topbar";

export default function Layout() {
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const { selectedOrganizationId } = useOrganization();

  return (
    <div className="min-h-screen bg-[#0b0f14] text-white">
      <div className="flex min-h-screen">
        <Sidebar open={mobileNavOpen} onClose={() => setMobileNavOpen(false)} />

        <div className="flex min-w-0 flex-1 flex-col">
          <Topbar onMenuClick={() => setMobileNavOpen(true)} />

          <main className="flex-1 overflow-y-auto p-6">
            {/* Смена организации пересоздаёт страницу: фильтры, формы и показанный ключ агента —
                от прежней организации не остаются на экране новой. */}
            <Outlet key={selectedOrganizationId || "none"} />
          </main>
        </div>
      </div>
    </div>
  );
}
