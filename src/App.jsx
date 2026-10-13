import { lazy } from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import Layout from "./components/Layout";
import ProtectedRoute from "./components/ProtectedRoute";
import Login from "./pages/Login";
import { OrganizationProvider } from "./context/OrganizationContext";
import ChangePassword from "./pages/ChangePassword";
import TwoFactor from "./pages/TwoFactor";

// Страницы — отдельными файлами сборки: при входе грузится только нужная (графики Recharts — на «Обзоре»).
// После выкатки новой версии открытая вкладка просит файл страницы прежней сборки, которого на сервере уже
// нет, — тогда страница один раз перезагружается и берёт новую сборку (повтор — только через 10 с: не по кругу).
function page(load) {
  return lazy(() =>
    load().catch((error) => {
      const last = Number(sessionStorage.getItem("chunk_reload_at") || 0);
      if (Date.now() - last > 10_000) {
        sessionStorage.setItem("chunk_reload_at", String(Date.now()));
        window.location.reload();
        return new Promise(() => {});
      }
      throw error;
    }),
  );
}

const OrganizationUsers = page(() => import("./pages/OrganizationUsers"));
const AdminUsers = page(() => import("./pages/AdminUsers"));
const Dashboard = page(() => import("./pages/Dashboard"));
const Assets = page(() => import("./pages/Assets"));
const AssetDetails = page(() => import("./pages/AssetDetails"));
const Hardening = page(() => import("./pages/Hardening"));
const Policies = page(() => import("./pages/Policies"));
const Report = page(() => import("./pages/Report"));
const SoftwareInventory = page(() => import("./pages/SoftwareInventory"));
const Scans = page(() => import("./pages/Scans"));
const OfflineScan = page(() => import("./pages/OfflineScan"));
const AgentKeys = page(() => import("./pages/AgentKeys"));
const ScanCompare = page(() => import("./pages/ScanCompare"));
const Vulnerabilities = page(() => import("./pages/Vulnerabilities"));
const FstecCoverage = page(() => import("./pages/FstecCoverage"));

export default function App() {
  return (
    <BrowserRouter>
      <OrganizationProvider>
        <Routes>
          <Route path="/login" element={<Login />} />

          <Route element={<ProtectedRoute />}>
            <Route path="/" element={<Layout />}>
              <Route index element={<Navigate to="/dashboard" replace />} />
              <Route path="dashboard" element={<Dashboard />} />
              <Route path="assets" element={<Assets />} />
              <Route path="assets/:assetId" element={<AssetDetails />} />
              <Route path="hardening" element={<Hardening />} />
              <Route path="vulnerabilities" element={<Vulnerabilities />} />
              <Route path="fstec" element={<FstecCoverage />} />
              <Route path="policies" element={<Policies />} />
              <Route path="report" element={<Report />} />
              {/* «Инфраструктура» объединена с «Активами»: среды — карточки-фильтры над таблицей */}
              <Route path="project" element={<Navigate to="/assets" replace />} />
              <Route path="software" element={<SoftwareInventory />} />
              <Route path="scans" element={<Scans />} />
              <Route path="offline-scan" element={<OfflineScan />} />
              <Route path="agents" element={<AgentKeys />} />
              <Route path="scan-compare" element={<ScanCompare />} />
              <Route path="organization-users" element={<OrganizationUsers />} />
              <Route path="admin/users" element={<AdminUsers />} />
              <Route path="change-password" element={<ChangePassword />} />
              <Route path="two-factor" element={<TwoFactor />} />
            </Route>
          </Route>

          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </OrganizationProvider>
    </BrowserRouter>
  );
}
