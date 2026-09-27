import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import Layout from "./components/Layout";
import ProtectedRoute from "./components/ProtectedRoute";
import Login from "./pages/Login";
import { OrganizationProvider } from "./context/OrganizationContext";
import OrganizationUsers from "./pages/OrganizationUsers";
import AdminUsers from "./pages/AdminUsers";
import ChangePassword from "./pages/ChangePassword";
import TwoFactor from "./pages/TwoFactor";
import Dashboard from "./pages/Dashboard";
import Assets from "./pages/Assets";
import AssetDetails from "./pages/AssetDetails";
import Hardening from "./pages/Hardening";
import Policies from "./pages/Policies";
import Report from "./pages/Report";
import Project from "./pages/Project";
import SoftwareInventory from "./pages/SoftwareInventory";
import Scans from "./pages/Scans";
import ScanCompare from "./pages/ScanCompare";

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
              <Route path="policies" element={<Policies />} />
              <Route path="report" element={<Report />} />
              <Route path="project" element={<Project />} />
              <Route path="software" element={<SoftwareInventory />} />
              <Route path="scans" element={<Scans />} />
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
