# 26. Карта модулей

Проверка полноты на 1 ноября 2026. В таблицу попали исходники бэкенда, агента, интерфейса, паки, фикстуры паков, тесты, скрипты `deploy/` и workflow CI. Бинарные образцы вывода в `agent/tests/fixtures/` в таблицу не включены: их читают тесты UserGate и Континента, глава 09.

Всего строк карты: 327 вместе с `src/backend/.env.example`, контекстом интерфейса, хуком сортировки и главами 00 и 27 (шаблон переменных, глава 21). Неразнесённых среди исходников, паков, скриптов deploy и workflow: 0. Файл `.env.example` добавлен к сгенерированному списку отдельно, потому что у него нестандартное расширение.

| Файл | Глава |
|---|---|
| `.github/scripts/agent-in-container.sh` | 23 |
| `.github/scripts/agent_fake_server.py` | 23 |
| `.github/workflows/agent-tests.yml` | 23 |
| `.github/workflows/backend-tests.yml` | 23 |
| `.github/workflows/e2e.yml` | 23 |
| `.github/workflows/frontend-ci.yml` | 23 |
| `.github/workflows/linux-packs.yml` | 23 |
| `.github/workflows/shell.yml` | 23 |
| `.github/workflows/windows-packs.yml` | 23 |
| `Dockerfile.frontend` | 21 |
| `agent/README.md` | 05, 06 |
| `agent/collector.py` | 06, 15 |
| `agent/continent4.py` | 09 |
| `agent/deploy/ansible/hardening-agent.yml` | 05 |
| `agent/deploy/ansible/templates/local.env.j2` | 05 |
| `agent/deploy/hardening-agent@.service` | 05 |
| `agent/deploy/hardening-agent@.timer` | 05, 20 |
| `agent/deploy/install.sh` | 05 |
| `agent/deploy/windows/gpo-startup.ps1` | 05 |
| `agent/probes.py` | 08 |
| `agent/tests/conftest.py` | 23 |
| `agent/tests/test_collector.py` | 23 |
| `agent/tests/test_continent4.py` | 23 |
| `agent/tests/test_deploy.py` | 23 |
| `agent/tests/test_ed25519.py` | 23 |
| `agent/tests/test_probes.py` | 23 |
| `agent/tests/test_transport.py` | 23 |
| `agent/tests/test_usergate.py` | 23 |
| `agent/tests/test_windows_probes.py` | 23 |
| `agent/tests/tls/README.md` | 23 |
| `agent/usergate.py` | 09 |
| `deploy/enable_fail2ban.sh` | 21 |
| `deploy/enable_https.sh` | 21 |
| `deploy/fail2ban/hardening-login.filter.conf` | 21 |
| `deploy/fail2ban/hardening-login.jail.conf` | 21 |
| `deploy/nginx-tls.conf.template` | 21 |
| `deploy/nginx.conf` | 21 |
| `deploy/nginx/admin-allow.conf` | 21, 22 |
| `deploy/nginx/app.conf` | 21, 22 |
| `deploy/nginx/limits.conf` | 21, 22 |
| `deploy/nginx/log-format.conf` | 21 |
| `deploy/publish_agent.sh` | 04 |
| `deploy/restart_backend.sh` | 21 |
| `deploy/restart_frontend.sh` | 21 |
| `deploy/update_bdu.sh` | 14, 20 |
| `docker-compose.yml` | 21 |
| `e2e/global-setup.js` | 23 |
| `e2e/helpers.js` | 23 |
| `e2e/playwright.config.js` | 23 |
| `e2e/seed.py` | 23 |
| `e2e/tests/00-smoke.spec.js` | 23 |
| `e2e/tests/01-auth.spec.js` | 23 |
| `e2e/tests/02-dashboard-assets.spec.js` | 23 |
| `e2e/tests/03-hardening-software-report.spec.js` | 23 |
| `e2e/tests/04-vuln-fstec-policies.spec.js` | 23 |
| `e2e/tests/05-scans-compare-offline.spec.js` | 23 |
| `e2e/tests/06-agents.spec.js` | 23 |
| `e2e/tests/07-users-navigation.spec.js` | 23 |
| `e2e/tests/08-manual-scan.spec.js` | 23 |
| `src/App.jsx` | 17 |
| `src/api/agentKeys.js` | 17, 18 |
| `src/api/assets.js` | 17, 18 |
| `src/api/auth.js` | 17, 18 |
| `src/api/client.js` | 17, 18 |
| `src/api/dashboard.js` | 17, 18 |
| `src/api/exports.js` | 17, 18 |
| `src/api/fstec.js` | 17, 18 |
| `src/api/hardening.js` | 17, 18 |
| `src/api/manualScans.js` | 17, 18 |
| `src/api/offlineScans.js` | 17, 18 |
| `src/api/organizations.js` | 17, 18 |
| `src/api/policies.js` | 17, 18 |
| `src/api/reports.js` | 17, 18 |
| `src/api/riskExceptions.js` | 17, 18 |
| `src/api/snapshots.js` | 17, 18 |
| `src/api/software.js` | 17, 18 |
| `src/api/twofa.js` | 17, 18 |
| `src/api/users.js` | 17, 18 |
| `src/api/vulnerabilities.js` | 17, 18 |
| `src/backend/Dockerfile` | 21 |
| `src/backend/alembic/versions/332ce34492ff_add_agent_api_keys_table.py` | 19 |
| `src/backend/alembic/versions/5bbca4cdfbaa_add_missing_fk_indexes.py` | 19 |
| `src/backend/alembic/versions/91c43e6f135e_baseline_existing_schema.py` | 19 |
| `src/backend/alembic/versions/a1d9c4f27e63_asset_inventory.py` | 19 |
| `src/backend/alembic/versions/a3f1c9d27b40_add_pack_result_columns.py` | 19 |
| `src/backend/alembic/versions/a7d2e9c4f1b8_add_distro_cve_status.py` | 19 |
| `src/backend/alembic/versions/b4e8d1f6a2c9_vulnerability_findings.py` | 19 |
| `src/backend/alembic/versions/b7d2e4f18c63_add_check_metadata_snapshot.py` | 19 |
| `src/backend/alembic/versions/b8e3f0a5c217_add_scan_snapshots_collection.py` | 19 |
| `src/backend/alembic/versions/c4e8a1d2f905_add_password_changed_at.py` | 19 |
| `src/backend/alembic/versions/c4f2a8d6e913_agent_transport.py` | 19 |
| `src/backend/alembic/versions/c9f2a7e4d815_software_search_indexes.py` | 19 |
| `src/backend/alembic/versions/d7a1e4c9f350_agent_host_enrollment.py` | 19 |
| `src/backend/alembic/versions/d91b3f7a2c64_add_users_locked_until.py` | 19 |
| `src/backend/alembic/versions/df4fc6d56bf8_seed_starter_hardening_rules.py` | 19 |
| `src/backend/alembic/versions/e5a7c3b9d102_add_risk_exceptions.py` | 19 |
| `src/backend/alembic/versions/e8b2f5a1c470_indexes_for_many_hosts.py` | 19 |
| `src/backend/alembic/versions/f1c3d6a8b925_expected_hosts.py` | 19 |
| `src/backend/alembic/versions/f3c1a9e7b2d4_add_bdu.py` | 19 |
| `src/backend/app/api/deps.py` | 01, 03, 18 |
| `src/backend/app/api/routes/admin_organizations.py` | 02, 18 |
| `src/backend/app/api/routes/admin_users.py` | 01, 18 |
| `src/backend/app/api/routes/agent.py` | 03, 07, 18 |
| `src/backend/app/api/routes/agent_keys.py` | 03, 06, 18 |
| `src/backend/app/api/routes/auth.py` | 01 |
| `src/backend/app/api/routes/coverage.py` | 02, 18 |
| `src/backend/app/api/routes/data.py` | 17, 18 |
| `src/backend/app/api/routes/exports.py` | 16, 18 |
| `src/backend/app/api/routes/fstec.py` | 12, 18 |
| `src/backend/app/api/routes/ingest.py` | 11 |
| `src/backend/app/api/routes/manual_scans.py` | 10, 18 |
| `src/backend/app/api/routes/members.py` | 02, 18 |
| `src/backend/app/api/routes/offline_scans.py` | 09, 18 |
| `src/backend/app/api/routes/policies.py` | 02, 18 |
| `src/backend/app/api/routes/risk_exceptions.py` | 13, 18 |
| `src/backend/app/api/routes/snapshots.py` | 11, 18 |
| `src/backend/app/api/routes/twofa.py` | 01 |
| `src/backend/app/api/routes/vulnerabilities.py` | 14, 18 |
| `src/backend/app/commands/bdu.py` | 14 |
| `src/backend/app/commands/create_admin.py` | 01, 18 |
| `src/backend/app/commands/create_agent_key.py` | 03, 18 |
| `src/backend/app/commands/pack.py` | 07 |
| `src/backend/app/commands/pack_signing_key.py` | 07 |
| `src/backend/app/commands/seed_demo_data.py` | 18, 23 |
| `src/backend/app/core/config.py` | 01, 21 |
| `src/backend/app/core/security.py` | 01, 03 |
| `src/backend/app/db/session.py` | 19 |
| `src/backend/app/main.py` | 18 |
| `src/backend/app/models/__init__.py` | 19 |
| `src/backend/app/models/asset.py` | 02, 15, 19 |
| `src/backend/app/models/auditor_organization.py` | 19 (не используется) |
| `src/backend/app/models/environment.py` | 02, 19 |
| `src/backend/app/models/hardening.py` | 03, 11, 19 |
| `src/backend/app/models/organization.py` | 02, 19 |
| `src/backend/app/models/risk_exception.py` | 13, 19 |
| `src/backend/app/models/scan_snapshot.py` | 11, 19 |
| `src/backend/app/models/software.py` | 14, 19 |
| `src/backend/app/models/user.py` | 01, 19 |
| `src/backend/app/models/user_2fa.py` | 01, 19 |
| `src/backend/app/models/user_role.py` | 19 (не используется) |
| `src/backend/app/packs/README.md` | 07 |
| `src/backend/app/packs/alt-linux-1.0.0.yaml` | 07 |
| `src/backend/app/packs/alt-linux-1.1.0.yaml` | 07 |
| `src/backend/app/packs/astra-linux-1.0.0.yaml` | 07 |
| `src/backend/app/packs/astra-linux-1.1.0.yaml` | 07 |
| `src/backend/app/packs/astra-linux-1.2.0.yaml` | 07 |
| `src/backend/app/packs/cisco-ios-1.0.0.yaml` | 07 |
| `src/backend/app/packs/cisco-ios-1.1.0.yaml` | 07 |
| `src/backend/app/packs/cisco-ios-1.2.0.yaml` | 07 |
| `src/backend/app/packs/cisco-ios-1.3.0.yaml` | 07 |
| `src/backend/app/packs/debian-server-1.0.0.yaml` | 07 |
| `src/backend/app/packs/debian-server-1.1.0.yaml` | 07 |
| `src/backend/app/packs/dionis-nx-1.0.0.yaml` | 07 |
| `src/backend/app/packs/docker-1.0.0.yaml` | 07 |
| `src/backend/app/packs/docker-1.1.0.yaml` | 07 |
| `src/backend/app/packs/docker-1.2.0.yaml` | 07 |
| `src/backend/app/packs/eltex-esr-1.0.0.yaml` | 07 |
| `src/backend/app/packs/eltex-mes-1.0.0.yaml` | 07 |
| `src/backend/app/packs/ideco-ngfw-1.0.0.yaml` | 07 |
| `src/backend/app/packs/infowatch-arma-ngfw-1.0.0.yaml` | 07 |
| `src/backend/app/packs/kontinent-4-1.0.0.yaml` | 07 |
| `src/backend/app/packs/kontinent-4-1.1.0.yaml` | 07 |
| `src/backend/app/packs/kontinent-4-local-1.0.0.yaml` | 07 |
| `src/backend/app/packs/postgresql-1.0.0.yaml` | 07 |
| `src/backend/app/packs/postgresql-1.1.0.yaml` | 07 |
| `src/backend/app/packs/pt-ngfw-1.0.0.yaml` | 07 |
| `src/backend/app/packs/pt-ngfw-settings-1.0.0.yaml` | 07 |
| `src/backend/app/packs/qtech-qsw-1.0.0.yaml` | 07 |
| `src/backend/app/packs/rhel-family-1.0.0.yaml` | 07 |
| `src/backend/app/packs/rhel-family-1.1.0.yaml` | 07 |
| `src/backend/app/packs/s-terra-gate-1.0.0.yaml` | 07 |
| `src/backend/app/packs/samba-1.0.0.yaml` | 07 |
| `src/backend/app/packs/snr-switch-1.0.0.yaml` | 07 |
| `src/backend/app/packs/ubuntu-server-1.0.0.yaml` | 07 |
| `src/backend/app/packs/ubuntu-server-1.1.0.yaml` | 07 |
| `src/backend/app/packs/ubuntu-server-1.2.0.yaml` | 07 |
| `src/backend/app/packs/ubuntu-server-1.3.0.yaml` | 07 |
| `src/backend/app/packs/ubuntu-server-1.4.0.yaml` | 07 |
| `src/backend/app/packs/usergate-ngfw-1.0.0.yaml` | 07 |
| `src/backend/app/packs/usergate-ngfw-1.1.0.yaml` | 07 |
| `src/backend/app/packs/vipnet-coordinator-1.0.0.yaml` | 07 |
| `src/backend/app/packs/windows-client-1.0.0.yaml` | 07 |
| `src/backend/app/packs/windows-dc-1.0.0.yaml` | 07 |
| `src/backend/app/packs/windows-server-1.0.0.yaml` | 07 |
| `src/backend/app/schemas/auth.py` | 01 |
| `src/backend/app/schemas/data.py` | 18 |
| `src/backend/app/schemas/ingest.py` | 06, 11 |
| `src/backend/app/services/bdu/__init__.py` | 14 |
| `src/backend/app/services/bdu/criticality.py` | 14 |
| `src/backend/app/services/bdu/importer.py` | 14 |
| `src/backend/app/services/bdu/matching.py` | 14 |
| `src/backend/app/services/bdu/products.py` | 14 |
| `src/backend/app/services/bdu/ubuntu_oval.py` | 14 |
| `src/backend/app/services/bdu/versions.py` | 14 |
| `src/backend/app/services/fstec/__init__.py` | 12 |
| `src/backend/app/services/fstec/catalog.py` | 12 |
| `src/backend/app/services/fstec/coverage.py` | 12 |
| `src/backend/app/services/hardening_engine.py` | 12 |
| `src/backend/app/services/login_guard.py` | 01 |
| `src/backend/app/services/manual_scan.py` | 10 |
| `src/backend/app/services/offline_scan.py` | 09 |
| `src/backend/app/services/packs/__init__.py` | 07 |
| `src/backend/app/services/packs/assertions.py` | 07, 12 |
| `src/backend/app/services/packs/authoring.py` | 07, 23 |
| `src/backend/app/services/packs/evaluate.py` | 07, 12 |
| `src/backend/app/services/packs/manifest.py` | 07 |
| `src/backend/app/services/packs/models.py` | 07, 08 |
| `src/backend/app/services/packs/registry.py` | 07 |
| `src/backend/app/services/remediation.py` | 12, 16 |
| `src/backend/app/services/risk_exceptions.py` | 12, 13 |
| `src/backend/app/services/snapshot_export.py` | 16 |
| `src/backend/app/services/twofa_service.py` | 01 |
| `src/backend/pack_sources/debian_family.py` | 07 |
| `src/backend/pack_sources/windows.py` | 07 |
| `src/backend/pack_tests/README.md` | 07, 23 |
| `src/backend/pack_tests/alt-linux.yaml` | 07, 23 |
| `src/backend/pack_tests/astra-linux.yaml` | 07, 23 |
| `src/backend/pack_tests/cisco-ios.yaml` | 07, 23 |
| `src/backend/pack_tests/debian-server.yaml` | 07, 23 |
| `src/backend/pack_tests/dionis-nx.yaml` | 07, 23 |
| `src/backend/pack_tests/docker.yaml` | 07, 23 |
| `src/backend/pack_tests/eltex-esr.yaml` | 07, 23 |
| `src/backend/pack_tests/eltex-mes.yaml` | 07, 23 |
| `src/backend/pack_tests/ideco-ngfw.yaml` | 07, 23 |
| `src/backend/pack_tests/infowatch-arma-ngfw.yaml` | 07, 23 |
| `src/backend/pack_tests/kontinent-4-local.yaml` | 07, 23 |
| `src/backend/pack_tests/kontinent-4.yaml` | 07, 23 |
| `src/backend/pack_tests/postgresql.yaml` | 07, 23 |
| `src/backend/pack_tests/pt-ngfw-settings.yaml` | 07, 23 |
| `src/backend/pack_tests/pt-ngfw.yaml` | 07, 23 |
| `src/backend/pack_tests/qtech-qsw.yaml` | 07, 23 |
| `src/backend/pack_tests/rhel-family.yaml` | 07, 23 |
| `src/backend/pack_tests/s-terra-gate.yaml` | 07, 23 |
| `src/backend/pack_tests/samba.yaml` | 07, 23 |
| `src/backend/pack_tests/snr-switch.yaml` | 07, 23 |
| `src/backend/pack_tests/ubuntu-server.yaml` | 07, 23 |
| `src/backend/pack_tests/usergate-ngfw.yaml` | 07, 23 |
| `src/backend/pack_tests/vipnet-coordinator.yaml` | 07, 23 |
| `src/backend/pack_tests/windows-client.yaml` | 07, 23 |
| `src/backend/pack_tests/windows-dc.yaml` | 07, 23 |
| `src/backend/pack_tests/windows-server.yaml` | 07, 23 |
| `src/backend/tests/conftest.py` | 23 |
| `src/backend/tests/test_admin_organizations.py` | 23 |
| `src/backend/tests/test_admin_users.py` | 23 |
| `src/backend/tests/test_agent_hosts.py` | 23 |
| `src/backend/tests/test_agent_interop.py` | 23 |
| `src/backend/tests/test_agent_transport.py` | 23 |
| `src/backend/tests/test_auth.py` | 23 |
| `src/backend/tests/test_bdu.py` | 23 |
| `src/backend/tests/test_continent4_offline.py` | 23 |
| `src/backend/tests/test_coverage.py` | 23 |
| `src/backend/tests/test_create_admin.py` | 23 |
| `src/backend/tests/test_exports.py` | 23 |
| `src/backend/tests/test_fstec_coverage.py` | 23 |
| `src/backend/tests/test_hardening_engine.py` | 23 |
| `src/backend/tests/test_ingest.py` | 23 |
| `src/backend/tests/test_ingest_inventory.py` | 23 |
| `src/backend/tests/test_ingest_packs.py` | 23 |
| `src/backend/tests/test_login_guard.py` | 23 |
| `src/backend/tests/test_manual_scans.py` | 23 |
| `src/backend/tests/test_network_pack_detect.py` | 23 |
| `src/backend/tests/test_offline_scans.py` | 23 |
| `src/backend/tests/test_org_scoped_data.py` | 23 |
| `src/backend/tests/test_pack_authoring.py` | 23 |
| `src/backend/tests/test_pack_command.py` | 23 |
| `src/backend/tests/test_pack_sources.py` | 23 |
| `src/backend/tests/test_packs.py` | 23 |
| `src/backend/tests/test_password_hashing.py` | 23 |
| `src/backend/tests/test_policies_and_members.py` | 23 |
| `src/backend/tests/test_rbac.py` | 23 |
| `src/backend/tests/test_risk_exceptions.py` | 23 |
| `src/backend/tests/test_snapshot_compare.py` | 23 |
| `src/backend/tests/test_stage2_packs.py` | 23 |
| `src/backend/tests/test_twofa.py` | 23 |
| `src/backend/tests/test_twofa_required.py` | 23 |
| `src/backend/tests/test_ubuntu_pack_regression.py` | 23 |
| `src/components/AgentCoverage.jsx` | 17 |
| `src/components/ChartTooltip.jsx` | 17 |
| `src/components/ComplianceChart.jsx` | 17 |
| `src/components/Layout.jsx` | 17 |
| `src/components/OrgGate.jsx` | 17 |
| `src/components/ProtectedRoute.jsx` | 17 |
| `src/components/Sidebar.jsx` | 17 |
| `src/components/Topbar.jsx` | 17 |
| `src/components/TrendChart.jsx` | 17 |
| `src/components/ui/AppCard.jsx` | 17 |
| `src/context/OrganizationContext.jsx` | 17 |
| `src/hooks/useSort.js` | 17 |
| `src/components/ui/CheckStatusBadge.jsx` | 17 |
| `src/components/ui/CopyButton.jsx` | 17 |
| `src/components/ui/EmptyState.jsx` | 17 |
| `src/components/ui/ErrorState.jsx` | 17 |
| `src/components/ui/SeverityBadge.jsx` | 17 |
| `src/components/ui/Skeleton.jsx` | 17 |
| `src/components/ui/SortableHeader.jsx` | 17 |
| `src/components/ui/StatCard.jsx` | 17 |
| `src/main.jsx` | 17 |
| `src/pages/AdminUsers.jsx` | 17 |
| `src/pages/AgentKeys.jsx` | 17 |
| `src/pages/AssetDetails.jsx` | 17 |
| `src/pages/Assets.jsx` | 17 |
| `src/pages/ChangePassword.jsx` | 17 |
| `src/pages/Dashboard.jsx` | 17 |
| `src/pages/FstecCoverage.jsx` | 17 |
| `src/pages/Hardening.jsx` | 17 |
| `src/pages/Login.jsx` | 17 |
| `src/pages/ManualScan.jsx` | 17 |
| `src/pages/OfflineScan.jsx` | 17 |
| `src/pages/OrganizationUsers.jsx` | 17 |
| `src/pages/Policies.jsx` | 17 |
| `src/pages/Report.jsx` | 17 |
| `src/pages/ScanCompare.jsx` | 17 |
| `src/pages/Scans.jsx` | 17 |
| `src/pages/SoftwareInventory.jsx` | 17 |
| `src/pages/TwoFactor.jsx` | 17 |
| `src/pages/Vulnerabilities.jsx` | 17 |
| `src/utils/clipboard.js` | 17 |
| `src/utils/collection.js` | 17 |
| `src/utils/datetime.js` | 17 |
| `src/utils/remediation.js` | 17 |
| `src/utils/roles.js` | 17 |
| `src/utils/score.js` | 17 |
| `src/utils/severity.js` | 17 |
| `src/utils/utils.test.js` | 17 |
| `tools/loadtest/ui_load.py` | 22, 23 |
| `src/backend/.env.example` | 21 |
| `docs/how-it-works/00-cheatsheet.md` | шпаргалка |
| `docs/how-it-works/27-worked-examples.md` | примеры из репозитория |

