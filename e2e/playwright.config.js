// Сквозные тесты интерфейса: настоящий бэкенд на одноразовой БД + Vite, браузер Chromium.
//
//   E2E_DATABASE_URL=postgresql+psycopg://postgres:postgres@localhost:5433/app_test_db npm run test:e2e
//
// БД стирается и засевается заново (e2e/seed.py) перед каждым прогоном — только одноразовый PostgreSQL.
// Бэкенд запускается из каталога e2e/: src/backend/.env (настройки прода) не подхватывается.
import { defineConfig, devices } from '@playwright/test'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const root = path.resolve(here, '..')
const BACKEND_PORT = Number(process.env.E2E_BACKEND_PORT || 8011)
const WEB_PORT = Number(process.env.E2E_WEB_PORT || 5174)
// Второй бэкенд на той же БД, но с обязательной 2FA, как на проде: тест forced-2fa ходит в него через page.route.
export const STRICT_BACKEND_PORT = Number(process.env.E2E_STRICT_BACKEND_PORT || 8012)
const PYTHON = process.env.E2E_PYTHON || path.join(root, 'src/backend/.venv/bin/python')

export const backendEnv = {
  DATABASE_URL: process.env.E2E_DATABASE_URL || '',
  JWT_SECRET_KEY: 'e2e-secret-key',
  TOTP_SECRET_ENCRYPTION_KEY: 'e2e-totp-encryption-key',
  PACK_SIGNING_KEY: 'e2e-pack-signing-key',
  REQUIRE_2FA: 'false',
  DISPLAY_TIMEZONE: 'Asia/Yekaterinburg',
}

export default defineConfig({
  testDir: './tests',
  globalSetup: './global-setup.js',
  // Тесты меняют общие данные стенда (пользователи, ключи, политики) — по одному, в заданном порядке.
  workers: 1,
  fullyParallel: false,
  retries: process.env.CI ? 1 : 0,
  timeout: 30_000,
  expect: { timeout: 7_000 },
  reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : 'list',
  outputDir: './test-results',
  use: {
    baseURL: `http://127.0.0.1:${WEB_PORT}`,
    locale: 'ru-RU',
    timezoneId: 'Asia/Yekaterinburg',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    acceptDownloads: true,
    ...devices['Desktop Chrome'],
    viewport: { width: 1440, height: 900 },
  },
  webServer: [
    {
      command: `${PYTHON} -m uvicorn app.main:app --app-dir ${path.join(root, 'src/backend')} --host 127.0.0.1 --port ${BACKEND_PORT}`,
      cwd: here,
      env: { ...process.env, ...backendEnv },
      url: `http://127.0.0.1:${BACKEND_PORT}/health`,
      reuseExistingServer: false,
      timeout: 60_000,
    },
    {
      command: `${PYTHON} -m uvicorn app.main:app --app-dir ${path.join(root, 'src/backend')} --host 127.0.0.1 --port ${STRICT_BACKEND_PORT}`,
      cwd: here,
      env: { ...process.env, ...backendEnv, REQUIRE_2FA: 'true' },
      url: `http://127.0.0.1:${STRICT_BACKEND_PORT}/health`,
      reuseExistingServer: false,
      timeout: 60_000,
    },
    {
      command: `npx vite --host 127.0.0.1 --port ${WEB_PORT} --strictPort`,
      cwd: root,
      env: { ...process.env, VITE_API_PROXY: `http://127.0.0.1:${BACKEND_PORT}` },
      url: `http://127.0.0.1:${WEB_PORT}/login`,
      reuseExistingServer: false,
      timeout: 60_000,
    },
  ],
})
