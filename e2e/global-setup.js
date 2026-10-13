// Перед прогоном: миграции одноразовой БД и засев (e2e/seed.py) — данные стенда в e2e/.state/seed.json.
import { execFileSync } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { backendEnv } from './playwright.config.js'

const here = path.dirname(fileURLToPath(import.meta.url))
const backend = path.resolve(here, '../src/backend')
const PYTHON = process.env.E2E_PYTHON || path.join(backend, '.venv/bin/python')

export default function globalSetup() {
  if (!backendEnv.DATABASE_URL) throw new Error('E2E_DATABASE_URL не задан: нужен одноразовый PostgreSQL (БД стирается)')
  fs.mkdirSync(path.join(here, '.state'), { recursive: true })
  const env = { ...process.env, ...backendEnv }
  // alembic.ini лежит в src/backend; .env прода alembic не читает — DATABASE_URL берётся из окружения.
  execFileSync(PYTHON, ['-m', 'alembic', 'upgrade', 'head'], { cwd: backend, env, stdio: 'inherit' })
  execFileSync(PYTHON, [path.join(here, 'seed.py'), path.join(here, '.state/seed.json')], { cwd: here, env, stdio: 'inherit' })
}
