// Общие помощники сквозных тестов: данные засева, вход под ролью, сбор ошибок страницы.
import crypto from 'node:crypto'
import { expect } from '@playwright/test'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
export const seed = () => JSON.parse(fs.readFileSync(path.join(here, '.state/seed.json'), 'utf-8'))

/** Токен через API (вход через форму проверяет auth.spec.js) — в localStorage до загрузки приложения. */
export async function loginAs(page, role, { org = 'main' } = {}) {
  const s = seed()
  const resp = await page.request.post('/api/auth/login', { data: { email: s.users[role], password: s.password } })
  expect(resp.ok(), `вход ${role}: ${resp.status()}`).toBeTruthy()
  const { access_token: token } = await resp.json()
  const orgId = org ? s.orgs[org].id : null
  await page.addInitScript(([t, o]) => {
    if (!sessionStorage.getItem('e2e_init')) {  // только при первой загрузке: тест может выйти или сменить организацию
      sessionStorage.setItem('e2e_init', '1')
      localStorage.setItem('hardening_access_token', t)
      if (o) localStorage.setItem('selected_organization_id', o)
    }
  }, [token, orgId])
  return token
}

/** Ошибки и предупреждения JS и ответы API 5xx за время теста — тест падает, если они были (afterEach в каждом файле). */
export function trackErrors(page) {
  const errors = []
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`))
  // Предупреждения консоли — тоже ошибка (React о ключах, Recharts о размерах): консоль должна быть чистой.
  page.on('console', (m) => {
    if (['error', 'warning'].includes(m.type()) && !/Failed to load resource/.test(m.text())) errors.push(`console: ${m.text()}`)
  })
  page.on('response', (r) => { if (r.url().includes('/api/') && r.status() >= 500) errors.push(`${r.status()} ${r.request().method()} ${r.url()}`) })
  return errors
}

export async function apiAs(request, role) {
  const s = seed()
  const resp = await request.post('/api/auth/login', { data: { email: s.users[role], password: s.password } })
  const { access_token: token } = await resp.json()
  return { Authorization: `Bearer ${token}` }
}

/** TOTP (RFC 6238, SHA-1, 6 цифр, 30 с) — как в приложении-аутентификаторе. */
export function totp(secretBase32, at = Date.now()) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  let bits = ''
  for (const ch of secretBase32.replace(/=+$/, '').toUpperCase()) bits += alphabet.indexOf(ch).toString(2).padStart(5, '0')
  const key = Buffer.from(bits.match(/.{8}/g).map((b) => parseInt(b, 2)))
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(Math.floor(at / 1000 / 30)))
  const hmac = crypto.createHmac('sha1', key).update(counter).digest()
  const offset = hmac[hmac.length - 1] & 0xf
  return String((hmac.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, '0')
}

/** Сервер принимает код один раз за интервал: следующий вход с кодом — после смены интервала. */
export async function nextTotpWindow() {
  const msLeft = 30_000 - (Date.now() % 30_000)
  await new Promise((r) => setTimeout(r, msLeft + 300))
}

/** Новый пользователь через API суперадмина; сразу меняет временный пароль, если не нужно иное. */
export async function createUser(request, { email, org = 'main', role = 'viewer', keepTemporary = false, password = 'Temp-password-123' }) {
  const s = seed()
  const su = await apiAs(request, 'super')
  const resp = await request.post('/api/admin/users', {
    headers: su, data: { email, password, organization_id: org ? s.orgs[org].id : null, role },
  })
  expect(resp.status(), await resp.text()).toBe(201)
  const user = await resp.json()
  let finalPassword = password
  if (!keepTemporary) {
    const login = await request.post('/api/auth/login', { data: { email, password } })
    const token = (await login.json()).access_token
    finalPassword = `${password}-own`
    const ch = await request.post('/api/auth/change-password', {
      headers: { Authorization: `Bearer ${token}` }, data: { current_password: password, new_password: finalPassword },
    })
    expect(ch.ok(), await ch.text()).toBeTruthy()
  }
  return { id: user.id, email, password: finalPassword }
}

export const unique = (prefix) => `${prefix}-${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}@e2e.example.com`
