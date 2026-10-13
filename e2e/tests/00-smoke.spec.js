// Каждая страница открывается под каждой ролью: без ошибок JS, без 5xx от API, без «Ошибка загрузки».
import { test, expect } from '@playwright/test'
import { loginAs, trackErrors } from '../helpers.js'

const PAGES = [
  ['/dashboard', 'Обзор'],
  ['/assets', 'Активы'],
  ['/software', 'Инвентаризация ПО'],
  ['/hardening', 'Харденинг'],
  ['/vulnerabilities', 'Уязвимости'],
  ['/fstec', 'ФСТЭК'],
  ['/policies', 'Политики'],
  ['/report', 'Отчёт'],
  ['/scans', 'Сканирования'],
  ['/offline-scan', 'выгрузке'],
  ['/agents', 'Агенты'],
  ['/scan-compare', 'Сравнение'],
  ['/organization-users', 'Управление доступом'],
  ['/change-password', 'Смена пароля'],
  ['/two-factor', 'двухфакторн'],
]

for (const role of ['super', 'admin', 'auditor', 'viewer']) {
  test.describe(`роль ${role}`, () => {
    for (const [url, heading] of PAGES) {
      test(`${url}`, async ({ page }) => {
        const errors = trackErrors(page)
        await loginAs(page, role)
        await page.goto(url)
        await expect(page.getByRole('heading', { name: new RegExp(heading, 'i') }).first()).toBeVisible()
        await page.waitForLoadState('networkidle')
        await expect(page.getByText(/Ошибка загрузки|Не удалось загрузить|Something went wrong/i)).toHaveCount(0)
        expect(errors).toEqual([])
      })
    }
  })
}

test('суперадмин: /admin/users', async ({ page }) => {
  const errors = trackErrors(page)
  await loginAs(page, 'super')
  await page.goto('/admin/users')
  await expect(page.getByRole('heading').first()).toBeVisible()
  await page.waitForLoadState('networkidle')
  expect(errors).toEqual([])
})
