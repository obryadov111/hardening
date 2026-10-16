// «Проверка по опросу»: оборудование без машиночитаемой конфигурации (Континент 4) — ответы аудитора становятся снимком.
import { test, expect } from '@playwright/test'
import { loginAs, trackErrors } from '../helpers.js'

let errors
test.beforeEach(({ page }) => { errors = trackErrors(page) })
test.afterEach(() => expect(errors).toEqual([]))

test('опрос: наблюдатель видит вопросы, но не сохраняет', async ({ page }) => {
  await loginAs(page, 'viewer')
  await page.goto('/manual-scan')
  await expect(page.getByText('Сохранять ответы может только администратор организации.')).toBeVisible()
  await page.getByRole('button', { name: /^kontinent-4/ }).click()
  await expect(page.getByText(/Пароль доступа к локальному меню/).first()).toBeVisible()
  await expect(page.getByRole('button', { name: 'Сохранить ответы' })).toBeDisabled()
})

test('опрос: Континент 4 — ответы, подтверждение и версия, снимок «по опросу»', async ({ page }) => {
  await loginAs(page, 'admin')
  await page.goto('/manual-scan')
  await page.getByRole('button', { name: /^kontinent-4/ }).click()
  await expect(page.getByRole('button', { name: /^kontinent-4/ })).toHaveAttribute('aria-pressed', 'true')
  const submit = page.getByRole('button', { name: 'Сохранить ответы' })
  await expect(submit).toBeDisabled()  // нет ни ответов, ни имени устройства

  const loader = page.getByRole('radiogroup', { name: /Пароль доступа к локальному меню/ })
  await loader.getByRole('radio', { name: 'Нет' }).click()
  await expect(loader.getByRole('radio', { name: 'Нет' })).toHaveAttribute('aria-checked', 'true')
  await page.getByLabel(/^Подтверждение: Пароль доступа к локальному меню/).fill('ЛМ УБ-01, после обновления до 4.2.1')
  await page.getByRole('radiogroup', { name: /Пароль BIOS/ }).getByRole('radio', { name: 'Да' }).click()
  await page.getByLabel(/^Ответ: Минимальная длина пароля/).fill('12')
  await page.getByLabel(/^Ответ: SSH-доступ к локальному меню/).selectOption('включён без ограничения адресов')
  await expect(page.getByText('Отвечено 4 из 9')).toBeVisible()

  await page.getByPlaceholder('ub-msk-01').fill('ub-e2e-01')
  await page.getByPlaceholder('4.2.1').fill('4.2.1')
  await page.getByPlaceholder('опрос от 16.10').fill('E2E опрос')
  await expect(submit).toBeEnabled()
  await submit.click()
  // 9 вопросов: 4 отвечены (2 соблюдено, 2 нарушения), 5 без ответа — «не проверено»
  await expect(page.getByText('Снимок создан: проверок 9, соблюдено 2, нарушений 2, не проверено 5')).toBeVisible()

  await page.getByRole('link', { name: 'Открыть сканирования' }).click()
  const row = page.locator('tbody tr').first()
  await expect(row).toContainText('E2E опрос')
  await expect(row).toContainText('ub-e2e-01')
  await expect(row).toContainText(/по опросу/i)
})

test('опрос: неверный ответ — ошибка сервера видна', async ({ page }) => {
  await loginAs(page, 'admin')
  await page.goto('/manual-scan')
  await page.getByRole('button', { name: /^kontinent-4/ }).click()
  await page.getByLabel(/^Ответ: Минимальная длина пароля/).fill('восемь')
  await page.getByPlaceholder('ub-msk-01').fill('ub-e2e-02')
  await page.getByRole('button', { name: 'Сохранить ответы' }).click()
  await expect(page.getByText(/ожидалось число/)).toBeVisible()
})
