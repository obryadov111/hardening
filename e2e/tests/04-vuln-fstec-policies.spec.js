// «Уязвимости ПО» (БДУ), «Методика ФСТЭК», «Политики».
import { test, expect } from '@playwright/test'
import { apiAs, loginAs, seed, trackErrors } from '../helpers.js'

let errors
test.beforeEach(({ page }) => { errors = trackErrors(page) })
test.afterEach(() => expect(errors).toEqual([]))

const statValue = (page, label) =>
  page.locator('div.text-sm.text-zinc-400', { hasText: new RegExp(`^${label}$`) }).locator('xpath=following-sibling::*[1]')

test('уязвимости: находка OpenSSH по засеянной БДУ, ссылки, фильтры, поиск', async ({ page, request }) => {
  const s = seed()
  const h = await apiAs(request, 'viewer')
  const data = await (await request.get(`/api/organizations/${s.orgs.main.id}/vulnerabilities`, { headers: h })).json()
  expect(data.items.length).toBeGreaterThan(0)
  await loginAs(page, 'viewer')
  await page.goto('/vulnerabilities')
  await expect(page.getByText(/Копия БДУ: загружена .*, уязвимостей — 2/)).toBeVisible()
  for (const [key, label] of [['critical', 'Критический'], ['high', 'Высокий'], ['medium', 'Средний'], ['low', 'Низкий']]) {
    await expect(statValue(page, label)).toHaveText(String(data.summary[key]))
  }
  const rows = page.locator('tbody tr')
  await expect(rows).toHaveCount(data.items.length)
  const link = page.getByRole('link', { name: 'BDU:2024-04914' }).first()
  await expect(link).toHaveAttribute('href', 'https://bdu.fstec.ru/vul/2024-04914')
  await expect(link).toHaveAttribute('target', '_blank')
  await expect(rows.first()).toContainText('CVE-2024-6387')
  await expect(rows.first()).toContainText('openssh')
  // уязвимость «до 7.4» к 9.6 не относится
  await expect(page.getByText('BDU:2019-00001')).toHaveCount(0)

  await page.getByLabel('Поиск уязвимостей').fill('db-01')
  await expect(rows).toHaveCount(data.items.filter((i) => i.asset.hostname === 'db-01').length)
  await page.getByLabel('Поиск уязвимостей').fill('нет-такой')
  await expect(page.getByText('По выбранным условиям ничего не найдено.')).toBeVisible()
  await page.getByLabel('Поиск уязвимостей').fill('')
  await page.getByLabel('Уровень').selectOption('low')
  await expect(rows).toHaveCount(data.items.filter((i) => i.level === 'low').length)
  await page.getByLabel('Уровень').selectOption('')
  await page.getByLabel('Статус в Ubuntu').selectOption('all')
  await expect(page.getByText(`Найдено: ${data.items.length}`)).toBeVisible()
})

test('уязвимости: организация без ПО — пустое состояние', async ({ page }) => {
  await loginAs(page, 'beta', { org: 'other' })
  await page.goto('/vulnerabilities')
  await expect(page.getByText('Нет потенциальных уязвимостей')).toBeVisible()
})

test('методика ФСТЭК: плитки по статусам, фильтр, раскрытие проверок, переход к уязвимостям', async ({ page, request }) => {
  const s = seed()
  const h = await apiAs(request, 'viewer')
  const data = await (await request.get(`/api/organizations/${s.orgs.main.id}/fstec-coverage`, { headers: h })).json()
  await loginAs(page, 'viewer')
  await page.goto('/fstec')
  await expect(statValue(page, 'нарушено')).toHaveText(String(data.summary.violated))
  await expect(statValue(page, 'соблюдено')).toHaveText(String(data.summary.passed))
  const all = data.sections.reduce((n, sec) => n + sec.items.length, 0)
  await expect(page.locator('tbody tr')).toHaveCount(all)

  await page.getByLabel('Статус пункта').selectOption('violated')
  await expect(page.locator('tbody tr')).toHaveCount(data.summary.violated)
  await expect(page.locator('tbody tr').first()).toContainText('нарушено')
  const details = page.locator('tbody tr details').first()
  await expect(details.locator('li').first()).toBeHidden()
  await details.locator('summary').click()
  await expect(details.locator('li').first()).toBeVisible()

  await page.getByLabel('Статус пункта').selectOption('')
  const bdu = page.getByRole('link', { name: 'к уязвимостям ПО' }).first()
  if (await bdu.count()) {
    await bdu.click()
    await expect(page).toHaveURL(/\/vulnerabilities$/)
  }
})

test('политики: админ создаёт, меняет статус, удаляет (с подтверждением); пустое название — ошибка', async ({ page }) => {
  await loginAs(page, 'admin')
  await page.goto('/policies')
  await expect(page.getByText('Нет политик')).toBeVisible()
  const total = statValue(page, 'Всего политик')
  await expect(total).toHaveText('0')

  await page.getByRole('button', { name: 'Добавить' }).click()
  await expect(page.getByText('Введите название политики')).toBeVisible()

  await page.getByPlaceholder('Название *').fill('E2E: парольная политика')
  await page.getByPlaceholder('Область применения').fill('серверы Linux')
  await page.getByPlaceholder('Владелец').fill('Отдел ИБ')
  await page.getByPlaceholder('Источник (например, методика ФСТЭК от 25.11.2025)').fill('ГОСТ Р 57580')
  await page.getByPlaceholder('Описание').fill('Длина пароля от 14 символов')
  await page.getByLabel('Статус', { exact: true }).selectOption({ label: 'Активна' })
  await page.getByRole('button', { name: 'Добавить' }).click()
  const card = page.locator('div.rounded-2xl', { hasText: 'E2E: парольная политика' }).last()
  await expect(card).toContainText('серверы Linux')
  await expect(card).toContainText('Отдел ИБ')
  await expect(card).toContainText('ГОСТ Р 57580')
  await expect(card).toContainText('Длина пароля от 14 символов')
  await expect(total).toHaveText('1')
  await expect(statValue(page, 'Активные')).toHaveText('1')
  await expect(page.getByPlaceholder('Название *')).toHaveValue('')  // форма очищена

  await card.getByLabel('Статус политики').selectOption('review')
  await expect(statValue(page, 'На пересмотре')).toHaveText('1')
  await expect(statValue(page, 'Активные')).toHaveText('0')

  page.once('dialog', (d) => d.dismiss())
  await card.getByRole('button', { name: /Удалить/ }).click()
  await expect(total).toHaveText('1')
  page.once('dialog', (d) => { expect(d.message()).toBe('Удалить политику «E2E: парольная политика»?'); d.accept() })
  await card.getByRole('button', { name: /Удалить/ }).click()
  await expect(total).toHaveText('0')
  await expect(page.getByText('Нет политик')).toBeVisible()
})

for (const role of ['viewer', 'auditor']) {
  test(`политики: ${role} видит, но не меняет`, async ({ page, request }) => {
    const s = seed()
    const admin = await apiAs(request, 'admin')
    const created = await (await request.post(`/api/organizations/${s.orgs.main.id}/policies`, {
      headers: admin, data: { name: `E2E: только чтение ${role}`, status: 'active' },
    })).json()
    await loginAs(page, role)
    await page.goto('/policies')
    await expect(page.getByText(`E2E: только чтение ${role}`)).toBeVisible()
    await expect(page.getByText('Активна')).toBeVisible()
    await expect(page.getByRole('heading', { name: 'Добавить политику' })).toHaveCount(0)
    await expect(page.getByLabel('Статус политики')).toHaveCount(0)
    await expect(page.getByRole('button', { name: /Удалить/ })).toHaveCount(0)
    await request.delete(`/api/organizations/${s.orgs.main.id}/policies/${created.id}`, { headers: admin })
  })
}
