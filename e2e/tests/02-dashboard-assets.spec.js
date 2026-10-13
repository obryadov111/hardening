// «Обзор», «Активы», карточка актива: числа совпадают с API, фильтры, поиск, сортировка, переходы, смена организации.
import { test, expect } from '@playwright/test'
import { apiAs, loginAs, seed, trackErrors } from '../helpers.js'

let errors
test.beforeEach(({ page }) => { errors = trackErrors(page) })
test.afterEach(() => expect(errors).toEqual([]))

const statValue = (page, label) =>
  page.locator('div.text-sm.text-zinc-400', { hasText: new RegExp(`^${label}$`) }).locator('xpath=following-sibling::*[1]')

test('обзор: показатели равны данным сервера', async ({ page, request }) => {
  const s = seed()
  const h = await apiAs(request, 'admin')
  const summary = await (await request.get(`/api/organizations/${s.orgs.main.id}/dashboard`, { headers: h })).json()
  await loginAs(page, 'admin')
  await page.goto('/dashboard')
  await expect(page.getByText(`Сводка по организации ${s.orgs.main.name}`)).toBeVisible()
  await expect(statValue(page, 'Активы')).toHaveText(String(summary.assetsCount))
  await expect(statValue(page, 'ПО')).toHaveText(String(summary.softwareCount))
  await expect(statValue(page, 'Проверки')).toHaveText(String(summary.checksCount))
  await expect(statValue(page, 'Нарушения')).toHaveText(String(summary.failedChecks))
  expect(summary.notEvaluatedChecks).toBeGreaterThan(0)  // засев: у db-01 проверки ОС «не проверено»
  await expect(page.getByText(new RegExp(`${summary.notEvaluatedChecks} из ${summary.checksCount} проверок не выполнены`))).toBeVisible()
  await expect(page.getByText(`Покрытие: ${Math.round(summary.coverage)}%`)).toBeVisible()
  // доля соблюдённых среди выполненных — на круговой диаграмме
  const pct = Math.round((summary.passedChecks / (summary.passedChecks + summary.failedChecks)) * 100)
  await expect(page.getByText(`${pct}%`).first()).toBeVisible()
  // динамика: точка на каждый день с отчётами (последний отчёт дня)
  const daily = await (await request.get(`/api/organizations/${s.orgs.main.id}/reports?daily=true&limit=30`, { headers: h })).json()
  expect(daily.length).toBeGreaterThan(1)
  expect(daily.length).toBeLessThan(summary.reportsCount)  // засев: два отчёта в один день
  await expect(page.locator('.recharts-line-dot, .recharts-dot')).toHaveCount(daily.length)
  // последний отчёт
  await expect(page.getByRole('heading', { name: 'Последний отчёт' })).toBeVisible()
})

test('обзор: другая организация без данных — пустое состояние; переключатель запоминает выбор', async ({ page }) => {
  const s = seed()
  await loginAs(page, 'super')
  await page.goto('/dashboard')
  const selector = page.getByLabel('Организация')
  await expect(selector.locator('option')).toHaveText([s.orgs.main.name, s.orgs.other.name].sort((a, b) => a.localeCompare(b, 'ru')))
  await selector.selectOption({ label: s.orgs.other.name })
  await expect(page.getByText('Нет данных по организации')).toBeVisible()
  await expect(page.getByText(`Текущая организация: ${s.orgs.other.name}`)).toBeVisible()
  await page.reload()
  await expect(page.getByText(`Текущая организация: ${s.orgs.other.name}`)).toBeVisible()
  await selector.selectOption({ label: s.orgs.main.name })
  await expect(page.getByText('Нет данных по организации')).toHaveCount(0)
})

test('пользователь видит только свои организации', async ({ page }) => {
  const s = seed()
  await loginAs(page, 'beta', { org: null })
  await page.goto('/dashboard')
  await expect(page.getByLabel('Организация').locator('option')).toHaveText([s.orgs.other.name])
})

test('сбой API на обзоре — ошибка, а не «нет данных»', async ({ page }) => {
  await loginAs(page, 'admin')
  await page.route((u) => u.pathname.startsWith('/api/') && u.pathname.endsWith('/dashboard'), (r) => r.fulfill({ status: 500, json: { detail: 'Сбой для теста' } }))
  await page.goto('/dashboard')
  await expect(page.getByText('Ошибка загрузки')).toBeVisible()
  await expect(page.getByText('Сбой для теста')).toBeVisible()
  await expect(page.getByText('Нет данных по организации')).toHaveCount(0)
  errors.length = 0
})

test('активы: таблица, карточки контуров, поиск, сортировка, «Обновить»', async ({ page, request }) => {
  const s = seed()
  const h = await apiAs(request, 'admin')
  const assets = await (await request.get(`/api/organizations/${s.orgs.main.id}/assets`, { headers: h })).json()
  await loginAs(page, 'admin')
  await page.goto('/assets')
  const rows = page.locator('tbody tr')
  await expect(rows).toHaveCount(assets.length)
  await expect(page.getByText(`Всего активов: ${assets.length}`)).toBeVisible()

  // строка web-01: значения из API, уровень по-русски
  const web = assets.find((a) => a.hostname === 'web-01')
  const webRow = rows.filter({ hasText: 'web-01' })
  await expect(webRow).toContainText(web.ip_address)
  await expect(webRow).toContainText('критический')
  await expect(webRow).toContainText(String(web.software_count))

  // карточка «Все среды» и контур prod: клик — фильтр, повторный — снимает
  const all = page.getByRole('button', { name: /Все среды/ })
  await expect(all).toHaveAttribute('aria-pressed', 'true')
  const prod = page.getByRole('button', { name: /^prod/ })
  await prod.click()
  await expect(prod).toHaveAttribute('aria-pressed', 'true')
  await expect(rows).toHaveCount(assets.length)
  await prod.click()
  await expect(all).toHaveAttribute('aria-pressed', 'true')

  // поиск: по имени, IP, ОС, без учёта регистра; ничего не найдено
  const search = page.getByPlaceholder('Поиск по имени хоста, IP, ОС...')
  await search.fill('WEB')
  await expect(rows).toHaveCount(1)
  await search.fill('10.10.0.21')
  await expect(rows).toHaveCount(1)
  await expect(rows.first()).toContainText('win-srv-01')
  await search.fill('windows')
  await expect(rows).toHaveCount(1)
  await search.fill('нет-такого')
  await expect(page.getByText('Под фильтр не попал ни один актив.')).toBeVisible()
  await search.fill('')

  // сортировка: по имени (asc/desc), по критичности — по уровню, а не по алфавиту
  const names = () => rows.locator('td:first-child').allTextContents()
  const byName = page.getByRole('button', { name: 'Имя хоста' })
  await byName.click()
  await expect(page.locator('th', { has: byName })).toHaveAttribute('aria-sort', 'ascending')
  expect((await names()).map((t) => t.trim())).toEqual(['db-01', 'web-01', 'win-srv-01'])
  await byName.click()
  await expect(page.locator('th', { has: byName })).toHaveAttribute('aria-sort', 'descending')
  expect((await names()).map((t) => t.trim())).toEqual(['win-srv-01', 'web-01', 'db-01'])
  await page.getByRole('button', { name: 'Критичность' }).click()
  expect((await names()).map((t) => t.trim())).toEqual(['win-srv-01', 'db-01', 'web-01'])  // средний < высокий < критический
  // клавиатура: заголовок — кнопка
  await page.getByRole('button', { name: 'Нарушений' }).focus()
  await page.keyboard.press('Enter')
  await expect(page.locator('th', { has: page.getByRole('button', { name: 'Нарушений' }) })).toHaveAttribute('aria-sort', 'ascending')

  const reload = page.waitForResponse((r) => r.url().includes(`/organizations/${s.orgs.main.id}/assets`))
  await page.getByRole('button', { name: 'Обновить' }).click()
  await reload
  await expect(rows).toHaveCount(assets.length)
})

test('карточка актива: ПО и проверки из API, «Назад к активам», несуществующий актив', async ({ page, request }) => {
  const s = seed()
  const h = await apiAs(request, 'viewer')
  const assets = await (await request.get(`/api/organizations/${s.orgs.main.id}/assets`, { headers: h })).json()
  const web = assets.find((a) => a.hostname === 'web-01')
  const detail = await (await request.get(`/api/assets/${web.id}`, { headers: h })).json()
  await loginAs(page, 'viewer')
  await page.goto('/assets')
  await page.getByRole('link', { name: 'web-01' }).click()
  await expect(page).toHaveURL(new RegExp(`/assets/${web.id}$`))
  await expect(page.getByRole('heading', { name: 'web-01' })).toBeVisible()
  await expect(statValue(page, 'IP-адрес')).toHaveText(web.ip_address)
  await expect(statValue(page, 'Единиц ПО')).toHaveText(String(detail.software_count))
  await expect(statValue(page, 'Проваленных проверок')).toHaveText(String(detail.failed_checks_count))
  const software = page.locator('table').first().locator('tbody tr')
  await expect(software).toHaveCount(detail.software.length)
  await expect(software.filter({ hasText: 'openssh-server' })).toContainText('1:9.6p1-3ubuntu13.19')
  const checks = page.locator('table').nth(1).locator('tbody tr')
  await expect(checks).toHaveCount(detail.checks.length)
  await expect(checks.first()).toContainText(/соблюдено|нарушено|не проверено/)

  // прямой переход по адресу и перезагрузка карточки работают (в проде nginx отдаёт index.html)
  await page.reload()
  await expect(page.getByRole('heading', { name: 'web-01' })).toBeVisible()
  await page.getByRole('link', { name: /Назад к активам|К списку активов|←/ }).click()
  await expect(page).toHaveURL(/\/assets$/)

  await page.goto('/assets/00000000-0000-0000-0000-000000000000')
  await expect(page.getByText('Ошибка загрузки актива')).toBeVisible()
  await expect(page.getByText('Актив не найден')).toBeVisible()
  errors.length = 0  // 404 ожидаем
})

test('чужой актив по прямой ссылке недоступен', async ({ page, request }) => {
  const s = seed()
  const h = await apiAs(request, 'admin')
  const assets = await (await request.get(`/api/organizations/${s.orgs.main.id}/assets`, { headers: h })).json()
  await loginAs(page, 'beta', { org: 'other' })
  await page.goto(`/assets/${assets[0].id}`)
  await expect(page.getByText('Нет доступа к этому активу')).toBeVisible()
  await expect(page.getByText(assets[0].hostname, { exact: true })).toHaveCount(0)
})
