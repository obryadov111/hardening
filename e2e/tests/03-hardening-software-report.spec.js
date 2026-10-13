// «Харденинг» (фильтры, сортировка, страницы, принятие и отзыв риска), «Инвентаризация ПО», «Отчёты».
import { test, expect } from '@playwright/test'
import { apiAs, loginAs, seed, trackErrors } from '../helpers.js'

let errors
test.beforeEach(({ page }) => { errors = trackErrors(page) })
test.afterEach(() => expect(errors).toEqual([]))

const statValue = (page, label) =>
  page.locator('div.text-sm.text-zinc-400', { hasText: new RegExp(`^${label}$`) }).locator('xpath=following-sibling::*[1]')

async function hardeningApi(request, role, params = '') {
  const s = seed()
  const h = await apiAs(request, role)
  return (await request.get(`/api/organizations/${s.orgs.main.id}/hardening?limit=500${params}`, { headers: h })).json()
}

test('харденинг: плитки равны сводке сервера, по умолчанию сначала срочное', async ({ page, request }) => {
  const body = await hardeningApi(request, 'viewer')
  await loginAs(page, 'viewer')
  await page.goto('/hardening')
  for (const [label, key] of [['Всего проверок', 'total'], ['Соблюдено', 'passed'], ['Нарушено', 'failed'],
    ['Риск принят', 'accepted'], ['Обязательно к устранению', 'mandatory']]) {
    await expect(statValue(page, label)).toHaveText(String(body.summary[key]))
  }
  const rows = page.locator('tbody tr')
  await expect(rows).toHaveCount(Math.min(body.total, 100))
  await expect(rows.first()).toContainText('критический')
  await expect(rows.first()).toContainText('нарушено')
  await expect(rows.first()).toContainText('до 24 часов')
  // у наблюдателя нет «принять риск»
  await expect(page.getByRole('button', { name: 'принять риск' })).toHaveCount(0)
})

test('харденинг: фильтры статуса, уровня, хоста и поиск — как на сервере', async ({ page, request }) => {
  await loginAs(page, 'viewer')
  await page.goto('/hardening')
  const rows = page.locator('table').first().locator('tbody tr')
  const counter = page.getByText(/^(Найдено|Всего): /)

  for (const [status, label] of [['fail', 'Нарушено'], ['pass', 'Соблюдено'], ['error', 'Не проверено']]) {
    const expected = await hardeningApi(request, 'viewer', `&status=${status}`)
    await page.getByLabel('Статус').selectOption({ label })
    await expect(counter).toContainText(`Найдено: ${expected.total} из`)
    await expect(rows).toHaveCount(Math.min(expected.total, 100))
    if (expected.total) await expect(rows.first()).toContainText(label.toLowerCase())
  }
  await page.getByLabel('Статус').selectOption({ label: 'Все статусы' })

  const crit = await hardeningApi(request, 'viewer', '&severity=critical')
  await page.getByLabel('Уровень').selectOption({ label: 'Критический' })
  await expect(rows).toHaveCount(crit.total)
  await page.getByLabel('Уровень').selectOption({ label: 'Все уровни' })

  const win = await hardeningApi(request, 'viewer', '&host=win-srv-01')
  await page.getByLabel('Хост').selectOption('win-srv-01')
  await expect(counter).toContainText(`Найдено: ${win.total} из`)
  await expect(rows.filter({ hasNotText: 'win-srv-01' })).toHaveCount(0)
  await page.getByLabel('Хост').selectOption('')

  await page.getByLabel('Поиск проверок').fill('ssh.permit_root')
  const ssh = await hardeningApi(request, 'viewer', '&q=ssh.permit_root')
  await expect(counter).toContainText(`Найдено: ${ssh.total} из`)
  await page.getByLabel('Поиск проверок').fill('нет-такой-проверки')
  await expect(page.getByText('Под фильтр не попала ни одна проверка.')).toBeVisible()
})

test('харденинг: сортировка по колонкам и страницы', async ({ page }) => {
  await loginAs(page, 'viewer')
  await page.goto('/hardening')
  const rows = page.locator('table').first().locator('tbody tr')
  await page.getByRole('button', { name: 'Актив' }).click()
  await expect(rows.first().locator('td').first()).toHaveText('db-01')
  await page.getByRole('button', { name: 'Актив' }).click()
  await expect(rows.first().locator('td').first()).toHaveText('win-srv-01')
  await page.getByRole('button', { name: 'Уровень' }).click()
  await page.getByRole('button', { name: 'Уровень' }).click()
  await expect(rows.first()).toContainText('критический')
  // страницы: в засеве больше 100 проверок
  await expect(page.getByText(/^1–100 из \d+$/)).toBeVisible()
  await expect(page.getByRole('button', { name: 'Назад' })).toBeDisabled()
  await page.getByRole('button', { name: 'Вперёд' }).click()
  await expect(page.getByText(/^101–\d+ из \d+$/)).toBeVisible()
  await expect(page.getByRole('button', { name: 'Вперёд' })).toBeDisabled()
  await page.getByRole('button', { name: 'Назад' }).click()
  await expect(page.getByText(/^1–100 из \d+$/)).toBeVisible()
})

test('принятие риска: форма, обязательное обоснование, «Отмена», принять, отозвать, история', async ({ page, request }) => {
  await loginAs(page, 'admin')
  await page.goto('/hardening')
  await page.getByLabel('Хост').selectOption('win-srv-01')
  await page.getByLabel('Статус').selectOption({ label: 'Нарушено' })
  const rows = page.locator('table').first().locator('tbody tr')
  const first = rows.first()
  const code = (await first.locator('td').nth(1).locator('.text-xs').first().textContent()).trim()
  const before = await hardeningApi(request, 'admin')

  const acceptButton = first.getByRole('button', { name: 'принять риск' })
  await acceptButton.click()
  await expect(acceptButton).toHaveAttribute('aria-expanded', 'true')
  await expect(page.getByText(`(${code})`)).toBeVisible()
  await page.getByRole('button', { name: 'Отмена' }).click()
  await expect(page.getByLabel('Обоснование')).toHaveCount(0)

  await acceptButton.click()
  await page.getByRole('button', { name: 'Принять риск', exact: true }).click()  // пустое обоснование — браузер не отправит
  await expect(page.getByLabel('Обоснование')).toBeVisible()
  await page.getByLabel('Обоснование').fill('E2E: компенсирующая мера — доступ только из сегмента администрирования')
  await expect(page.getByLabel('Область')).toHaveValue('asset')
  await page.getByRole('button', { name: 'Принять риск', exact: true }).click()
  await expect(page.getByLabel('Обоснование')).toHaveCount(0)

  // нарушение ушло из «Нарушено» в «Риск принят»; плитки пересчитаны
  await expect(statValue(page, 'Риск принят')).toHaveText(String(before.summary.accepted + 1))
  await expect(statValue(page, 'Нарушено')).toHaveText(String(before.summary.failed - 1))
  const register = page.locator('table').nth(1)
  const registered = register.locator('tbody tr', { hasText: code })
  await expect(registered).toContainText('win-srv-01')
  await expect(registered).toContainText('Действует')
  await expect(registered).toContainText('бессрочно')
  await expect(registered).toContainText(seed().users.admin)

  // отзыв: подтверждение «Отмена» — ничего не меняется; «ОК» — отозвано
  page.once('dialog', (d) => d.dismiss())
  await registered.getByRole('button', { name: 'отозвать' }).click()
  await expect(registered).toContainText('Действует')
  page.once('dialog', (d) => { expect(d.message()).toContain('Отозвать принятие риска?'); d.accept() })
  await registered.getByRole('button', { name: 'отозвать' }).click()
  await expect(register.locator('tbody tr', { hasText: code })).toHaveCount(0)
  await expect(statValue(page, 'Риск принят')).toHaveText(String(before.summary.accepted))
  await page.getByLabel('Показать отозванные и истёкшие').check()
  await expect(register.locator('tbody tr', { hasText: code })).toContainText('Отозвано')
})

test('принятие риска на все активы организации со сроком', async ({ page }) => {
  await loginAs(page, 'admin')
  await page.goto('/hardening')
  await page.getByLabel('Статус').selectOption({ label: 'Нарушено' })
  await page.getByLabel('Хост').selectOption('db-01')
  const first = page.locator('table').first().locator('tbody tr').first()
  const code = (await first.locator('td').nth(1).locator('.text-xs').first().textContent()).trim()
  await first.getByRole('button', { name: 'принять риск' }).click()
  await page.getByLabel('Обоснование').fill('E2E: принято для всей организации')
  await page.getByLabel('Область').selectOption('org')
  await page.getByLabel('До').fill('2030-12-31')
  await page.getByRole('button', { name: 'Принять риск', exact: true }).click()
  const registered = page.locator('table').nth(1).locator('tbody tr', { hasText: code })
  await expect(registered).toContainText('все активы')
  await expect(registered).toContainText('31.12.2030')
  // чистим за собой
  page.once('dialog', (d) => d.accept())
  await registered.getByRole('button', { name: 'отозвать' }).click()
  await expect(page.locator('table').nth(1).locator('tbody tr', { hasText: code })).toHaveCount(0)
})

test('ПО: сводка, поиск на сервере, фильтр хоста, сортировка', async ({ page, request }) => {
  const s = seed()
  const h = await apiAs(request, 'viewer')
  const all = await (await request.get(`/api/organizations/${s.orgs.main.id}/software`, { headers: h })).json()
  await loginAs(page, 'viewer')
  await page.goto('/software')
  await expect(statValue(page, 'Всего программ')).toHaveText(String(all.summary.programs))
  await expect(statValue(page, 'Хосты')).toHaveText(String(all.summary.hosts.length))
  const rows = page.locator('tbody tr')
  await expect(rows).toHaveCount(all.total)

  const search = page.getByLabel('Поиск ПО')
  await search.fill('openssh-S')
  await expect(page.getByText(/Найдено: 2 из/)).toBeVisible()  // openssh-server на web-01 и db-01
  await expect(rows).toHaveCount(2)
  await search.fill('')
  await expect(page.getByText(`Всего: ${all.summary.programs}`)).toBeVisible()
  await page.getByLabel('Хост').selectOption('db-01')
  await expect(rows.filter({ hasNotText: 'db-01' })).toHaveCount(0)
  await page.getByLabel('Хост').selectOption('')

  await page.getByRole('button', { name: 'Название' }).click()  // уже по названию asc → desc
  await expect(page.locator('th', { has: page.getByRole('button', { name: 'Название' }) })).toHaveAttribute('aria-sort', 'descending')
  await expect(rows.first().locator('td').first()).toHaveText([...all.items.map((i) => i.name)].sort().at(-1))
  await search.fill('нет-такой-программы')
  await expect(page.getByText('Под фильтр не попала ни одна программа.')).toBeVisible()
})

test('ПО: организация без ПО — пустое состояние', async ({ page }) => {
  await loginAs(page, 'beta', { org: 'other' })
  await page.goto('/software')
  await expect(page.getByText('Нет данных по ПО')).toBeVisible()
})

test('отчёты: план устранения из сводки сервера, история по дням, сортировка', async ({ page, request }) => {
  const s = seed()
  const h = await apiAs(request, 'viewer')
  const hardening = await (await request.get(`/api/organizations/${s.orgs.main.id}/hardening?limit=1`, { headers: h })).json()
  const daily = await (await request.get(`/api/organizations/${s.orgs.main.id}/reports?daily=true&limit=90`, { headers: h })).json()
  await loginAs(page, 'viewer')
  await page.goto('/report')
  const plan = page.locator('table').first().locator('tbody tr')
  await expect(plan).toHaveCount(hardening.summary.open_by_severity.length)
  const critical = hardening.summary.open_by_severity.find((r) => r.severity === 'critical')
  await expect(plan.first()).toContainText('критический')
  await expect(plan.first()).toContainText(String(critical.count))
  await expect(plan.first()).toContainText('Обязательно (п. 3.4.4)')
  const history = page.locator('table').nth(1).locator('tbody tr')
  await expect(history).toHaveCount(daily.length)
  await expect(statValue(page, 'Последнее соответствие')).toHaveText(`${Math.round(daily[0].compliance_score)}%`)
  await page.getByRole('button', { name: 'Соответствие' }).click()
  await expect(history.first()).toContainText(`${Math.round(Math.min(...daily.map((r) => r.compliance_score)))}%`)
  await page.getByRole('link', { name: /Харденинг/ }).last().click()
  await expect(page).toHaveURL(/\/hardening$/)
})
