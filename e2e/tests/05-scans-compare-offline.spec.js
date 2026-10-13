// «Сканирования» (PDF, Excel, выбор двух сканов, фильтр хоста), «Сравнение сканов», «Проверка по выгрузке».
import { test, expect } from '@playwright/test'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { apiAs, loginAs, seed, trackErrors } from '../helpers.js'

const here = path.dirname(fileURLToPath(import.meta.url))
const offline = (name) => path.join(here, '../.state/offline', name)

let errors
test.beforeEach(({ page }) => { errors = trackErrors(page) })
test.afterEach(() => expect(errors).toEqual([]))

async function snapshotsApi(request, params = '') {
  const s = seed()
  const h = await apiAs(request, 'viewer')
  return (await request.get(`/api/organizations/${s.orgs.main.id}/snapshots?limit=500${params}`, { headers: h })).json()
}

test('сканы: таблица и сводка как на сервере, хосты в строке, фильтр по хосту', async ({ page, request }) => {
  const body = await snapshotsApi(request)
  await loginAs(page, 'viewer')
  await page.goto('/scans')
  const rows = page.locator('tbody tr')
  await expect(rows).toHaveCount(body.total)
  await expect(page.locator('div.text-sm.text-zinc-400', { hasText: /^Всего сканов$/ }).locator('xpath=following-sibling::*[1]'))
    .toHaveText(String(body.summary.total))
  const first = body.items[0]
  await expect(rows.first()).toContainText(first.snapshot_label)
  await expect(rows.first()).toContainText(first.hosts.join(', '))
  await expect(rows.first()).toContainText(`${Math.round(first.compliance_score)}%`)

  const web = await snapshotsApi(request, '&host=web-01')
  await page.getByLabel('Хост').selectOption('web-01')
  await expect(rows).toHaveCount(web.total)
  await expect(rows.filter({ hasNotText: 'web-01' })).toHaveCount(0)
})

test('сканы: PDF и Excel скачиваются и это настоящие файлы', async ({ page }) => {
  await loginAs(page, 'viewer')
  await page.goto('/scans')
  const row = page.locator('tbody tr', { hasText: 'web-01' }).first()
  const number = (await row.getByRole('checkbox').getAttribute('aria-label')).match(/№(\d+)/)[1]

  const [pdf] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: `Скачать PDF скана №${number}` }).click()])
  expect(pdf.suggestedFilename()).toMatch(/\.pdf$/)
  expect(fs.readFileSync(await pdf.path()).subarray(0, 5).toString()).toBe('%PDF-')

  const [xlsx] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: `Скачать Excel скана №${number}` }).click()])
  expect(xlsx.suggestedFilename()).toMatch(/\.xlsx$/)
  expect(fs.readFileSync(await xlsx.path()).subarray(0, 2).toString()).toBe('PK')
})

test('сканы: ошибка экспорта показывается и закрывается', async ({ page }) => {
  await loginAs(page, 'viewer')
  await page.route((u) => u.pathname.includes('/api/exports/'), (r) => r.fulfill({ status: 404, json: { detail: 'Снимок не найден' } }))
  await page.goto('/scans')
  await page.locator('tbody tr').first().getByRole('button', { name: /Скачать PDF/ }).click()
  await expect(page.getByText('Не удалось сформировать PDF: Снимок не найден')).toBeVisible()
  await page.getByRole('button', { name: 'Закрыть' }).click()
  await expect(page.getByText(/Не удалось сформировать PDF/)).toHaveCount(0)
})

test('сканы: выбрать два, третий вытесняет первый, «сбросить», «Сравнить выбранные» — было раньше, стало позже', async ({ page, request }) => {
  const body = await snapshotsApi(request, '&host=web-01')
  const [newest, middle, oldest] = body.items  // у web-01 три скана
  await loginAs(page, 'viewer')
  await page.goto('/scans')
  const box = (s) => page.getByRole('checkbox', { name: `Выбрать скан №${s.scan_number} для сравнения` })
  const compare = page.getByRole('button', { name: 'Сравнить выбранные' })
  await expect(compare).toBeDisabled()
  await box(newest).check()
  await expect(page.getByText('выбрано 1 из 2')).toBeVisible()
  await box(middle).check()
  await box(oldest).check()  // вытесняет newest
  await expect(box(newest)).not.toBeChecked()
  await expect(page.getByText('выбрано 2 из 2')).toBeVisible()
  await page.getByRole('button', { name: 'сбросить' }).click()
  await expect(page.getByText('выбрано 0 из 2')).toBeVisible()

  await box(newest).check()  // отмечаем в обратном порядке — сравнение всё равно «старый → новый»
  await box(oldest).check()
  await compare.click()
  await expect(page).toHaveURL(new RegExp(`/scan-compare\\?before=${oldest.id}&after=${newest.id}$`))
  await expect(page.getByText(`Скан №${oldest.scan_number} → скан №${newest.scan_number}`)).toBeVisible()
})

test('сканы: «Сравнить» с предыдущим сканом того же актива', async ({ page, request }) => {
  const body = await snapshotsApi(request, '&host=web-01')
  const [newest, middle] = body.items
  await loginAs(page, 'viewer')
  await page.goto('/scans')
  await page.getByRole('link', { name: `Сравнить скан №${newest.scan_number} с предыдущим` }).click()
  await expect(page).toHaveURL(new RegExp(`before=${middle.id}&after=${newest.id}`))
})

test('сравнение: по умолчанию последний и предыдущий того же актива; итоги и таблица изменений', async ({ page, request }) => {
  const s = seed()
  const h = await apiAs(request, 'viewer')
  const body = await snapshotsApi(request, '&host=web-01')
  const [newest, , oldest] = body.items
  const diff = await (await request.get(`/api/snapshots/compare?before_snapshot_id=${oldest.id}&after_snapshot_id=${newest.id}`, { headers: h })).json()
  await loginAs(page, 'viewer')
  await page.goto(`/scan-compare?before=${oldest.id}&after=${newest.id}`)
  const stat = (label) => page.locator('div.text-sm.text-zinc-400', { hasText: new RegExp(`^${label}$`) }).locator('xpath=following-sibling::*[1]')
  await expect(stat('Исправлено')).toHaveText(String(diff.summary.fixed))
  await expect(stat('Ухудшилось')).toHaveText(String(diff.summary.regressed))
  expect(diff.summary.fixed).toBeGreaterThan(0)  // web-01: слабый → укреплённый
  await expect(page.getByText('Исправлено').first()).toBeVisible()

  // без параметров — последний скан организации и предыдущий того же актива
  const all = await snapshotsApi(request)
  await page.goto('/scan-compare')
  await expect(page).toHaveURL(new RegExp(`after=${all.items[0].id}`))
  void s
})

test('сравнение: выбор в форме, «поменять местами», один и тот же скан, «было» новее «стало»', async ({ page, request }) => {
  const body = await snapshotsApi(request, '&host=web-01')
  const [newest, middle, oldest] = body.items
  await loginAs(page, 'viewer')
  await page.goto(`/scan-compare?before=${oldest.id}&after=${middle.id}`)
  const before = page.getByLabel('Было')
  const after = page.getByLabel('Стало')
  await expect(before).toHaveValue(oldest.id)
  await expect(after).toHaveValue(middle.id)

  await after.selectOption(oldest.id)
  await expect(page.getByText('Выбран один и тот же скан — выберите два разных.')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Сравнить' })).toBeDisabled()

  await before.selectOption(newest.id)
  await expect(page.getByText(/«Было» новее, чем «стало»/)).toBeVisible()
  await page.getByRole('button', { name: 'Поменять местами' }).click()
  await expect(before).toHaveValue(oldest.id)
  await expect(after).toHaveValue(newest.id)
  await page.getByRole('button', { name: 'Сравнить' }).click()
  await expect(page).toHaveURL(new RegExp(`before=${oldest.id}&after=${newest.id}`))
  await expect(page.getByText(`Скан №${oldest.scan_number} → скан №${newest.scan_number}`)).toBeVisible()
  // «Назад» в браузере возвращает прежнюю пару и в форму
  await page.goBack()
  await expect(page.getByText(`Скан №${oldest.scan_number} → скан №${middle.scan_number}`)).toBeVisible()
  await expect(page.getByLabel('Стало')).toHaveValue(middle.id)
})

test('сравнение: в организации меньше двух сканов — подсказка', async ({ page }) => {
  await loginAs(page, 'beta', { org: 'other' })
  await page.goto('/scan-compare')
  await expect(page.getByText('Для сравнения нужно хотя бы два скана в организации.')).toBeVisible()
})

test('выгрузка: наблюдатель не загружает', async ({ page }) => {
  await loginAs(page, 'viewer')
  await page.goto('/offline-scan')
  await expect(page.getByText('Загружать выгрузки может только администратор организации.')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Проверить выгрузку' })).toBeDisabled()
})

test('выгрузка: Cisco — распознавание по show version, снимок создан, скан появился', async ({ page, request }) => {
  await loginAs(page, 'admin')
  await page.goto('/offline-scan')
  const submit = page.getByRole('button', { name: 'Проверить выгрузку' })
  await page.getByRole('button', { name: /^cisco-ios/ }).click()
  await expect(page.getByRole('button', { name: /^cisco-ios/ })).toHaveAttribute('aria-pressed', 'true')
  await expect(submit).toBeDisabled()  // нет файлов и имени
  await page.getByLabel('Файл выгрузки «show running-config»').setInputFiles(offline('running_weak.txt'))
  await page.getByPlaceholder('sw-core-01').fill('sw-e2e-01')
  // без show version — нужно явное подтверждение пака
  await expect(submit).toBeDisabled()
  await page.getByLabel('Файл выгрузки «show version»').setInputFiles(offline('show_version.txt'))
  await expect(submit).toBeEnabled()
  await page.getByPlaceholder('10.0.0.1').fill('10.0.0.7')
  await page.getByLabel('Критичность').selectOption('high')
  await page.getByPlaceholder('бэкап от 01.10').fill('E2E выгрузка')
  await submit.click()
  await expect(page.getByText(/Снимок создан: проверок \d+, соблюдено \d+, нарушений [1-9]\d*/)).toBeVisible()
  await page.getByRole('link', { name: 'Открыть сканирования' }).click()
  await expect(page.locator('tbody tr').first()).toContainText('E2E выгрузка')
  await expect(page.locator('tbody tr').first()).toContainText('sw-e2e-01')
  await expect(page.locator('tbody tr').first()).toContainText(/выгрузк/i)
  void request
})

test('выгрузка: только running-config — подтверждение пака; чужая выгрузка — ошибка сервера', async ({ page }) => {
  await loginAs(page, 'admin')
  await page.goto('/offline-scan')
  await page.getByRole('button', { name: /^cisco-ios/ }).click()
  const submit = page.getByRole('button', { name: 'Проверить выгрузку' })
  await page.getByPlaceholder('sw-core-01').fill('sw-e2e-02')
  await page.getByLabel('Файл выгрузки «show running-config»').setInputFiles(offline('running_good.txt'))
  await expect(submit).toBeDisabled()
  await page.getByRole('checkbox').check()
  await expect(submit).toBeEnabled()
  await submit.click()
  await expect(page.getByText(/Снимок создан/)).toBeVisible()

  // show version не от Cisco: сервер отказывает, ошибка видна
  await page.getByRole('button', { name: /^cisco-ios/ }).click()  // повторный выбор — форма файлов с чистого листа
  await page.getByLabel('Файл выгрузки «show version»').setInputFiles(offline('not_cisco.txt'))
  await page.getByLabel('Файл выгрузки «show running-config»').setInputFiles(offline('running_good.txt'))
  await submit.click()
  await expect(page.locator('.text-rose-300').last()).toBeVisible()
})
