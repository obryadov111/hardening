// «Агенты»: ключи площадок, регистрация хостов, отзыв и удаление, охват по списку из AD, отчёт из файла,
// скачивание агента, права. Регистрация и отчёты — настоящими запросами агента к API.
import { test, expect } from '@playwright/test'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { apiAs, loginAs, seed, trackErrors } from '../helpers.js'

const here = path.dirname(fileURLToPath(import.meta.url))
const fixture = (name) => path.join(here, '../.state/offline', name)

let errors
test.beforeEach(({ page }) => { errors = trackErrors(page) })
test.afterEach(() => expect(errors).toEqual([]))

test('не администратор: только сообщение, без ключей', async ({ page }) => {
  for (const role of ['viewer']) {
    await loginAs(page, role)
    await page.goto('/agents')
    await expect(page.getByText('Управлять агентами может только администратор организации.')).toBeVisible()
    await expect(page.getByRole('heading', { name: 'Новый ключ площадки' })).toHaveCount(0)
  }
})

test('ключ площадки: создание, показ один раз, копирование, настройки Linux и Windows, «Скрыть ключ»', async ({ page }) => {
  await loginAs(page, 'admin')
  await page.goto('/agents')
  const create = page.getByRole('button', { name: 'Создать ключ' })
  await expect(create).toBeDisabled()
  await page.getByPlaceholder('Казань, ЦОД, сегмент АСУ').fill('E2E Казань')
  await page.getByLabel('Срок действия').selectOption({ label: '90 дней' })
  await create.click()
  const box = page.locator('div', { hasText: /^Ключ «E2E Казань» создан/ }).first()
  await expect(page.getByText(/Ключ «E2E Казань» создан, действует до \d\d\.\d\d\.\d{4}/)).toBeVisible()
  const key = (await page.locator('pre, code').filter({ hasText: /^[A-Za-z0-9_-]{30,}$/ }).first().textContent()).trim()
  expect(key.length).toBeGreaterThan(30)
  await expect(page.getByText(`HARDENING_AGENT_API_KEY=${key}`).or(page.getByText(new RegExp(key)).nth(1))).toBeVisible()
  await expect(page.getByText(/--enroll/)).toBeVisible()
  await page.context().grantPermissions(['clipboard-read', 'clipboard-write'])
  await page.getByRole('button', { name: /Скопировать|копировать/ }).first().click()
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(key)
  await page.getByRole('button', { name: 'Скрыть ключ' }).click()
  await expect(page.getByText(key)).toHaveCount(0)
  void box

  // в таблице ключей: действует, не использовался
  const keysTable = page.locator('table').filter({ hasText: 'Действует до' })
  const row = keysTable.locator('tr', { hasText: 'E2E Казань' })
  await expect(row).toContainText('действует')
  await expect(row).toContainText('не использовался')

  // ключ работает: хост регистрируется — появляется в «Хосты» после обновления страницы
  const enroll = await page.request.post('/api/agent/enroll', { headers: { 'X-Agent-Api-Key': key }, data: { hostname: 'e2e-kzn-01', os: 'Astra Linux 1.8' } })
  expect(enroll.status()).toBe(201)
  await page.reload()
  const host = page.locator('table').filter({ hasText: 'Зарегистрирован' }).locator('tr', { hasText: 'e2e-kzn-01' })
  await expect(host).toContainText('E2E Казань')
  await expect(host).toContainText('активен')
  await expect(host).toContainText('Astra Linux 1.8')
  await expect(row).not.toContainText('не использовался')

  // отзыв ключа: «Отмена» — ничего; «ОК» — отозван, новые хосты не регистрируются
  page.once('dialog', (d) => d.dismiss())
  await page.getByRole('button', { name: 'Отозвать ключ «E2E Казань»' }).click()
  await expect(row).toContainText('действует')
  page.once('dialog', (d) => { expect(d.message()).toContain('Новые хосты по нему не зарегистрируются'); d.accept() })
  await page.getByRole('button', { name: 'Отозвать ключ «E2E Казань»' }).click()
  await expect(row).toContainText('отозван')
  await expect(page.getByRole('button', { name: 'Отозвать ключ «E2E Казань»' })).toHaveCount(0)
  const again = await page.request.post('/api/agent/enroll', { headers: { 'X-Agent-Api-Key': key }, data: { hostname: 'e2e-kzn-02' } })
  expect(again.status()).toBe(401)
})

test('хосты: поиск, отзыв (отчёты больше не принимаются), удаление регистрации', async ({ page }) => {
  const s = seed()
  const enroll = await page.request.post('/api/agent/enroll', { headers: { 'X-Agent-Api-Key': s.site_key }, data: { hostname: 'e2e-host-rv', os: 'Debian 12' } })
  const hostKey = (await enroll.json()).key
  await loginAs(page, 'admin')
  await page.goto('/agents')
  await page.getByLabel('Поиск хостов').fill('debian')
  const hostsTable = page.locator('table').filter({ hasText: 'Зарегистрирован' })
  await expect(hostsTable.locator('tbody tr')).toHaveCount(1)
  await page.getByLabel('Поиск хостов').fill('нет-такого')
  await expect(page.getByText('Под поиск не попал ни один хост.')).toBeVisible()
  await page.getByLabel('Поиск хостов').fill('e2e-host-rv')

  page.once('dialog', (d) => d.accept())
  await page.getByRole('button', { name: 'Отозвать хост e2e-host-rv' }).click()
  await expect(page.locator('tr', { hasText: 'e2e-host-rv' })).toContainText('отозван')
  const report = await page.request.post('/api/ingest', {
    headers: { 'X-Agent-Api-Key': hostKey },
    data: { environment: 'prod', asset: { hostname: 'e2e-host-rv' } },
  })
  expect(report.status()).toBe(401)
  // повторная регистрация отозванного хоста — нельзя, пока не удалена регистрация
  const reEnroll = await page.request.post('/api/agent/enroll', { headers: { 'X-Agent-Api-Key': s.site_key }, data: { hostname: 'e2e-host-rv' } })
  expect(reEnroll.status()).toBe(409)

  page.once('dialog', (d) => { expect(d.message()).toContain('Актив и история проверок останутся'); d.accept() })
  await page.getByRole('button', { name: 'Удалить регистрацию e2e-host-rv' }).click()
  await expect(page.locator('tr', { hasText: 'e2e-host-rv' })).toHaveCount(0)
  const fresh = await page.request.post('/api/agent/enroll', { headers: { 'X-Agent-Api-Key': s.site_key }, data: { hostname: 'e2e-host-rv' } })
  expect(fresh.status()).toBe(201)
})

test('охват: список из AD — плитки, фильтр, поиск, периоды, CSV, замена и удаление списка', async ({ page }) => {
  await loginAs(page, 'admin')
  await page.goto('/agents')
  const cover = page.locator('section, div').filter({ has: page.getByRole('heading', { name: 'Охват' }) }).last()
  await page.getByRole('button', { name: 'копировать' }).click()
  await expect(page.getByRole('button', { name: 'Загрузить список' })).toBeDisabled()

  // файл без колонки имени — ошибка сервера видна
  await page.getByLabel('Файл списка компьютеров').setInputFiles(fixture('no_name_column.csv'))
  await page.getByRole('button', { name: 'Загрузить список' }).click()
  await expect(page.getByText(/Не найдена колонка с именем хоста/)).toBeVisible()

  await page.getByLabel('Файл списка компьютеров').setInputFiles(fixture('computers.csv'))
  await page.getByRole('button', { name: 'Загрузить список' }).click()
  await expect(page.getByText(/Загружено хостов: 2, повторов пропущено: 1, отключённых в AD пропущено: 1/)).toBeVisible()
  await expect(page.getByText(/Список: 2 хостов/)).toBeVisible()

  const tile = (name) => page.getByRole('button', { name: new RegExp(`^${name}`) })
  await expect(tile('Отчитываются')).toContainText('1')
  await expect(tile('Отчитываются')).toContainText('50% списка')
  await expect(tile('Агент не установлен')).toContainText('1')
  await tile('Агент не установлен').click()
  await expect(tile('Агент не установлен')).toHaveAttribute('aria-pressed', 'true')
  const rows = cover.locator('tbody tr')
  await expect(page.getByText('агент не установлен: 1')).toBeVisible()
  const coverTable = page.locator('table').filter({ hasText: 'Последний вход (AD)' })
  await expect(coverTable.locator('tr', { hasText: 'PC-404' })).toContainText('агента нет')
  await tile('Агент не установлен').click()
  await tile('Нет в списке').click()
  await expect(coverTable.locator('tr', { hasText: 'win-srv-01' })).toContainText('нет в списке')
  await tile('Нет в списке').click()
  void rows

  await page.getByLabel('Поиск в охвате').fill('pc-4')
  await expect(page.getByText('весь список: 1')).toBeVisible()
  await page.getByLabel('Поиск в охвате').fill('')

  // период: «сутки» — web-01 отчитывался 24 ч назад и раньше, может выпасть в «давно молчат»
  await page.getByRole('button', { name: 'сутки' }).click()
  await expect(page.getByRole('button', { name: 'сутки' })).toHaveAttribute('aria-pressed', 'true')
  await page.getByRole('button', { name: '30 дн.' }).click()
  await expect(tile('Отчитываются')).toContainText('1')

  const [csv] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: 'Скачать CSV' }).click()])
  expect(csv.suggestedFilename()).toBe('охват-все.csv')
  const text = fs.readFileSync(await csv.path(), 'utf-8')
  expect(text).toContain('PC-404')
  expect(text).toContain('WEB-01')  // имя — как в списке AD

  // замена тем же файлом и удаление списка с подтверждением
  await page.getByLabel('Файл списка компьютеров').setInputFiles(fixture('computers.csv'))
  await page.getByRole('button', { name: 'Заменить список' }).click()
  await expect(page.getByText(/Загружено хостов: 2/)).toBeVisible()
  page.once('dialog', (d) => d.dismiss())
  await page.getByRole('button', { name: 'Удалить список' }).click()
  await expect(page.getByText(/Список: 2 хостов/)).toBeVisible()
  page.once('dialog', (d) => d.accept())
  await page.getByRole('button', { name: 'Удалить список' }).click()
  await expect(page.getByRole('button', { name: 'Загрузить список' })).toBeVisible()
})

test('отчёт из файла: подписанный принимается; изменённый и чужой формат — отказ', async ({ page }) => {
  await loginAs(page, 'admin')
  await page.goto('/agents')
  const submit = page.getByRole('button', { name: 'Загрузить отчёт' })
  await expect(submit).toBeDisabled()
  await page.getByLabel('Файл отчёта агента').setInputFiles(fixture('not_a_report.json'))
  await submit.click()
  await expect(page.getByText('Файл — не отчёт агента (ожидается JSON, сохранённый агентом с --out)')).toBeVisible()
  await page.getByLabel('Файл отчёта агента').setInputFiles(fixture('agent_report_tampered.json'))
  await submit.click()
  await expect(page.getByText(/Подпись отчёта не совпала/)).toBeVisible()
  await page.getByLabel('Файл отчёта агента').setInputFiles(fixture('agent_report.json'))
  await expect(page.getByText(/Подпись отчёта не совпала/)).toHaveCount(0)  // новый файл — ошибка сброшена
  await submit.click()
  await expect(page.getByText(/Снимок создан: проверок \d+/)).toBeVisible()
  await page.getByRole('link', { name: 'Открыть сканирования' }).click()
  await expect(page.locator('tbody tr').first()).toContainText('e2e отчёт из файла')
  await expect(page.locator('tbody tr').first()).toContainText('air-gap-01')
})

test('скачать агент: агент не опубликован — подсказка; опубликован — ссылки, версии, SHA-256, отпечаток в настройках', async ({ page }) => {
  await loginAs(page, 'admin')
  await page.goto('/agents')
  await expect(page.getByText(/publish_agent\.sh|не опубликован/)).toBeVisible()

  const version = {
    published_at: '2026-10-12T16:42:25+00:00',
    server_url: 'https://audit.example.com',
    server_pin: 'sha256//E2E+pin+value=',
    files: [
      { platform: 'linux', name: 'hardening-agent-linux.tar.gz', version: '2026.10.12-c126ac6', sha256: 'a'.repeat(64), size: 54041 },
      { platform: 'windows', name: 'hardening-agent.exe', version: '2026.10.12-c126ac6', sha256: 'b'.repeat(64), size: 8986625 },
      { platform: 'windows-gpo', name: 'gpo-startup.ps1', version: '2026.10.12-c126ac6', sha256: 'c'.repeat(64), size: 8338 },
    ],
  }
  await page.route('**/downloads/version.json', (r) => r.fulfill({ json: version }))
  await page.reload()
  await expect(page.getByRole('link', { name: 'Скачать' }).first()).toHaveAttribute('href', '/downloads/hardening-agent-linux.tar.gz')
  await expect(page.getByRole('link', { name: 'Скачать' }).nth(1)).toHaveAttribute('href', '/downloads/hardening-agent.exe')
  await expect(page.getByText(`SHA-256: ${'a'.repeat(64)}`)).toBeVisible()
  await expect(page.getByRole('link', { name: 'gpo-startup.ps1' })).toHaveAttribute('href', '/downloads/gpo-startup.ps1')

  await page.getByPlaceholder('Казань, ЦОД, сегмент АСУ').fill('E2E с опубликованным агентом')
  await page.getByLabel('Срок действия').selectOption({ label: 'бессрочно' })
  await page.getByRole('button', { name: 'Создать ключ' }).click()
  await expect(page.getByText(/создан, бессрочный/)).toBeVisible()
  await expect(page.getByText(/HARDENING_API_URL=https:\/\/audit\.example\.com/)).toBeVisible()
  await expect(page.getByText(/HARDENING_PIN_SHA256=sha256\/\/E2E\+pin\+value=/)).toBeVisible()
  await expect(page.getByText(/setx \/M HARDENING_PIN_SHA256 "sha256\/\/E2E\+pin\+value="/)).toBeVisible()
  // чистим: отзываем созданный ключ
  page.once('dialog', (d) => d.accept())
  await page.getByRole('button', { name: 'Отозвать ключ «E2E с опубликованным агентом»' }).click()
})

test('смена организации прячет показанный ключ прежней', async ({ page }) => {
  await loginAs(page, 'super')
  await page.goto('/agents')
  await page.getByPlaceholder('Казань, ЦОД, сегмент АСУ').fill('E2E утечка ключа')
  await page.getByRole('button', { name: 'Создать ключ' }).click()
  await expect(page.getByText(/Ключ «E2E утечка ключа» создан/)).toBeVisible()
  await page.getByLabel('Организация').selectOption({ label: seed().orgs.other.name })
  await expect(page.getByText(/Ключ «E2E утечка ключа» создан/)).toHaveCount(0)
  await expect(page.getByText('Ключей пока нет.')).toBeVisible()
  await page.getByLabel('Организация').selectOption({ label: seed().orgs.main.name })
  page.once('dialog', (d) => d.accept())
  await page.getByRole('button', { name: 'Отозвать ключ «E2E утечка ключа»' }).click()
})

test('API: ключи агентов другой организации недоступны администратору', async ({ request }) => {
  const s = seed()
  const h = await apiAs(request, 'admin')
  const resp = await request.get(`/api/organizations/${s.orgs.other.id}/agent-keys`, { headers: h })
  expect(resp.status()).toBe(403)
})
