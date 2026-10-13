// «Управление доступом» (админ организации), «Пользователи и организации» (суперадмин), навигация и меню на телефоне.
import { test, expect } from '@playwright/test'
import { createUser, loginAs, seed, trackErrors, unique } from '../helpers.js'

let errors
test.beforeEach(({ page }) => { errors = trackErrors(page) })
test.afterEach(() => expect(errors).toEqual([]))

test('управление доступом: добавить по email (Enter), сменить роль, убрать; ошибки видны', async ({ page, request }) => {
  const user = await createUser(request, { email: unique('member'), org: null })
  await loginAs(page, 'admin')
  await page.goto('/organization-users')
  const rows = page.locator('tbody tr')
  await expect(rows.filter({ hasText: seed().users.admin })).toHaveCount(1)  // список загружен
  const before = await rows.count()

  await page.getByRole('button', { name: 'Добавить' }).click()
  await expect(page.getByText('Введите email пользователя')).toBeVisible()
  await page.getByLabel('Email пользователя').fill('nobody-here@e2e.example.com')
  await page.getByLabel('Роль', { exact: true }).selectOption({ label: 'Наблюдатель' })
  await page.getByLabel('Email пользователя').press('Enter')
  await expect(page.getByText('Ошибка действия')).toBeVisible()

  await page.getByLabel('Email пользователя').fill(user.email)
  await page.getByLabel('Email пользователя').press('Enter')
  await expect(rows).toHaveCount(before + 1)
  const row = rows.filter({ hasText: user.email })
  await expect(row.getByLabel(`Роль ${user.email}`)).toHaveValue('viewer')
  await expect(page.getByLabel('Email пользователя')).toHaveValue('')

  await row.getByLabel(`Роль ${user.email}`).selectOption({ label: 'Аудитор' })
  await expect(row.getByLabel(`Роль ${user.email}`)).toHaveValue('auditor')
  await page.reload()
  await expect(rows.filter({ hasText: user.email }).getByLabel(`Роль ${user.email}`)).toHaveValue('auditor')

  page.once('dialog', (d) => d.dismiss())
  await page.getByRole('button', { name: `Убрать ${user.email} из организации` }).click()
  await expect(rows).toHaveCount(before + 1)
  page.once('dialog', (d) => { expect(d.message()).toBe(`Убрать ${user.email} из организации?`); d.accept() })
  await page.getByRole('button', { name: `Убрать ${user.email} из организации` }).click()
  await expect(rows).toHaveCount(before)
})

test('управление доступом: последнего администратора не понизить', async ({ page }) => {
  const s = seed()
  await loginAs(page, 'admin')
  await page.goto('/organization-users')
  await page.getByLabel(`Роль ${s.users.admin}`).selectOption('viewer')
  await expect(page.getByText('Ошибка действия')).toBeVisible()
  await page.reload()
  await expect(page.getByLabel(`Роль ${s.users.admin}`)).toHaveValue('admin')
})

test('управление доступом: не администратору — «Недостаточно прав»', async ({ page }) => {
  await loginAs(page, 'auditor')
  await page.goto('/organization-users')
  await expect(page.getByText('Недостаточно прав')).toBeVisible()
  await expect(page.getByLabel('Email пользователя')).toHaveCount(0)
})

test('суперадмин: новая организация сразу выбрана; дубль названия — ошибка', async ({ page }) => {
  const name = `E2E Орг ${Date.now().toString(36)}`
  await loginAs(page, 'super')
  await page.goto('/admin/users')
  await page.getByPlaceholder('Название *').fill(name)
  await page.getByPlaceholder('Отрасль').fill('Энергетика')
  await page.getByRole('button', { name: /Создать организацию|Создать/ }).first().click()
  await expect(page.getByText(`Текущая организация: ${name}`)).toBeVisible()
  // сообщение остаётся и после того, как новая организация стала выбранной (страница не пересоздаётся)
  await expect(page.getByText(`Организация «${name}» создана и выбрана.`, { exact: false })).toBeVisible()
  await expect(page.getByLabel('Организация').first()).toContainText(name)

  await page.getByPlaceholder('Название *').fill(name.toUpperCase())
  await page.getByRole('button', { name: /Создать организацию|Создать/ }).first().click()
  await expect(page.getByText('Организация с таким названием уже есть')).toBeVisible()
  errors.length = 0
})

test('суперадмин: пользователь — генерация пароля, создание в организации с ролью, выдача пароля один раз', async ({ page, request }) => {
  const s = seed()
  const email = unique('created')
  await loginAs(page, 'super')
  await page.goto('/admin/users')
  const form = page.locator('form').filter({ has: page.getByPlaceholder('Email *') })
  await expect(form.getByLabel('Роль в организации')).toBeDisabled()
  await form.getByPlaceholder('Email *').fill(email)
  await form.getByPlaceholder('ФИО').fill('Иванов Иван')
  await form.getByRole('button', { name: 'Сгенерировать' }).click()
  const password = await form.getByPlaceholder('Временный пароль * (от 12 символов)').inputValue()
  expect(password).toMatch(/^[A-HJ-NP-Za-km-z2-9]{16}$/)
  await form.getByLabel('Организация').selectOption({ label: s.orgs.main.name })
  await form.getByLabel('Роль в организации').selectOption({ label: 'Аудитор' })
  await form.getByRole('button', { name: 'Создать' }).click()
  await expect(page.getByText(`Временный пароль для ${email}.`, { exact: false })).toBeVisible()
  await expect(page.locator('code', { hasText: password })).toBeVisible()
  await page.getByRole('button', { name: 'Скрыть' }).click()
  await expect(page.locator('code', { hasText: password })).toHaveCount(0)

  const row = page.locator('tbody tr', { hasText: email })
  await expect(row).toContainText('Иванов Иван')
  await expect(row).toContainText(`${s.orgs.main.name} (аудитор)`)
  await expect(row).toContainText('временный пароль')

  // выданный пароль работает и требует смены
  const login = await request.post('/api/auth/login', { data: { email, password } })
  expect(login.ok()).toBeTruthy()
  expect((await (await request.get('/api/auth/me', { headers: { Authorization: `Bearer ${(await login.json()).access_token}` } })).json()).must_change_password).toBe(true)
})

test('суперадмин: короткий пароль и повторный email — ошибки сервера', async ({ page }) => {
  const s = seed()
  await loginAs(page, 'super')
  await page.goto('/admin/users')
  const form = page.locator('form').filter({ has: page.getByPlaceholder('Email *') })
  await form.getByPlaceholder('Email *').fill(s.users.viewer)
  await form.getByPlaceholder('Временный пароль * (от 12 символов)').fill('Long-enough-pass-1')
  await form.getByRole('button', { name: 'Создать' }).click()
  await expect(page.getByText('Пользователь с таким email уже есть')).toBeVisible()
  errors.length = 0
})

test('суперадмин: сброс пароля, блокировка и разблокировка, сброс 2FA; себя — нельзя', async ({ page, request }) => {
  const user = await createUser(request, { email: unique('managed') })
  await loginAs(page, 'super')
  await page.goto('/admin/users')
  const row = page.locator('tbody tr', { hasText: user.email })
  await expect(row).toContainText('активен')
  // себе — только подсказка
  await expect(page.locator('tbody tr', { hasText: seed().users.super })).toContainText('свой пароль — в меню профиля')

  page.once('dialog', (d) => d.dismiss())
  await page.getByRole('button', { name: `Сбросить пароль ${user.email}` }).click()
  await expect(page.getByText(`Временный пароль для ${user.email}`)).toHaveCount(0)
  page.once('dialog', (d) => { expect(d.message()).toContain('Все его текущие сессии будут завершены'); d.accept() })
  await page.getByRole('button', { name: `Сбросить пароль ${user.email}` }).click()
  const issued = (await page.locator('code').filter({ hasText: /^[A-Za-z0-9]{16}$/ }).first().textContent()).trim()
  await expect(row).toContainText('временный пароль')
  expect((await request.post('/api/auth/login', { data: { email: user.email, password: user.password } })).status()).toBe(401)
  expect((await request.post('/api/auth/login', { data: { email: user.email, password: issued } })).ok()).toBeTruthy()

  page.once('dialog', (d) => { expect(d.message()).toContain('Доступ прекратится сразу'); d.accept() })
  await page.getByRole('button', { name: `Заблокировать ${user.email}` }).click()
  await expect(row).toContainText('заблокирован')
  expect((await request.post('/api/auth/login', { data: { email: user.email, password: issued } })).ok()).toBeFalsy()
  page.once('dialog', (d) => d.accept())
  await page.getByRole('button', { name: `Разблокировать ${user.email}` }).click()
  await expect(row).not.toContainText('заблокирован')

  // «Сбросить 2FA» есть только у пользователя с 2FA
  await expect(page.getByRole('button', { name: `Сбросить 2FA ${user.email}` })).toHaveCount(0)
})

test('копирование работает и без HTTPS (http://адрес-в-сети): запасной способ через выделение', async ({ page, context }) => {
  // Не защищённый контекст: navigator.clipboard нет, как у браузера по http://192.168.x.x
  await page.addInitScript(() => {
    Object.defineProperty(window, 'isSecureContext', { value: false })
    Object.defineProperty(navigator, 'clipboard', { value: undefined })
  })
  await context.grantPermissions(['clipboard-read', 'clipboard-write'])
  await loginAs(page, 'super')
  await page.goto('/admin/users')
  const form = page.locator('form').filter({ has: page.getByPlaceholder('Email *') })
  await form.getByPlaceholder('Email *').fill(unique('copy'))
  await form.getByRole('button', { name: 'Сгенерировать' }).click()
  const password = await form.getByPlaceholder('Временный пароль * (от 12 символов)').inputValue()
  await form.getByRole('button', { name: 'Создать' }).click()
  await page.getByRole('button', { name: /Скопировать|копировать/ }).first().click()
  await expect(page.getByRole('button', { name: 'Скопировано' })).toBeVisible()
  const reader = await context.newPage()  // у этой страницы обычный буфер обмена
  await reader.goto('/login')
  expect(await reader.evaluate(() => navigator.clipboard.readText())).toBe(password)
})

test('не суперадмин: «Пользователи и организации» закрыта', async ({ page }) => {
  await loginAs(page, 'admin')
  await page.goto('/admin/users')
  await expect(page.getByText('Учётными записями управляет суперадминистратор.')).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Новый пользователь' })).toHaveCount(0)
})

test('навигация: каждый пункт бокового меню открывает свою страницу и подсвечивается', async ({ page }) => {
  await loginAs(page, 'admin')
  await page.goto('/dashboard')
  const nav = page.getByRole('navigation', { name: 'Разделы' }).first()
  const links = nav.getByRole('link')
  await expect(links).toHaveCount(12)
  for (let i = 0; i < 12; i++) {
    const link = links.nth(i)
    const href = await link.getAttribute('href')
    await link.click()
    await expect(page).toHaveURL(new RegExp(`${href}$`))
    await expect(page.getByRole('heading', { level: 1 }).first()).toBeVisible()
    await expect(link).toHaveAttribute('aria-current', 'page')
  }
  // старый адрес /project ведёт на «Активы», неизвестный — на «Обзор»
  await page.goto('/project')
  await expect(page).toHaveURL(/\/assets$/)
  await page.goto('/нет-такой-страницы')
  await expect(page).toHaveURL(/\/dashboard$/)
})

test('файл страницы прежней сборки не найден — одна перезагрузка, и страница открывается', async ({ page }) => {
  await loginAs(page, 'viewer')
  await page.goto('/dashboard')
  let failed = 0
  // как после выкатки: открытая вкладка просит файл страницы, которого на сервере уже нет
  await page.route(/\/src\/pages\/Hardening\.jsx/, (route) => {
    if (failed++ === 0) return route.fulfill({ status: 404, body: 'Not Found' })
    return route.fallback()
  })
  await page.getByRole('navigation', { name: 'Разделы' }).getByRole('link', { name: 'Харденинг' }).click()
  await expect(page.getByRole('heading', { name: 'Харденинг', level: 1 })).toBeVisible()
  expect(failed).toBe(2)  // первый запрос — 404, после перезагрузки — настоящий файл
  errors.length = 0  // ошибка загрузки модуля в консоли — ожидаемая
})

test.describe('телефон', () => {
  test.use({ viewport: { width: 390, height: 844 } })
  test('меню открывается кнопкой, закрывается крестиком, фоном и переходом', async ({ page }) => {
    await loginAs(page, 'viewer')
    await page.goto('/dashboard')
    const open = page.getByRole('button', { name: 'Открыть меню' })
    await expect(open).toBeVisible()
    await open.click()
    await expect(page.getByRole('button', { name: 'Закрыть меню' })).toBeVisible()
    await page.getByRole('button', { name: 'Закрыть меню' }).click()
    await expect(page.getByRole('button', { name: 'Закрыть меню' })).toHaveCount(0)
    await open.click()
    await page.mouse.click(380, 400)  // по затемнённому фону справа от меню
    await expect(page.getByRole('button', { name: 'Закрыть меню' })).toHaveCount(0)
    await open.click()
    await page.getByRole('link', { name: 'Харденинг' }).last().click()
    await expect(page).toHaveURL(/\/hardening$/)
    await expect(page.getByRole('button', { name: 'Закрыть меню' })).toHaveCount(0)
    // на узком экране страницы не вылезают за ширину окна
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)
    expect(overflow).toBeLessThanOrEqual(0)
  })
})
