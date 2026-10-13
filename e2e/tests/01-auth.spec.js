// Вход, выход, 2FA (подключение, вход с кодом и резервным кодом, отключение), смена пароля, временный пароль,
// обязательная 2FA, блокировка после неудачных попыток, недоступный сервер.
import { test, expect } from '@playwright/test'
import { STRICT_BACKEND_PORT } from '../playwright.config.js'
import { createUser, loginAs, nextTotpWindow, seed, totp, trackErrors, unique } from '../helpers.js'

let errors
test.beforeEach(({ page }) => { errors = trackErrors(page) })
// Ошибки консоли от ожидаемых отказов (неверный пароль) — не ошибки приложения: проверяем только JS и 5xx.
test.afterEach(() => expect(errors.filter((e) => !e.startsWith('console:'))).toEqual([]))

async function fillLogin(page, email, password) {
  await page.goto('/login')
  await page.getByLabel('Email').fill(email)
  await page.getByLabel('Пароль').fill(password)
  await page.getByRole('button', { name: 'Войти' }).click()
}

test('без входа любой раздел ведёт на страницу входа', async ({ page }) => {
  for (const url of ['/', '/dashboard', '/agents', '/admin/users', '/нет-такой']) {
    await page.goto(url)
    await expect(page).toHaveURL(/\/login$/)
  }
  await expect(page.getByRole('heading', { name: 'Харденинг' })).toBeVisible()
  await expect(page.getByText('Аккаунты создаются администратором системы')).toBeVisible()
})

test('пустые поля — подсказки без запроса к серверу', async ({ page }) => {
  let calls = 0
  page.on('request', (r) => { if (r.url().includes('/api/auth/login')) calls++ })
  await page.goto('/login')
  await page.getByRole('button', { name: 'Войти' }).click()
  await expect(page.getByText('Введите email')).toBeVisible()
  await page.getByLabel('Email').fill('someone@example.com')
  await page.getByRole('button', { name: 'Войти' }).click()
  await expect(page.getByText('Введите пароль')).toBeVisible()
  expect(calls).toBe(0)
})

test('неверный пароль и неизвестный email — одинаковая ошибка', async ({ page }) => {
  const s = seed()
  await fillLogin(page, s.users.viewer, 'wrong-password-1')
  const message = page.locator('.text-red-300')
  await expect(message).toBeVisible()
  const text = await message.textContent()
  await fillLogin(page, 'nobody@e2e.example.com', 'wrong-password-1')
  await expect(page.locator('.text-red-300')).toHaveText(text)
  await expect(page).toHaveURL(/\/login$/)
})

test('вход по паролю, email без учёта регистра и пробелов; со входом /login ведёт в приложение', async ({ page }) => {
  const s = seed()
  await fillLogin(page, `  ${s.users.viewer.toUpperCase()} `, s.password)
  await expect(page).toHaveURL(/\/dashboard$/)
  await expect(page.getByRole('button', { name: 'Меню пользователя' })).toContainText(s.users.viewer)
  await page.goto('/login')
  await expect(page).toHaveURL(/\/dashboard$/)
})

test('выход: токен стирается, назад в приложение без входа нельзя', async ({ page }) => {
  await loginAs(page, 'viewer')
  await page.goto('/dashboard')
  await page.getByRole('button', { name: 'Меню пользователя' }).click()
  await page.getByRole('button', { name: 'Выйти' }).click()
  await expect(page).toHaveURL(/\/login$/)
  expect(await page.evaluate(() => localStorage.getItem('hardening_access_token'))).toBeNull()
  await page.goto('/dashboard')
  await expect(page).toHaveURL(/\/login$/)
})

test('токен отозван на сервере (401) — приложение отправляет на вход', async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem('hardening_access_token', 'not-a-valid-token'))
  await page.goto('/dashboard')
  await expect(page).toHaveURL(/\/login$/)
})

test('сервер недоступен — экран с «Повторить» и «Выйти», без петли перенаправлений', async ({ page }) => {
  await loginAs(page, 'viewer')
  await page.route('**/api/auth/me', (route) => route.fulfill({ status: 502, body: 'Bad Gateway' }))
  await page.goto('/dashboard')
  await expect(page.getByText('Сервер недоступен')).toBeVisible()
  await page.unroute('**/api/auth/me')
  await page.getByRole('button', { name: 'Повторить' }).click()
  await expect(page.getByRole('heading', { name: 'Обзор' })).toBeVisible()

  await page.route('**/api/auth/me', (route) => route.abort())
  await page.reload()
  await expect(page.getByText('Сервер недоступен')).toBeVisible()
  await page.getByRole('button', { name: 'Выйти' }).click()
  await expect(page).toHaveURL(/\/login$/)
  errors.length = 0  // 502 выше — намеренный
})

test('меню пользователя: роль по-русски, пункты ведут на свои страницы', async ({ page }) => {
  const s = seed()
  await loginAs(page, 'admin')
  await page.goto('/dashboard')
  const menu = page.getByRole('button', { name: 'Меню пользователя' })
  await expect(menu).toContainText(s.users.admin)
  await expect(menu).toContainText('Администратор организации')
  await menu.click()
  await page.getByRole('button', { name: 'Управление доступом' }).click()
  await expect(page).toHaveURL(/\/organization-users$/)
  await menu.click()
  await page.getByRole('button', { name: 'Сменить пароль' }).click()
  await expect(page).toHaveURL(/\/change-password$/)
  await menu.click()
  await page.getByRole('button', { name: 'Двухфакторная защита' }).click()
  await expect(page).toHaveURL(/\/two-factor$/)
  // «Пользователи и организации» — только суперадмину
  await menu.click()
  await expect(page.getByRole('button', { name: 'Пользователи и организации' })).toHaveCount(0)
  // клик мимо меню закрывает его
  await page.getByRole('heading', { name: 'Двухфакторная защита' }).click()
  await expect(page.getByRole('button', { name: 'Сменить пароль' })).toHaveCount(0)
})

test('суперадмин: роль «Суперадминистратор», пункт «Пользователи и организации»', async ({ page }) => {
  await loginAs(page, 'super')
  await page.goto('/dashboard')
  const menu = page.getByRole('button', { name: 'Меню пользователя' })
  await expect(menu).toContainText('Суперадминистратор')
  await menu.click()
  await page.getByRole('button', { name: 'Пользователи и организации' }).click()
  await expect(page).toHaveURL(/\/admin\/users$/)
})

test('смена пароля: неверный текущий, несовпадающий повтор, короткий; успешная смена', async ({ page, request }) => {
  const user = await createUser(request, { email: unique('chpass') })
  await fillLogin(page, user.email, user.password)
  await expect(page).toHaveURL(/\/dashboard$/)
  await page.goto('/change-password')
  const submit = page.getByRole('button', { name: 'Сменить пароль' })

  await page.getByLabel('Текущий пароль').fill('wrong-current-1')
  await page.getByLabel('Новый пароль (от 12 символов)').fill('Brand-new-pass-1')
  await page.getByLabel('Повторите новый пароль').fill('Brand-new-pass-2')
  await submit.click()
  await expect(page.getByText('Новый пароль и повтор не совпадают')).toBeVisible()

  await page.getByLabel('Повторите новый пароль').fill('Brand-new-pass-1')
  await submit.click()
  await expect(page.locator('.text-red-300')).toBeVisible()
  await expect(page.locator('.text-red-300')).not.toHaveText('Новый пароль и повтор не совпадают')

  // короткий пароль браузер не отправит (minLength=12)
  await page.getByLabel('Текущий пароль').fill(user.password)
  await page.getByLabel('Новый пароль (от 12 символов)').fill('short')
  await page.getByLabel('Повторите новый пароль').fill('short')
  await submit.click()
  await expect(page).toHaveURL(/\/change-password$/)

  await page.getByLabel('Новый пароль (от 12 символов)').fill('Brand-new-pass-1')
  await page.getByLabel('Повторите новый пароль').fill('Brand-new-pass-1')
  await submit.click()
  await expect(page).toHaveURL(/\/dashboard$/)

  // старый пароль больше не подходит, новый — подходит
  const old = await request.post('/api/auth/login', { data: { email: user.email, password: user.password } })
  expect(old.status()).toBe(401)
  const fresh = await request.post('/api/auth/login', { data: { email: user.email, password: 'Brand-new-pass-1' } })
  expect(fresh.ok()).toBeTruthy()
})

test('временный пароль: до смены — только форма смены, «Выйти» работает', async ({ page, request }) => {
  const user = await createUser(request, { email: unique('temp'), keepTemporary: true })
  await fillLogin(page, user.email, user.password)
  await expect(page.getByRole('heading', { name: 'Задайте свой пароль' })).toBeVisible()
  await expect(page.getByRole('navigation')).toHaveCount(0)
  await page.goto('/agents')
  await expect(page.getByRole('heading', { name: 'Задайте свой пароль' })).toBeVisible()
  await page.getByRole('button', { name: 'Выйти' }).click()
  await expect(page).toHaveURL(/\/login$/)

  await fillLogin(page, user.email, user.password)
  await page.getByLabel('Временный пароль').fill(user.password)
  await page.getByLabel('Новый пароль (от 12 символов)').fill('My-own-password-1')
  await page.getByLabel('Повторите новый пароль').fill('My-own-password-1')
  await page.getByRole('button', { name: 'Сменить пароль' }).click()
  await expect(page.getByRole('heading', { name: 'Обзор' })).toBeVisible()
})

test('2FA: подключение, резервные коды, вход с кодом и резервным кодом, «Назад», отключение', async ({ page, request }) => {
  test.setTimeout(150_000)
  const user = await createUser(request, { email: unique('twofa') })
  await fillLogin(page, user.email, user.password)
  await expect(page).toHaveURL(/\/dashboard$/)
  await page.goto('/two-factor')
  await expect(page.getByText('2FA выключена')).toBeVisible()

  // начать и отменить
  await page.getByRole('button', { name: 'Подключить 2FA' }).click()
  await expect(page.getByAltText('QR-код для приложения-аутентификатора')).toBeVisible()
  await page.getByRole('button', { name: 'Отмена' }).click()
  await expect(page.getByText('2FA выключена')).toBeVisible()

  await page.getByRole('button', { name: 'Подключить 2FA' }).click()
  const secret = (await page.locator('code').first().textContent()).trim()
  await page.getByPlaceholder('Код из приложения (6 цифр)').fill('000000')
  await page.getByRole('button', { name: 'Включить 2FA' }).click()
  await expect(page.getByText('Ошибка', { exact: true })).toBeVisible()
  await page.getByPlaceholder('Код из приложения (6 цифр)').fill(totp(secret))
  await page.getByRole('button', { name: 'Включить 2FA' }).click()
  await expect(page.getByText('Резервные коды', { exact: true })).toBeVisible()
  const codes = await page.locator('.grid code').allTextContents()
  expect(codes).toHaveLength(8)
  await page.context().grantPermissions(['clipboard-read', 'clipboard-write'])
  await page.getByRole('button', { name: 'Скопировать все' }).click()
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(codes.join('\n'))
  await page.getByRole('button', { name: 'Я сохранил коды' }).click()
  await expect(page.getByText('2FA включена')).toBeVisible()
  await expect(page.getByText('Осталось резервных кодов: 8')).toBeVisible()

  // вход: пароль → код; неверный код; «Назад»
  await page.getByRole('button', { name: 'Меню пользователя' }).click()
  await page.getByRole('button', { name: 'Выйти' }).click()
  await fillLogin(page, user.email, user.password)
  await expect(page.getByLabel('Код 2FA или резервный код')).toBeVisible()
  await page.getByRole('button', { name: 'Подтвердить' }).click()
  await expect(page.getByText('Введите код из приложения-аутентификатора')).toBeVisible()
  await page.getByLabel('Код 2FA или резервный код').fill('123456')
  await page.getByRole('button', { name: 'Подтвердить' }).click()
  await expect(page.locator('.text-red-300')).toBeVisible()
  await page.getByRole('button', { name: 'Назад' }).click()
  await expect(page.getByLabel('Email')).toBeVisible()

  await nextTotpWindow()  // код, отклонённый выше, не «сжигает» интервал, но шаг подтверждения брал интервал при включении
  await page.getByLabel('Пароль').fill(user.password)
  await page.getByRole('button', { name: 'Войти' }).click()
  await page.getByLabel('Код 2FA или резервный код').fill(totp(secret))
  await page.getByRole('button', { name: 'Подтвердить' }).click()
  await expect(page).toHaveURL(/\/dashboard$/)

  // вход резервным кодом; тот же код второй раз не принимается
  await page.getByRole('button', { name: 'Меню пользователя' }).click()
  await page.getByRole('button', { name: 'Выйти' }).click()
  await fillLogin(page, user.email, user.password)
  await page.getByLabel('Код 2FA или резервный код').fill(codes[0])
  await page.getByRole('button', { name: 'Подтвердить' }).click()
  await expect(page).toHaveURL(/\/dashboard$/)
  await page.goto('/two-factor')
  await expect(page.getByText('Осталось резервных кодов: 7')).toBeVisible()
  await page.getByRole('button', { name: 'Меню пользователя' }).click()
  await page.getByRole('button', { name: 'Выйти' }).click()
  await fillLogin(page, user.email, user.password)
  await page.getByLabel('Код 2FA или резервный код').fill(codes[0])
  await page.getByRole('button', { name: 'Подтвердить' }).click()
  await expect(page.locator('.text-red-300')).toBeVisible()
  await page.getByLabel('Код 2FA или резервный код').fill(codes[1])
  await page.getByRole('button', { name: 'Подтвердить' }).click()
  await expect(page).toHaveURL(/\/dashboard$/)

  // отключение: неверный пароль — ошибка; верный пароль и резервный код — выключено
  await page.goto('/two-factor')
  await page.getByPlaceholder('Пароль').fill('wrong-password-1')
  await page.getByPlaceholder('Код 2FA или резервный код').fill(codes[2])
  await page.getByRole('button', { name: 'Отключить 2FA' }).click()
  await expect(page.getByText('Ошибка', { exact: true })).toBeVisible()
  await page.getByPlaceholder('Пароль').fill(user.password)
  await page.getByPlaceholder('Код 2FA или резервный код').fill(codes[2])
  await page.getByRole('button', { name: 'Отключить 2FA' }).click()
  await expect(page.getByText('2FA выключена')).toBeVisible()
})

test('обязательная 2FA (как на проде): без неё — только подключение; после — приложение', async ({ page, request }) => {
  const user = await createUser(request, { email: unique('forced') })
  // Браузер ходит в бэкенд с REQUIRE_2FA=true: те же БД и код, другой режим.
  await page.route((url) => url.pathname.startsWith('/api/'), async (route) => {
    const url = new URL(route.request().url())
    url.host = `127.0.0.1:${STRICT_BACKEND_PORT}`
    url.protocol = 'http:'
    await route.fulfill({ response: await route.fetch({ url: url.toString() }) })
  })
  await fillLogin(page, user.email, user.password)
  await expect(page.getByRole('heading', { name: 'Подключите двухфакторную защиту' })).toBeVisible()
  await expect(page.getByText('Сайт доступен из интернета, поэтому вход только с 2FA.')).toBeVisible()
  await expect(page.getByRole('navigation')).toHaveCount(0)
  await page.goto('/agents')
  await expect(page.getByRole('heading', { name: 'Подключите двухфакторную защиту' })).toBeVisible()

  await page.getByRole('button', { name: 'Подключить 2FA' }).click()
  const secret = (await page.locator('code').first().textContent()).trim()
  await page.getByPlaceholder('Код из приложения (6 цифр)').fill(totp(secret))
  await page.getByRole('button', { name: 'Включить 2FA' }).click()
  await page.getByRole('button', { name: 'Я сохранил коды' }).click()
  await expect(page.getByRole('heading', { name: 'Агенты' })).toBeVisible()
})

test('блокировка после 5 неудачных попыток; суперадмин сбрасывает пароль — вход снова возможен', async ({ page, request }) => {
  const user = await createUser(request, { email: unique('lock') })
  for (let i = 0; i < 5; i++) {
    await request.post('/api/auth/login', { data: { email: user.email, password: `wrong-password-${i}` } })
  }
  await fillLogin(page, user.email, user.password)  // верный пароль, но учётка заблокирована
  await expect(page.locator('.text-red-300')).toBeVisible()
  await expect(page).toHaveURL(/\/login$/)
})
