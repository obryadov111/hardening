/**
 * Пакет раскатки Windows через GPO. Собирается в браузере в момент создания ключа площадки:
 * сервер хранит только хэш ключа и повторить строку параметров не может.
 * Ключ попадает в gpo-parameters.txt. README архива ключ не содержит.
 * Сценарий на ПК пишет ключ в site.key (SYSTEM и администраторы) и удаляет файл после регистрации.
 */

export const GPO_DEFAULTS = {
  initialJitterMaxSeconds: 900,
  retryBudgetSeconds: 1800,
  bootstrapEveryMinutes: 15,
  bootstrapRandomDelayMinutes: 15,
  share: "\\\\ДОМЕН\\NETLOGON\\Hardening",
};

const SCRIPT_NAME = "gpo-startup.ps1";
const EXE_NAME = "hardening-agent.exe";

function quoteArg(value) {
  const text = String(value);
  if (text === "" || /[\s"]/.test(text)) return `"${text.replaceAll('"', '`"')}"`;
  return text;
}

/** Одна строка параметров для вкладки «Сценарии PowerShell» и для немедленной задачи. */
export function gpoParameterLine({ server, siteKey, packPublicKey, pin, share } = {}) {
  if (!server) throw new Error("Нет адреса сервера");
  if (!siteKey) throw new Error("Нет ключа площадки");
  const parts = ["-Server", quoteArg(server), "-SiteKey", quoteArg(siteKey)];
  if (packPublicKey) parts.push("-PackPublicKey", quoteArg(packPublicKey));
  if (pin) parts.push("-Pin", quoteArg(pin));
  parts.push(
    "-Share",
    quoteArg(share || GPO_DEFAULTS.share),
    "-InitialJitterMaxSeconds",
    String(GPO_DEFAULTS.initialJitterMaxSeconds),
    "-RetryBudgetSeconds",
    String(GPO_DEFAULTS.retryBudgetSeconds),
    "-BootstrapEveryMinutes",
    String(GPO_DEFAULTS.bootstrapEveryMinutes),
    "-BootstrapRandomDelayMinutes",
    String(GPO_DEFAULTS.bootstrapRandomDelayMinutes),
  );
  return parts.join(" ");
}

/** Текст для администратора домена внутри архива. Секрет сюда не подставляется. */
export function gpoPackageReadme({ server, pin } = {}) {
  const host = server || "https://audit.hardening-audit.ru";
  const pinLine = pin
    ? `В строке параметров уже стоит -Pin ${pin}. Это отпечаток из version.json сервера.`
    : "В строке параметров нет -Pin: version.json ещё не отдал server_pin. Незарегистрированный ПК один раз берёт пин из version.json. После TLS_PIN_MISMATCH этот источник запирается, и пин нужно дописать в политику явно.";
  return `Пакет групповой политики агента «Харденинг»
==========================================

Адрес сервера: ${host}
Ключ площадки лежит только в файле gpo-parameters.txt (одна строка параметров).
Повторно сайт его не показывает: сервер хранит хэш.

Что в архиве
------------
- gpo-parameters.txt — параметры сценария. Замените ДОМЕН на DNS-имя домена.
- gpo-startup.ps1 — сценарий автозагрузки, если он был опубликован на сервере.
- hardening-agent.exe — агент, если он был опубликован. В git этого файла нет.
  Его же отдаёт ${host}/downloads/hardening-agent.exe
  и релиз GitHub (workflow windows-release.yml, тег agent-* или v*).

${pinLine}

Как хранится ключ на ПК
-----------------------
Сценарий пишет ключ в C:\\ProgramData\\HardeningAgent\\site.key.
Каталог и файл доступны только SYSTEM и группе администраторов.
В аргументы задачи «Hardening agent bootstrap» ключ не входит.
В журнал gpo-startup.log ключ не пишется.
После регистрации файл site.key удаляется, остаётся host.json с ключом этого ПК.
В SYSVOL строка параметров видна пользователям домена, поэтому срок ключа на время раскатки короткий.
Уже зарегистрированные ПК от этого ключа не зависят.

Перед раскаткой
---------------
1. Kaspersky Endpoint Security. В политике KSC исключите домен сервера из проверки защищённых соединений.
   Статья «Исключение защищенных соединений из проверки»:
   https://support.kaspersky.com/KESWIN/12.8/ru-RU/175151.htm
   Политики → свойства → Общие настройки → Настройки сети → Проверка защищенных соединений → Настроить доверенные адреса → Добавить.
2. Если после исключения домена на пробных ПК остаётся TLS_PIN_MISMATCH, добавьте в доверенные программы
   C:\\Program Files\\Hardening\\hardening-agent.exe и отметьте «Не проверять сетевой трафик».
   Статья «Формирование списка доверенных программ»:
   https://support.kaspersky.com/keswin/11/ru-RU/123510.htm
3. Любой другой антивирус или шлюз, который подменяет сертификат, нуждается в таком же исключении домена.
   Периметровый межсетевой экран этой инфраструктуры — Континент 4. Проверьте, что для домена сервера
   инспекция TLS выключена. Отпечаток, который ПК увидел на проводе, в -Pin не добавляют.
4. С ПК домена: Test-NetConnection к порту 443 сервера, TcpTestSucceeded = True.

NETLOGON
--------
На контроллере домена создайте \\\\ДОМЕН\\NETLOGON\\Hardening и положите туда
gpo-startup.ps1 и hardening-agent.exe из этого архива (или заново с ${host}/downloads/, сверив SHA-256 с version.json).

Групповая политика
------------------
Конфигурация компьютера → Политики → Конфигурация Windows → Сценарии (запуск/завершение) → Автозагрузка.
Вкладка «Сценарии PowerShell» (не «Сценарии»).
Имя сценария: \\\\ДОМЕН\\NETLOGON\\Hardening\\gpo-startup.ps1
Параметры сценария: строка из gpo-parameters.txt, целиком, после замены ДОМЕН.

Чтобы не ждать перезагрузку, в той же политике создайте немедленную задачу (Windows 7 и выше)
от SYSTEM с наивысшими правами. Программа: powershell.exe.
Аргументы: -NoProfile -ExecutionPolicy Bypass -File "\\\\ДОМЕН\\NETLOGON\\Hardening\\gpo-startup.ps1" и та же строка параметров.

Применение и партии
-------------------
Сначала 10 ПК. На пробном: gpupdate /target:computer /force
Дальше 50, затем партии по 100. Между партиями пауза 5 минут.
Лимиты nginx из-за раскатки не поднимают.

Проверка
--------
Журнал: C:\\ProgramData\\HardeningAgent\\gpo-startup.log
Задача планировщика: «Hardening agent bootstrap» (после регистрации её снимает сценарий, остаётся «Hardening agent»).
Файл C:\\ProgramData\\HardeningAgent\\host.json появляется после регистрации.
ПК виден на сайте в «Агенты» → «Хосты» и в текущем прогоне.

Если что-то пошло не так
------------------------
- code=TLS_PIN_MISMATCH, выход агента 76, рядом code=TLS_INSPECTION.
  Сертификат подменён. Исключение домена в KES или на Континенте 4. Новый -Pin из журнала не составляют.
- Ответ 429 и заголовок Retry-After. Агент повторяет запрос в бюджете -RetryBudgetSeconds (1800).
  После бюджета выход 75, задача bootstrap повторит через 15–30 минут.
- Таймаут скачивания (60 с) и code=VERSION_UNAVAILABLE или code=None: нет маршрута до 443 или нужен -Proxy.
- code=SHA256_MISMATCH: в NETLOGON лежит файл, который не совпал с version.json. Положите опубликованную пару файлов.

Обновление
----------
Новые gpo-startup.ps1 и hardening-agent.exe кладут в ту же папку NETLOGON.
ПК сверяют SHA-256 сами. Уже зарегистрированные компьютеры снимать не нужно:
ключ хоста у них свой, site.key к этому моменту уже удалён.

Удаление с одного ПК
--------------------
Уберите ПК из области действия политики, затем в PowerShell от администратора:

Unregister-ScheduledTask -TaskName 'Hardening agent bootstrap' -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'Hardening agent' -Confirm:$false
Remove-Item -Recurse -Force 'C:\\Program Files\\Hardening','C:\\ProgramData\\HardeningAgent'

После этого удалите регистрацию этого имени на сайте, если имя нужно занять снова.
ПК, которые продолжают работать, этой командой не трогают.
`;
}

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    table[n] = c >>> 0;
  }
  return table;
})();

export function crc32(bytes) {
  let c = 0xffffffff;
  for (let i = 0; i < bytes.length; i += 1) c = CRC_TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function dosDateTime(date) {
  const time = (date.getHours() << 11) | (date.getMinutes() << 5) | Math.floor(date.getSeconds() / 2);
  const day = ((date.getFullYear() - 1980) << 9) | ((date.getMonth() + 1) << 5) | date.getDate();
  return { time, day };
}

/** ZIP без сжатия (STORE) и с именами в UTF-8. Подходит для exe: байты файла лежат в архиве как есть. */
export function buildStoredZip(files, date = new Date(2026, 10, 8, 12, 0, 0)) {
  const encoder = new TextEncoder();
  const { time, day } = dosDateTime(date);
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const file of files) {
    const name = encoder.encode(file.name);
    const data = typeof file.data === "string" ? encoder.encode(file.data) : file.data;
    const crc = crc32(data);
    const local = new Uint8Array(30 + name.length + data.length);
    const view = new DataView(local.buffer);
    view.setUint32(0, 0x04034b50, true);
    view.setUint16(4, 20, true);
    view.setUint16(6, 0x0800, true);
    view.setUint16(8, 0, true);
    view.setUint16(10, time, true);
    view.setUint16(12, day, true);
    view.setUint32(14, crc, true);
    view.setUint32(18, data.length, true);
    view.setUint32(22, data.length, true);
    view.setUint16(26, name.length, true);
    view.setUint16(28, 0, true);
    local.set(name, 30);
    local.set(data, 30 + name.length);
    locals.push(local);

    const central = new Uint8Array(46 + name.length);
    const centralView = new DataView(central.buffer);
    centralView.setUint32(0, 0x02014b50, true);
    centralView.setUint16(4, 20, true);
    centralView.setUint16(6, 20, true);
    centralView.setUint16(8, 0x0800, true);
    centralView.setUint16(10, 0, true);
    centralView.setUint16(12, time, true);
    centralView.setUint16(14, day, true);
    centralView.setUint32(16, crc, true);
    centralView.setUint32(20, data.length, true);
    centralView.setUint32(24, data.length, true);
    centralView.setUint16(28, name.length, true);
    centralView.setUint16(30, 0, true);
    centralView.setUint16(32, 0, true);
    centralView.setUint16(34, 0, true);
    centralView.setUint16(36, 0, true);
    centralView.setUint32(38, 0, true);
    centralView.setUint32(42, offset, true);
    central.set(name, 46);
    centrals.push(central);
    offset += local.length;
  }
  const centralSize = centrals.reduce((sum, part) => sum + part.length, 0);
  const end = new Uint8Array(22);
  const endView = new DataView(end.buffer);
  endView.setUint32(0, 0x06054b50, true);
  endView.setUint16(4, 0, true);
  endView.setUint16(6, 0, true);
  endView.setUint16(8, files.length, true);
  endView.setUint16(10, files.length, true);
  endView.setUint32(12, centralSize, true);
  endView.setUint32(16, offset, true);
  endView.setUint16(20, 0, true);
  const out = new Uint8Array(offset + centralSize + end.length);
  let pos = 0;
  for (const part of [...locals, ...centrals, end]) {
    out.set(part, pos);
    pos += part.length;
  }
  return out;
}

export async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function fetchPublished(name, expectedSha) {
  const response = await fetch(`/downloads/${name}`, { cache: "no-store" });
  if (!response.ok) throw new Error(`Не удалось скачать ${name}: ответ ${response.status}`);
  const data = new Uint8Array(await response.arrayBuffer());
  if (expectedSha) {
    const got = await sha256Hex(data);
    if (got !== expectedSha.toLowerCase()) {
      throw new Error(`SHA-256 файла ${name} не совпал с version.json. Пакет не собран.`);
    }
  }
  return data;
}

/**
 * Архив для одного ключа. files — список из version.json.
 * fetchFile(name, sha256) подменяется в тестах. Без опубликованного файла имя попадает в missing,
 * чужая контрольная сумма прерывает сборку.
 */
export async function buildGpoPackage({ server, siteKey, packPublicKey, pin, files, fetchFile } = {}) {
  const parameterLine = gpoParameterLine({ server, siteKey, packPublicKey, pin });
  const readme = gpoPackageReadme({ server, pin });
  const entries = [
    { name: "gpo-parameters.txt", data: `${parameterLine}\n` },
    { name: "README.txt", data: readme },
  ];
  const missing = [];
  const load = fetchFile || fetchPublished;
  for (const name of [SCRIPT_NAME, EXE_NAME]) {
    const meta = (files || []).find((file) => file.name === name);
    if (!meta) {
      missing.push(name);
      continue;
    }
    const data = await load(name, meta.sha256);
    if (meta.sha256) {
      const got = await sha256Hex(data);
      if (got !== String(meta.sha256).toLowerCase()) {
        throw new Error(`SHA-256 файла ${name} не совпал с version.json. Пакет не собран.`);
      }
    }
    entries.push({ name, data });
  }
  return {
    zip: buildStoredZip(entries),
    parameterLine,
    missing,
    filename: "hardening-gpo.zip",
  };
}
