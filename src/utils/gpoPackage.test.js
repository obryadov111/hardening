import { test } from "node:test";
import assert from "node:assert/strict";
import {
  GPO_DEFAULTS,
  buildGpoPackage,
  buildStoredZip,
  crc32,
  gpoPackageReadme,
  gpoParameterLine,
  sha256Hex,
} from "./gpoPackage.js";

const PIN = "sha256//F2IS+EuQnazu4oq6kt82+KkSARv4DiztB0hU9vOzdsU=";
const KEY = "yak_test-site-key-value";

test("crc32 совпадает с контрольным значением PNG/ZIP", () => {
  assert.equal(crc32(new TextEncoder().encode("123456789")), 0xcbf43926);
});

test("строка параметров GPO содержит адрес, ключ, пин и паузы сценария", () => {
  const line = gpoParameterLine({
    server: "https://audit.hardening-audit.ru",
    siteKey: KEY,
    packPublicKey: "ed25519-public=",
    pin: PIN,
  });
  assert.equal(
    line,
    [
      "-Server https://audit.hardening-audit.ru",
      `-SiteKey ${KEY}`,
      "-PackPublicKey ed25519-public=",
      `-Pin ${PIN}`,
      `-Share ${GPO_DEFAULTS.share}`,
      "-InitialJitterMaxSeconds 900",
      "-RetryBudgetSeconds 1800",
      "-BootstrapEveryMinutes 15",
      "-BootstrapRandomDelayMinutes 15",
    ].join(" "),
  );
  assert.equal(line.includes("--enroll"), false);
  assert.equal(line.includes("--pin-sha256"), false);
});

test("без пина и без ключа паков эти параметры в строку не попадают", () => {
  const line = gpoParameterLine({ server: "https://audit.example.ru", siteKey: KEY });
  assert.equal(line.includes("-Pin"), false);
  assert.equal(line.includes("-PackPublicKey"), false);
  assert.match(line, /^-Server https:\/\/audit\.example\.ru -SiteKey /);
});

test("пробел в пути общей папки берётся в кавычки", () => {
  const line = gpoParameterLine({
    server: "https://audit.example.ru",
    siteKey: KEY,
    share: "\\\\corp\\NETLOGON\\Hardening Agent",
  });
  assert.match(line, /-Share "\\\\corp\\NETLOGON\\Hardening Agent"/);
});

test("README архива объясняет site.key и не содержит ключ площадки", () => {
  const text = gpoPackageReadme({ server: "https://audit.hardening-audit.ru", pin: PIN });
  assert.match(text, /site\.key/);
  assert.match(text, /Hardening agent bootstrap/);
  assert.match(text, /175151\.htm/);
  assert.match(text, /123510\.htm/);
  assert.match(text, /Континент 4/);
  assert.match(text, /TLS_PIN_MISMATCH/);
  assert.match(text, /Retry-After/);
  assert.match(text, /gpo-startup\.log/);
  assert.equal(text.includes(KEY), false);
  assert.equal(text.includes("yak_"), false);
});

test("архив без опубликованных файлов содержит параметры; README ключ не повторяет", async () => {
  const { zip, missing, filename } = await buildGpoPackage({
    server: "https://audit.hardening-audit.ru",
    siteKey: KEY,
    packPublicKey: "pub=",
    pin: PIN,
    files: [],
  });
  assert.deepEqual(missing, ["gpo-startup.ps1", "hardening-agent.exe"]);
  assert.equal(filename, "hardening-gpo.zip");
  assert.equal(String.fromCharCode(zip[0], zip[1]), "PK");
  const text = new TextDecoder().decode(zip);
  assert.match(text, new RegExp(`-SiteKey ${KEY}`));
  assert.match(text, new RegExp(`-Pin ${PIN.replaceAll("+", "\\+")}`));
  assert.match(text, /-InitialJitterMaxSeconds 900/);
  assert.match(text, /-RetryBudgetSeconds 1800/);
  assert.match(text, /-BootstrapEveryMinutes 15/);
  assert.match(text, /-BootstrapRandomDelayMinutes 15/);
  const readmeAt = text.indexOf("Пакет групповой политики");
  assert.equal(text.slice(readmeAt).includes(KEY), false);
});

test("чужой SHA-256 обрывает сборку и не отдаёт архив", async () => {
  await assert.rejects(
    () => buildGpoPackage({
      server: "https://audit.example.ru",
      siteKey: KEY,
      files: [{ name: "gpo-startup.ps1", sha256: "ab".repeat(32) }],
      fetchFile: async () => new TextEncoder().encode("not-the-script"),
    }),
    /SHA-256/,
  );
});

test("совпавший файл сценария попадает в архив байт в байт", async () => {
  const script = new TextEncoder().encode("param([string]$Server)\r\n");
  const digest = await sha256Hex(script);
  const { zip, missing } = await buildGpoPackage({
    server: "https://audit.example.ru",
    siteKey: KEY,
    pin: PIN,
    files: [{ name: "gpo-startup.ps1", sha256: digest }],
    fetchFile: async (name) => {
      assert.equal(name, "gpo-startup.ps1");
      return script;
    },
  });
  assert.deepEqual(missing, ["hardening-agent.exe"]);
  const packed = buildStoredZip([{ name: "marker", data: script }]);
  assert.equal(packed.includes(script[0]), true);
  assert.equal(zip.includes(script[0]), true);
  const asText = Buffer.from(zip).toString("latin1");
  assert.equal(asText.includes("param([string]$Server)"), true);
});
