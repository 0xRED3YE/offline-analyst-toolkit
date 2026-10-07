#!/usr/bin/env node
/*
 * End-to-end smoke test: opens dist/analyst-toolkit.html from file:// in a real
 * Edge or Chrome (installed browser, no download), exercises every module, and
 * fails if the page makes ANY network request or logs an error.
 *
 *   npm run build && npm run test:e2e        (add --headed to watch)
 */
'use strict';

const path = require('path');
const crypto = require('crypto');
const { pathToFileURL } = require('url');
const { chromium } = require('playwright-core');

const FILE = path.join(__dirname, '..', '..', 'dist', 'analyst-toolkit.html');
const URL_ = pathToFileURL(FILE).href;
const headed = process.argv.includes('--headed');

const results = [];
async function check(name, fn) {
  try { await fn(); results.push({ name, ok: true }); }
  catch (e) { results.push({ name, ok: false, error: e.message.split('\n')[0] }); }
}
function expect(cond, msg) { if (!cond) throw new Error(msg); }

async function launch() {
  for (const channel of ['msedge', 'chrome']) {
    try { return await chromium.launch({ channel, headless: !headed }); } catch (_) { /* try the next one */ }
  }
  throw new Error('Neither Microsoft Edge nor Google Chrome could be started');
}

(async () => {
  const browser = await launch();
  const context = await browser.newContext({ acceptDownloads: true });
  const page = await context.newPage();

  const network = [];
  const errors = [];
  // Anything that leaves the machine. Browser-internal pages (edge://, chrome://,
  // e.g. the downloads panel opened by the CSV export) are not network traffic.
  const offMachine = /^(?:https?|wss?|ftp):/i;
  context.on('request', (r) => { if (offMachine.test(r.url())) network.push(r.url()); });
  page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
  page.on('pageerror', (e) => errors.push(e.message));

  await page.goto(URL_);
  const wait = (ms) => page.waitForTimeout(ms);
  const go = async (id) => { await page.evaluate((h) => { location.hash = h; }, id); await wait(150); return page.locator(`#mod-${id}`); };

  await check('all 14 modules are listed and mount', async () => {
    const ids = await page.$$eval('#module-list button', (b) => b.map((x) => x.dataset.id));
    expect(ids.join() === 'encode,hash,time,jwt,ps,ioc,defang,url,lookup,email,diff,regex,entropy,case', `modules: ${ids}`);
    for (const id of ids) {
      const m = await go(id);
      expect(await m.isVisible(), `${id} not visible`);
      expect(await m.locator('.error').count() === 0, `${id} shows an error`);
    }
  });

  await check('CSP blocks network access from the page', async () => {
    const blocked = await page.evaluate(async () => {
      try { await fetch('https://example.com/'); return false; } catch (_) { return true; }
    });
    expect(blocked, 'fetch to example.com was not blocked');
  });

  await check('Encode: PowerShell -EncodedCommand is detected and decoded', async () => {
    const m = await go('encode');
    await m.locator('textarea').fill('VwByAGkAdABlAC0ASABvAHMAdAAgACcAaABpACcA');
    await m.locator('.suggestion').first().click();
    expect((await m.locator('pre.output').textContent()) === "Write-Host 'hi'", 'wrong decode');
  });

  await check('Hashing: 30 MB file in a Web Worker matches OpenSSL', async () => {
    const m = await go('hash');
    const buf = crypto.randomBytes(30 * 1024 * 1024 + 7);
    await m.locator('input[type=file]').setInputFiles({ name: 'big.bin', mimeType: 'application/octet-stream', buffer: buf });
    await m.locator('.file-job code.hash').first().waitFor({ timeout: 60000 });
    const text = await m.locator('.file-job').textContent();
    expect(text.includes('Web Worker'), `did not use the worker: ${text.slice(0, 120)}`);
    for (const alg of ['md5', 'sha1', 'sha256', 'sha512']) {
      const want = crypto.createHash(alg).update(buf).digest('hex');
      expect(text.includes(want), `${alg} mismatch`);
    }
  });

  await check('IOC Extractor: finds refanged indicators and exports CSV', async () => {
    const m = await go('ioc');
    await m.locator('textarea').fill('C2 hxxps://evil-update[.]com/gate from 185.220.101.47, CVE-2021-44228 (T1059.001)');
    await wait(400);
    const cells = await m.locator('tbody code').allTextContents();
    for (const want of ['https://evil-update.com/gate', 'evil-update.com', '185.220.101.47', 'CVE-2021-44228', 'T1059.001']) {
      expect(cells.includes(want), `missing ${want} in ${cells}`);
    }
    const [dl] = await Promise.all([page.waitForEvent('download'), m.getByRole('button', { name: 'CSV' }).click()]);
    expect(dl.suggestedFilename() === 'iocs.csv', 'csv name');
  });

  await check('Defang: indicators only, idempotent', async () => {
    const m = await go('defang');
    await m.locator('textarea').fill('Block https://evil.com/x and 1.2.3.4.');
    await wait(300);
    expect((await m.locator('pre.output').textContent()) === 'Block hxxps[://]evil[.]com/x and 1[.]2[.]3[.]4.', 'defang output');
  });

  await check('JWT: decodes and verifies HS256 locally', async () => {
    const m = await go('jwt');
    await m.locator('textarea').fill('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c');
    await wait(300);
    expect((await m.locator('pre.json').nth(1).textContent()).includes('John Doe'), 'payload');
    await m.locator('input[type=password]').fill('your-256-bit-secret');
    await m.getByRole('button', { name: 'Verify' }).click();
    expect((await m.textContent()).includes('Signature valid'), 'verify');
  });

  await check('Timestamp: FILETIME with Kigali time', async () => {
    const m = await go('time');
    await m.locator('input.input').fill('133444736000000000');
    await wait(300);
    const t = await m.locator('.reading').first().textContent();
    expect(t.includes('2023-11-14T22:13:20Z') && t.includes('00:13:20 (GMT+2)'), t);
  });

  await check('Email: findings, and hostile header values stay text', async () => {
    const m = await go('email');
    await m.locator('textarea').fill([
      'Received: from a.example.net (a.example.net [41.186.20.11]) by mx.company.rw; Tue, 7 Oct 2026 16:00:03 +0000',
      'Authentication-Results: mx.company.rw; spf=fail smtp.mailfrom=x.com; dmarc=fail header.from=bk.rw',
      'From: "Bank" <alerts@bk-login.com>', 'Reply-To: pay@protonmail.com',
      'Subject: <img src=x onerror="document.title=\'pwned\'">', '',
    ].join('\n'));
    await wait(400);
    const text = await m.textContent();
    expect(text.includes('DMARC fail') && text.includes('Reply-To domain'), 'findings');
    expect(await m.locator('img').count() === 0, 'an <img> was created from header text');
    expect((await page.title()) !== 'pwned', 'script ran');
  });

  await check('Lookup: links are https, new tab, no referrer', async () => {
    const m = await go('lookup');
    await m.locator('textarea').fill('8.8.8.8');
    await wait(300);
    const links = await m.locator('a.btn').evaluateAll((as) => as.map((a) => [a.href, a.rel, a.target]));
    expect(links.length >= 3, 'links');
    for (const [href, rel, target] of links) expect(href.startsWith('https://') && rel.includes('noreferrer') && target === '_blank', href);
  });

  await check('URL Analyzer: unwraps SafeLinks → Google → obfuscated IP', async () => {
    const m = await go('url');
    const inner = `https://www.google.com/url?q=${encodeURIComponent('http://0x7f.0.0.1/login.php')}`;
    await m.locator('textarea').fill(`https://eur01.safelinks.protection.outlook.com/?url=${encodeURIComponent(inner)}&data=05`);
    await wait(400);
    expect((await m.locator('code.big-url').textContent()) === 'http://127.0.0.1/login.php', 'final URL');
    expect((await m.textContent()).includes('Obfuscated IP address'), 'finding');
  });

  await check('PowerShell: nested -enc layers decode to readable script', async () => {
    const m = await go('ps');
    const enc = (s) => Buffer.from(s, 'utf16le').toString('base64');
    await m.locator('textarea').fill(`powershell -nop -enc ${enc(`powershell -w hidden -enc ${enc("& (\"{1}{0}\" -f 'ost','Write-H') ('he'+'llo')")}`)}`);
    await wait(700);
    expect((await m.locator('pre.output').first().textContent()) === "Write-Host 'hello'", 'final script');
    expect((await m.textContent()).includes('Hidden window'), 'finding');
  });

  await check('Text Diff: side by side with word marks', async () => {
    const m = await go('diff');
    await m.locator('textarea').nth(0).fill('host=10.0.0.1\nport=443');
    await m.locator('textarea').nth(1).fill('host=10.0.0.9\nport=443');
    await wait(400);
    expect((await m.locator('table.diff mark').allTextContents()).join() === '1,9', 'word marks');
  });

  await check('Regex Tester: catastrophic pattern is stopped, page stays usable', async () => {
    const m = await go('regex');
    await m.locator('textarea').fill(`${'a'.repeat(34)}!`);
    await m.locator('input.big').fill('(a+)+$');
    await m.locator('.notice').waitFor({ timeout: 6000 });
    expect((await m.locator('.notice').textContent()).includes('Stopped'), 'timeout notice');
    await m.locator('input.big').fill('a{3}');
    await wait(500);
    expect((await m.textContent()).includes('11 matches'), 'works again after the timeout');
  });

  await check('Entropy: random half of a file is flagged', async () => {
    const m = await go('entropy');
    const buf = Buffer.concat([crypto.randomBytes(32768), Buffer.alloc(32768, 0x41)]);
    await m.locator('input[type=file]').setInputFiles({ name: 'half.bin', mimeType: 'application/octet-stream', buffer: buf });
    await m.locator('svg.entropy-svg').waitFor();
    const hot = await m.locator('svg rect.bar-hot').count();
    const all = await m.locator('svg rect.bar, svg rect.bar-hot').count();
    expect(hot === all / 2, `${hot} of ${all} blocks flagged`);
  });

  await check('Case Notes: receives IOCs, exports escaped HTML, stores nothing by default', async () => {
    const m = await go('case');
    await m.locator('textarea').first().fill('C2 at hxxps://bad-host[.]com/x and 185.220.101.47');
    await m.getByRole('button', { name: 'Add', exact: true }).click();
    expect((await m.locator('tbody tr').count()) === 3, 'three IOCs');
    const [dl] = await Promise.all([page.waitForEvent('download'), m.getByRole('button', { name: 'Download HTML' }).click()]);
    const html = require('fs').readFileSync(await dl.path(), 'utf8');
    expect(html.includes('hxxps[://]bad-host[.]com') && html.includes("default-src 'none'"), 'defanged report with CSP');
    expect(await page.evaluate(() => localStorage.getItem('oat.case.v1')) === null, 'nothing stored without opt-in');
  });

  await check('no network requests were made', async () => {
    expect(network.length === 0, `${network.length} request(s): ${network.slice(0, 10).join(', ')}`);
  });

  await check('no console errors', async () => {
    const real = errors.filter((e) => !/example\.com|Content Security Policy/.test(e));   // our own blocked-fetch probe
    expect(real.length === 0, real.join(' | '));
  });

  await browser.close();

  let failed = 0;
  for (const r of results) {
    if (r.ok) console.log(`  ✓ ${r.name}`);
    else { failed++; console.log(`  ✗ ${r.name}\n      ${r.error}`); }
  }
  console.log(`\n${results.length - failed}/${results.length} passed (${URL_})`);
  process.exitCode = failed ? 1 : 0;
})().catch((e) => { console.error(e); process.exitCode = 1; });
