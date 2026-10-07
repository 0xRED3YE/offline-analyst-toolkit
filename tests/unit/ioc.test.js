/* Unit tests for src/lib/ioc.js, including the tricky corpus from the spec. */
(function () {
  'use strict';
  const I = globalThis.OAT.ioc;
  const values = (text, type, opts) => I.extract(text, opts).filter((x) => x.type === type).map((x) => x.value);
  const json = (v) => JSON.stringify(v);

  const LOG = `
2026-10-07T08:12:44Z proxy ALLOW src=10.20.30.40 dst=185.220.101.47 url=hxxps://login-micros0ft[.]com/auth?x=1
Mail from billing@invoice-portal.co.uk relayed via 2001:db8:85a3::8a2e:370:7334 and fe80::1
Payload sha256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 md5 d41d8cd98f00b204e9800998ecf8427e
sha1 da39a3ee5e6b4b0d3255bfef95601890afd80709. Exploits CVE-2021-44228 and cve-2023-23397 (T1566.001, T1059).
Agent version 1.2.3.4 and v10.0.0.1 are versions; 1.2.3.4.5 is not an IP; 256.1.1.1 is invalid.
Dropped invoice.pdf.exe and System.Net.WebClient then report.zip; callback 45.13.227.9:8443.
See https://example.org/path_(x)/page.html, and (http://evil.example.net/a).
Defanged: 8.8.8[.]8, evil[.]top, user[@]phish(.)ru, hxxp[:]//bad.biz/x
`;

  test('extracts URLs and trims sentence punctuation', () => {
    assert.equal(json(values(LOG, 'url')), json([
      'https://login-micros0ft.com/auth?x=1',
      'https://example.org/path_(x)/page.html',
      'http://evil.example.net/a',
      'http://bad.biz/x',
    ]));
  });

  test('extracts IPv4, skipping versions, 5-part numbers and invalid octets', () => {
    assert.equal(json(values(LOG, 'ipv4')), json(['10.20.30.40', '185.220.101.47', '45.13.227.9', '8.8.8.8']));
  });

  test('extracts and validates IPv6', () => {
    assert.equal(json(values(LOG, 'ipv6')), json(['2001:db8:85a3::8a2e:370:7334', 'fe80::1']));
    assert.equal(values('time 10:20:30 mac 00:1a:2b:3c:4d:5e std::string', 'ipv6').length, 0);
  });

  test('domains need a real TLD; file names and .NET types are skipped', () => {
    const d = values(LOG, 'domain');
    for (const want of ['login-micros0ft.com', 'example.org', 'evil.example.net', 'evil.top', 'bad.biz']) {
      assert.ok(d.includes(want), `missing ${want}`);
    }
    for (const bad of ['invoice.pdf.exe', 'system.net.webclient', 'report.zip', 'page.html']) {
      assert.ok(!d.includes(bad), `should not include ${bad}`);
    }
    assert.ok(!d.includes('invoice-portal.co.uk'), 'domain inside an email is reported as the email');
  });

  test('file-like TLDs are included only on request, and marked', () => {
    const items = I.extract('see report.zip', { fileLike: true }).filter((x) => x.type === 'domain');
    assert.equal(items.length, 1);
    assert.equal(items[0].note, 'may be a file name');
  });

  test('emails, hashes, CVEs and ATT&CK IDs', () => {
    assert.equal(json(values(LOG, 'email')), json(['billing@invoice-portal.co.uk', 'user@phish.ru']));
    assert.equal(json(values(LOG, 'sha256')), json(['9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08']));
    assert.equal(json(values(LOG, 'md5')), json(['d41d8cd98f00b204e9800998ecf8427e']));
    assert.equal(json(values(LOG, 'sha1')), json(['da39a3ee5e6b4b0d3255bfef95601890afd80709']));
    assert.equal(json(values(LOG, 'cve')), json(['CVE-2021-44228', 'CVE-2023-23397']));
    assert.equal(json(values(LOG, 'mitre')), json(['T1566.001', 'T1059']));
  });

  test('deduplicates and counts', () => {
    const items = I.extract('8.8.8.8 and 8.8.8.8 and 8[.]8[.]8[.]8');
    assert.equal(items.length, 1);
    assert.equal(items[0].count, 3);
  });

  test('private and reserved IPs are marked', () => {
    const notes = Object.fromEntries(I.extract('10.0.0.1 192.168.1.1 127.0.0.1 169.254.1.1 100.64.0.1 8.8.8.8 ::1 fd00::1').map((x) => [x.value, x.note || 'public']));
    assert.equal(notes['10.0.0.1'], 'private');
    assert.equal(notes['192.168.1.1'], 'private');
    assert.equal(notes['127.0.0.1'], 'loopback');
    assert.equal(notes['169.254.1.1'], 'link-local');
    assert.equal(notes['100.64.0.1'], 'carrier-grade NAT');
    assert.equal(notes['8.8.8.8'], 'public');
    assert.equal(notes['fd00::1'], 'private');
  });

  test('refang handles the common styles', () => {
    assert.equal(I.refang('hxxps[://]evil[.]com'), 'https://evil.com');
    assert.equal(I.refang('hXXp://a(.)b{.}c[dot]d'), 'http://a.b.c.d');
    assert.equal(I.refang('user[@]mail[.]ru and admin(at)x[.]io'), 'user@mail.ru and admin@x.io');
    assert.equal(I.refang('1.2.3[.]4 evil\\.com'), '1.2.3.4 evil.com');
  });

  test('defang changes only indicators and is idempotent', () => {
    const src = 'Block https://evil.com/a.php?id=1 and 185.220.101.47, mail bob@evil.com; keep report.zip and v1.2.3.4.';
    const once = I.defang(src);
    assert.equal(once.text, 'Block hxxps[://]evil[.]com/a.php?id=1 and 185[.]220[.]101[.]47, mail bob[@]evil[.]com; keep report.zip and v1.2.3.4.');
    assert.equal(once.count, 3);
    assert.equal(I.defang(once.text).text, once.text, 'defanging twice changes nothing');
    assert.equal(I.refang(once.text), src);
  });

  test('classify single values', () => {
    assert.equal(I.classify('8.8.8.8'), 'ipv4');
    assert.equal(I.classify('evil[.]com'), 'domain');
    assert.equal(I.classify('hxxp://evil.com/x'), 'url');
    assert.equal(I.classify('d41d8cd98f00b204e9800998ecf8427e'), 'md5');
    assert.equal(I.classify('CVE-2021-44228'), 'cve');
    assert.equal(I.classify('hello world'), null);
  });
})();
