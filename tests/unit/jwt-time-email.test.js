/* Unit tests for src/lib/jwt.js, src/lib/time.js, src/lib/email.js and src/lib/lookup.js. */
(function () {
  'use strict';
  const { jwt: J, time: T, email: E, lookup: L } = globalThis.OAT;

  // ------------------------------------------------------------ JWT

  // The well-known jwt.io sample, signed with the secret "your-256-bit-secret".
  const JWT_IO = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

  test('JWT: decodes the jwt.io sample', () => {
    const r = J.decode(JWT_IO, Date.UTC(2026, 0, 1));
    assert.equal(r.header.alg, 'HS256');
    assert.equal(r.payload.name, 'John Doe');
    assert.equal(r.times[0].claim, 'iat');
    assert.equal(r.times[0].date.toISOString(), '2018-01-18T01:30:22.000Z');
    assert.ok(r.findings.some((f) => /No expiry/.test(f.text)));
  });

  test('JWT: HMAC verification with the right and wrong secret', () => {
    assert.equal(J.verifyHmac(JWT_IO, 'your-256-bit-secret'), true);
    assert.equal(J.verifyHmac(JWT_IO, 'wrong'), false);
    assert.equal(J.verifyHmac(`Bearer ${JWT_IO}`, 'your-256-bit-secret'), true, 'Bearer prefix is accepted');
  });

  test('JWT: HS384/HS512 round trip', () => {
    for (const alg of ['HS384', 'HS512']) {
      const tok = J.signHmac({ alg, typ: 'JWT' }, { sub: 'x' }, 's3cret');
      assert.equal(J.verifyHmac(tok, 's3cret'), true, alg);
      assert.equal(J.verifyHmac(tok, 'nope'), false, alg);
    }
  });

  test('JWT: flags alg none, expiry, nbf and remote keys', () => {
    const c = globalThis.OAT.codecs;
    const enc = (o) => c.base64Encode(c.utf8(JSON.stringify(o)), { urlSafe: true });
    const now = Date.UTC(2026, 9, 7) ;
    const nowS = now / 1000;
    const tok = `${enc({ alg: 'none', jku: 'https://attacker.example/keys' })}.${enc({ exp: nowS - 3600, nbf: nowS + 7200 })}.`;
    const text = J.decode(tok, now).findings.map((f) => `${f.level}: ${f.text}`).join('\n');
    assert.ok(/high: alg is "none"/.test(text), text);
    assert.ok(/Expired 60 minutes ago/.test(text), text);
    assert.ok(/Not valid yet/.test(text), text);
    assert.ok(/"jku" points to a remote key/.test(text), text);
  });

  test('JWT: clear errors for malformed tokens', () => {
    assert.throws(() => J.decode('abc.def'), /3 parts/);
    assert.throws(() => J.decode('!!!.e30.x'), /Header is not valid Base64URL/);
    assert.throws(() => J.decode('e30.bm90IGpzb24.x'), /Payload is not valid JSON/);
  });

  // ------------------------------------------------------------ Timestamps

  const NOW = Date.UTC(2026, 9, 7, 12, 0, 0);
  const firstIso = (s) => T.toIso(T.interpret(s, NOW)[0].ticks);
  const ids = (s) => T.interpret(s, NOW).map((r) => r.id);

  test('Time: Unix seconds, milliseconds and fractions', () => {
    assert.equal(firstIso('1700000000'), '2023-11-14T22:13:20Z');
    assert.equal(ids('1700000000')[0], 'unix_s');
    assert.equal(firstIso('1700000000123'), '2023-11-14T22:13:20.123Z');
    assert.equal(firstIso('1700000000.5'), '2023-11-14T22:13:20.5Z');
  });

  test('Time: FILETIME / LDAP decimal and hex keep 100 ns precision', () => {
    assert.equal(firstIso('133419744001234567'), '2023-10-17T00:00:00.1234567Z');
    assert.equal(ids('133419744001234567')[0], 'filetime');
    assert.equal(firstIso('0x01DA01A1E8E8C287'), T.toIso(T.interpret(String(0x01DA01A1E8E8C287n), NOW).find((r) => r.id === 'filetime').ticks));
    assert.equal(firstIso('01DA01A1:E8E8C287'), firstIso('0x01DA01A1E8E8C287'));
  });

  test('Time: Chrome/WebKit microseconds', () => {
    // 2023-11-14T22:13:20Z in WebKit time = (1700000000 + 11644473600) * 1e6
    const r = T.interpret('13344473600000000', NOW).find((x) => x.id === 'webkit');
    assert.ok(r, 'webkit reading present');
    assert.equal(T.toIso(r.ticks), '2023-11-14T22:13:20Z');
  });

  test('Time: date strings, zone-less read as UTC', () => {
    assert.equal(firstIso('2024-02-29 13:45:00'), '2024-02-29T13:45:00Z');
    assert.ok(/read as UTC/.test(T.interpret('2024-02-29 13:45:00', NOW)[0].label));
    assert.equal(firstIso('Tue, 15 Nov 1994 08:12:31 +0200'), '1994-11-15T06:12:31Z');
    assert.equal(T.interpret('not a date', NOW).length, 0);
  });

  test('Time: conversions round trip and Kigali time', () => {
    const ticks = T.interpret('1700000000', NOW)[0].ticks;
    const conv = Object.fromEntries(T.conversions(ticks).map((r) => [r.id, r.value]));
    assert.equal(conv.unix_ms, '1700000000000');
    assert.equal(conv.filetime, '133444736000000000');
    assert.equal(conv.webkit, '13344473600000000');
    assert.equal(conv.filetime_hex, '0x01DA1747C66D0000');
    assert.equal(T.inZone(ticks, 'Africa/Kigali'), 'Wed 2023-11-15 00:13:20 (GMT+2)');
  });

  test('Time: likely readings come first', () => {
    const r = T.interpret('1700000000', NOW);
    assert.ok(r[0].likely && r[0].id === 'unix_s');
    assert.ok(r.filter((x) => x.likely).length >= 1);
    assert.ok(r.some((x) => !x.likely), 'the 1970 millisecond reading is kept but marked unlikely');
  });

  // ------------------------------------------------------------ Email headers

  const HEADERS = [
    'Delivered-To: victim@company.rw',
    'Received: by 2002:a05:6a10:1234 with SMTP id abc;',
    '        Tue, 7 Oct 2026 09:00:05 -0700 (PDT)',
    'Received: from mail.sender-relay.net (mail.sender-relay.net [203.0.113.50])',
    '        by mx.company.rw (Postfix) with ESMTPS id 4XYZ;',
    '        Tue, 7 Oct 2026 16:00:03 +0000',
    'Received: from [192.168.1.20] (unknown [198.51.100.23])',
    '        by mail.sender-relay.net with ESMTPSA id 77;',
    '        Tue, 7 Oct 2026 16:00:01 +0000',
    'Authentication-Results: mx.company.rw;',
    '       spf=softfail (domain does not designate) smtp.mailfrom=bounce.sender-relay.net;',
    '       dkim=pass header.d=sender-relay.net;',
    '       dmarc=fail (p=REJECT) header.from=paypal.com',
    'Received-SPF: softfail (mx.company.rw: domain of transitioning bounce@sender-relay.net)',
    'From: "PayPal Support support@paypal.com" <security@paypa1-alerts.com>',
    'Reply-To: refunds@gmail.com',
    'Return-Path: <bounce@bounce.sender-relay.net>',
    'Subject: Your account is limited',
    'Date: Tue, 7 Oct 2026 16:00:00 +0000',
    'Message-ID: <abc123@sender-relay.net>',
    'X-Mailer: PHPMailer 6.0',
    '',
    'Body text that must be ignored: Received: fake',
  ].join('\r\n');

  test('Email: headers are unfolded and the body is ignored', () => {
    const h = E.parseHeaders(HEADERS);
    assert.equal(h.filter((x) => x.name === 'Received').length, 3);
    assert.ok(h[2].value.startsWith('from mail.sender-relay.net (mail.sender-relay.net [203.0.113.50]) by mx.company.rw'));
    assert.ok(!h.some((x) => /fake/.test(x.value)));
  });

  test('Email: relay path oldest first, with delays and originating IP', () => {
    const r = E.analyze(HEADERS);
    assert.equal(r.hops.length, 3);
    assert.equal(r.hops[0].by, 'mail.sender-relay.net');
    assert.equal(JSON.stringify(r.hops[0].ips), '["192.168.1.20","198.51.100.23"]');
    assert.equal(r.hops[1].delay, 2);
    assert.equal(r.hops[2].delay, 2);
    // 198.51.100.23 is a documentation range, so the first *public* hop IP is not it.
    // 203.0.113.50 is documentation too: no public IP, nothing invented.
    assert.equal(r.summary.originatingIp, '');
    const pub = E.analyze(HEADERS.replace('198.51.100.23', '41.186.20.11'));
    assert.equal(pub.summary.originatingIp, '41.186.20.11');
  });

  test('Email: authentication results and findings', () => {
    const r = E.analyze(HEADERS);
    const res = Object.fromEntries(r.auth.filter((a) => a.source === 'Authentication-Results').map((a) => [a.method, a.result]));
    assert.equal(JSON.stringify(res), '{"spf":"softfail","dkim":"pass","dmarc":"fail"}');
    const text = r.findings.map((f) => `${f.level}: ${f.text}`).join('\n');
    assert.ok(/high: DMARC fail/.test(text), text);
    assert.ok(/high: Reply-To domain \(gmail.com\)/.test(text), text);
    assert.ok(/high: Display name shows a different address \("support@paypal.com"\)/.test(text), text);
    assert.ok(/medium: Return-Path domain/.test(text), text);
    assert.equal(r.findings[0].level, 'high', 'sorted by severity');
  });

  test('Email: organisational domain handles co.uk style suffixes', () => {
    assert.equal(E.orgDomain('mail.example.co.uk'), 'example.co.uk');
    assert.equal(E.orgDomain('a.b.example.com'), 'example.com');
    assert.equal(E.parseAddress('"Doe, John" <John@Example.com>').address, 'john@example.com');
  });

  // ------------------------------------------------------------ Lookup links

  test('Lookup: links per type are https and encode the value', () => {
    const ip = L.linksFor('ipv4', '8.8.8.8');
    assert.ok(ip.length >= 3 && ip.every((l) => l.url.startsWith('https://')));
    assert.equal(L.linksFor('mitre', 'T1566.001')[0].url, 'https://attack.mitre.org/techniques/T1566/001/');
    assert.ok(L.linksFor('domain', 'a"b.com')[0].url.includes('a%22b.com'));
    assert.equal(L.linksFor('email', 'x@y.com').length, 0);
  });
})();
