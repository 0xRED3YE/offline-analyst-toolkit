/*
 * email.js: parse raw email headers into the facts an analyst checks first:
 * the relay path with delays, the authentication results the receiving server
 * recorded, sender address mismatches and the originating IP.
 *
 * SPF/DKIM/DMARC are NOT re-verified here (that needs DNS). We report what the
 * receiving server wrote in Authentication-Results / Received-SPF.
 */
(function (root, factory) {
  const lib = factory();
  if (typeof module === 'object' && module.exports) module.exports = lib;
  else (root.OAT = root.OAT || {}).email = lib;
})(globalThis, function () {
  'use strict';

  const ioc = () => globalThis.OAT.ioc;

  // Unfold continuation lines and split into [{ name, value }], in original order.
  // Stops at the first blank line after the headers (the start of the body).
  function parseHeaders(raw) {
    const lines = raw.replace(/\r\n?/g, '\n').split('\n');
    const headers = [];
    let started = false;
    for (const line of lines) {
      if (!line.trim()) { if (started) break; continue; }
      if (/^[ \t]/.test(line) && headers.length) {
        headers[headers.length - 1].value += ' ' + line.trim();
        continue;
      }
      const m = line.match(/^([!-9;-~]+):\s?(.*)$/);   // printable ASCII name, no spaces or colon
      if (m) { headers.push({ name: m[1], value: m[2].trim() }); started = true; }
    }
    return headers;
  }

  const get = (headers, name) => headers.filter((h) => h.name.toLowerCase() === name.toLowerCase()).map((h) => h.value);
  const first = (headers, name) => get(headers, name)[0] || '';

  // "Display Name <user@example.com>" -> { display, address, domain }
  function parseAddress(value) {
    if (!value) return null;
    const angle = value.match(/<([^<>\s]+@[^<>\s]+)>/);
    const bare = value.match(/[^\s<>"',;:()]+@[^\s<>"',;:()]+/);
    const address = ((angle && angle[1]) || (bare && bare[0]) || '').toLowerCase();
    if (!address) return null;
    let display = angle ? value.slice(0, value.indexOf('<')).trim().replace(/^"|"$/g, '') : '';
    display = display.replace(/\\"/g, '"');
    return { display, address, domain: address.slice(address.lastIndexOf('@') + 1) };
  }

  // Rough organisational domain: last two labels, or three for "co.uk"-style suffixes.
  function orgDomain(domain) {
    const labels = domain.toLowerCase().split('.').filter(Boolean);
    if (labels.length <= 2) return labels.join('.');
    const sld = labels[labels.length - 2];
    const tld = labels[labels.length - 1];
    const take = tld.length === 2 && /^(?:co|com|org|net|ac|gov|edu|ne|or|go)$/.test(sld) ? 3 : 2;
    return labels.slice(-take).join('.');
  }

  function parseReceived(value) {
    const semi = value.lastIndexOf(';');
    const body = semi >= 0 ? value.slice(0, semi) : value;
    const dateText = semi >= 0 ? value.slice(semi + 1).trim() : '';
    const ms = Date.parse(dateText.replace(/\s*\([^)]*\)\s*$/, ''));
    const grab = (re) => { const m = body.match(re); return m ? m[1] : ''; };
    const from = grab(/\bfrom\s+(\S+)/i);
    const fromDetail = grab(/\bfrom\s+\S+\s+\(([^)]*)\)/i);
    const ips = [...new Set(ioc().findAll(`${from} ${fromDetail}`).filter((m) => m.type === 'ipv4' || m.type === 'ipv6').map((m) => m.value))];
    return {
      from, fromDetail, ips,
      by: grab(/\bby\s+(\S+)/i),
      with: grab(/\bwith\s+(\S+)/i),
      date: Number.isNaN(ms) ? null : new Date(ms),
      raw: value,
    };
  }

  // Authentication-Results: "mx.example.com; spf=pass smtp.mailfrom=a.com; dkim=fail header.d=b.com"
  function parseAuthResults(value, source) {
    const out = [];
    const re = /\b(spf|dkim|dmarc|arc|compauth|bimi)\s*=\s*([a-z]+)([^;]*)/gi;
    let m;
    while ((m = re.exec(value))) {
      const detail = m[3].replace(/\s*\([^)]*\)/g, '').trim();
      out.push({ method: m[1].toLowerCase(), result: m[2].toLowerCase(), detail, source });
    }
    return out;
  }

  function analyze(raw) {
    const headers = parseHeaders(raw);
    const findings = [];
    const add = (level, text) => findings.push({ level, text });

    const from = parseAddress(first(headers, 'From'));
    const replyTo = parseAddress(first(headers, 'Reply-To'));
    const returnPath = parseAddress(first(headers, 'Return-Path'));
    const sender = parseAddress(first(headers, 'Sender'));
    const messageId = first(headers, 'Message-ID');

    // ------------------------------------------------ Relay path (oldest hop first)
    const hops = get(headers, 'Received').map(parseReceived).reverse();
    hops.forEach((hop, i) => {
      const prev = hops[i - 1];
      hop.delay = prev && prev.date && hop.date ? Math.round((hop.date - prev.date) / 1000) : null;
      if (hop.delay !== null && hop.delay < -60) add('low', `Hop ${i + 1} is timestamped ${-hop.delay}s before the previous hop (clock skew, or a forged Received header).`);
      if (hop.delay !== null && hop.delay > 3600) add('info', `Hop ${i + 1} took ${Math.round(hop.delay / 60)} minutes.`);
    });

    // ------------------------------------------------ Originating IP
    let originatingIp = '';
    let originatingSource = '';
    for (const name of ['X-Originating-IP', 'X-Sender-IP', 'X-Source-IP']) {
      const v = first(headers, name);
      const ip = v && ioc().findAll(v).find((m) => m.type === 'ipv4' || m.type === 'ipv6');
      if (ip) { originatingIp = ip.value; originatingSource = name; break; }
    }
    if (!originatingIp) {
      for (const hop of hops) {
        const pub = hop.ips.find((ip) => ioc().ipScope(ip) === 'public');
        if (pub) { originatingIp = pub; originatingSource = 'first Received hop with a public IP'; break; }
      }
    }

    // ------------------------------------------------ Authentication
    const auth = [
      ...get(headers, 'Authentication-Results').flatMap((v) => parseAuthResults(v, 'Authentication-Results')),
      ...get(headers, 'ARC-Authentication-Results').flatMap((v) => parseAuthResults(v, 'ARC-Authentication-Results')),
    ];
    for (const v of get(headers, 'Received-SPF')) {
      const m = v.match(/^\s*([a-z]+)/i);
      if (m) auth.push({ method: 'spf', result: m[1].toLowerCase(), detail: v.slice(m[0].length).trim(), source: 'Received-SPF' });
    }
    const primary = auth.filter((a) => a.source !== 'ARC-Authentication-Results');
    for (const method of ['spf', 'dkim', 'dmarc']) {
      const results = primary.filter((a) => a.method === method).map((a) => a.result);
      if (!results.length) continue;
      if (results.some((r) => ['fail', 'softfail', 'permerror', 'temperror'].includes(r))) {
        add(method === 'dmarc' ? 'high' : 'medium', `${method.toUpperCase()} ${results.find((r) => r !== 'pass')} recorded by the receiving server.`);
      } else if (results.every((r) => r === 'none' || r === 'neutral')) {
        add('low', `${method.toUpperCase()} result is "${results[0]}": the sender domain does not protect itself with ${method.toUpperCase()}.`);
      }
    }
    if (!auth.length) add('info', 'No Authentication-Results or Received-SPF headers found. The receiving server may not record them, or they were stripped.');

    // ------------------------------------------------ Address mismatches
    if (from) {
      if (replyTo && orgDomain(replyTo.domain) !== orgDomain(from.domain)) {
        add('high', `Reply-To domain (${replyTo.domain}) differs from From domain (${from.domain}): replies go somewhere else.`);
      }
      if (returnPath && orgDomain(returnPath.domain) !== orgDomain(from.domain)) {
        add('medium', `Return-Path domain (${returnPath.domain}) differs from From domain (${from.domain}). Common for mailing services, also for spoofing.`);
      }
      const inDisplay = from.display.match(/[^\s<>"']+@[^\s<>"']+/);
      if (inDisplay && inDisplay[0].toLowerCase() !== from.address) {
        add('high', `Display name shows a different address ("${inDisplay[0]}") than the real sender (${from.address}).`);
      }
      const midDomain = (messageId.match(/@([^>\s]+)/) || [])[1];
      if (midDomain && orgDomain(midDomain) !== orgDomain(from.domain)) {
        add('info', `Message-ID domain (${midDomain}) differs from From domain (${from.domain}).`);
      }
      if (sender && orgDomain(sender.domain) !== orgDomain(from.domain)) {
        add('low', `Sender header (${sender.address}) differs from From (${from.address}).`);
      }
    } else {
      add('medium', 'No parseable From header.');
    }

    const order = { high: 0, medium: 1, low: 2, info: 3 };
    findings.sort((a, b) => order[a.level] - order[b.level]);

    return {
      headers,
      summary: {
        from, replyTo, returnPath, sender,
        to: first(headers, 'To'),
        subject: first(headers, 'Subject'),
        date: first(headers, 'Date'),
        messageId,
        mailer: first(headers, 'X-Mailer') || first(headers, 'User-Agent'),
        originatingIp, originatingSource,
      },
      hops, auth, findings,
    };
  }

  return { parseHeaders, parseAddress, orgDomain, analyze };
});
