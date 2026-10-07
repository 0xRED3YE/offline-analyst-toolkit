/*
 * ioc.js: find, classify, refang and defang indicators of compromise.
 *
 * Types: url, domain, ipv4, ipv6, email, md5, sha1, sha256, sha512, cve, mitre.
 * Domains are checked against the bundled IANA TLD list (lib/tlds.js) to cut
 * false positives such as "invoice.pdf.exe" or "System.Net.WebClient".
 */
(function (root, factory) {
  const lib = factory();
  if (typeof module === 'object' && module.exports) module.exports = lib;
  else (root.OAT = root.OAT || {}).ioc = lib;
})(globalThis, function () {
  'use strict';

  const tlds = () => globalThis.OAT.tlds;

  const TYPES = [
    { id: 'url', label: 'URLs' },
    { id: 'domain', label: 'Domains' },
    { id: 'ipv4', label: 'IPv4' },
    { id: 'ipv6', label: 'IPv6' },
    { id: 'email', label: 'Emails' },
    { id: 'md5', label: 'MD5' },
    { id: 'sha1', label: 'SHA-1' },
    { id: 'sha256', label: 'SHA-256' },
    { id: 'sha512', label: 'SHA-512' },
    { id: 'cve', label: 'CVE IDs' },
    { id: 'mitre', label: 'MITRE ATT&CK' },
  ];

  // TLDs that are also common file extensions. "report.zip" is more likely a file
  // than a domain, so these are only reported when the caller asks for them.
  // (.cc and .so are left out on purpose: both are real, frequently abused TLDs.)
  const FILE_LIKE_TLDS = new Set(['zip', 'mov', 'py', 'sh', 'md', 'pl', 'ps', 'rs', 'cs', 'js', 'ts', 'rar', 'tar', 'bin', 'log', 'ini', 'dat', 'tmp', 'sys']);

  // ---------------------------------------------------------------- Refang / defang

  // Undo the common defanging styles. Applied before extraction so
  // "hxxps://evil[.]com" and "user[@]evil(.)com" are found.
  function refang(text) {
    return text
      .replace(/\bh(?:xx|XX|\*\*|tt)p(s?)(?=\[?:)/g, 'http$1')
      .replace(/\bfxp(?=\[?:)/gi, 'ftp')
      .replace(/\[:\/\/\]/g, '://')
      .replace(/\[:\]|\(:\)/g, ':')
      .replace(/\s?\[(?:\.|dot)\]\s?|\s?\((?:\.|dot)\)\s?|\{(?:\.|dot)\}|\[\s\.\s\]/gi, '.')
      .replace(/\\\./g, '.')
      .replace(/\s?\[(?:@|at)\]\s?|\s?\((?:@|at)\)\s?|\{@\}/gi, '@');
  }

  // Defang every indicator in the text, leaving everything else untouched.
  // Already-defanged input is refanged first, so running this twice is safe.
  function defang(text, { fileLike = false } = {}) {
    const clean = refang(text);
    const spans = outermost(findAll(clean, { fileLike }).filter((m) => ['url', 'domain', 'ipv4', 'ipv6', 'email'].includes(m.type)));
    let out = '';
    let last = 0;
    for (const m of spans) {
      out += clean.slice(last, m.start) + defangValue(m.type, clean.slice(m.start, m.end));
      last = m.end;
    }
    return { text: out + clean.slice(last), count: spans.length };
  }

  function defangValue(type, v) {
    switch (type) {
      case 'url': {
        const m = v.match(/^([a-z][a-z0-9+.-]*):\/\/([^/?#]*)(.*)$/is);
        if (!m) return v.replace(/\./g, '[.]');
        const scheme = m[1].toLowerCase().replace(/^http/, 'hxxp').replace(/^ftp/, 'fxp');
        return `${scheme}[://]${m[2].replace(/\./g, '[.]')}${m[3]}`;
      }
      case 'email': return v.replace('@', '[@]').replace(/\./g, '[.]');
      case 'ipv6': return v.replace(/:/g, '[:]');
      default: return v.replace(/\./g, '[.]');
    }
  }

  // Keep only spans that are not inside an earlier, longer span.
  function outermost(matches) {
    const sorted = [...matches].sort((a, b) => a.start - b.start || b.end - a.end);
    const out = [];
    let reach = -1;
    for (const m of sorted) {
      if (m.start >= reach) { out.push(m); reach = m.end; }
    }
    return out;
  }

  // ---------------------------------------------------------------- Matching

  const OCTET = '(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)';
  const RE = {
    url: /\b(?:https?|ftp):\/\/[^\s<>"'`{}|\\^]+/gi,
    email: /\b[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z][A-Za-z0-9-]{1,62}\b/g,
    // Not part of a longer dotted number (1.2.3.4.5) or preceded by digits.
    ipv4: new RegExp(`(?<![\\d.]\\d*)(?<!\\d\\.)${OCTET}(?:\\.${OCTET}){3}(?!\\.?\\d)`, 'g'),
    ipv6: /(?<![0-9a-f:.])(?:[0-9a-f]{0,4}:){2,7}(?:(?:\d{1,3}\.){3}\d{1,3}|[0-9a-f]{1,4})?(?![0-9a-f:])/gi,
    domain: /(?<![\w@.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})(?![\w-])/gi,
    hash: /\b(?:[a-f0-9]{128}|[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b/gi,
    cve: /\bCVE-\d{4}-\d{4,7}\b/gi,
    mitre: /\bT1\d{3}(?:\.\d{3})?\b/g,
  };

  const HASH_TYPES = { 32: 'md5', 40: 'sha1', 64: 'sha256', 128: 'sha512' };

  function validIpv6(v) {
    if ((v.match(/::/g) || []).length > 1) return false;
    // At least two non-empty groups, so code like "std::" or "a::b" is not an address.
    if (v.split(':').filter(Boolean).length < 2) return false;
    const groups = v.split(':').length;
    if (!v.includes('::') && groups !== 8 && !(groups === 7 && v.includes('.'))) return false;
    try { new URL(`http://[${v}]/`); return true; } catch (_) { return false; }
  }

  // Strip trailing punctuation that belongs to the sentence, not the URL.
  function trimUrl(url) {
    let u = url.replace(/[.,;:!?'"*]+$/, '');
    while (u.endsWith(')') && (u.match(/\(/g) || []).length < (u.match(/\)/g) || []).length) u = u.slice(0, -1);
    while (u.endsWith(']') && !u.includes('[')) u = u.slice(0, -1);
    return u.replace(/[.,;:!?'"*]+$/, '');
  }

  function domainInfo(d) {
    const tld = d.slice(d.lastIndexOf('.') + 1).toLowerCase();
    return { valid: tlds().has(tld), fileLike: FILE_LIKE_TLDS.has(tld) };
  }

  // Every match with its position: [{ type, value, start, end }].
  function findAll(text, { fileLike = false } = {}) {
    const out = [];
    const push = (type, value, start, end) => out.push({ type, value, start, end });
    let m;

    for (const re of Object.values(RE)) re.lastIndex = 0;

    while ((m = RE.url.exec(text))) {
      const v = trimUrl(m[0]);
      push('url', v, m.index, m.index + v.length);
    }
    while ((m = RE.email.exec(text))) {
      if (domainInfo(m[0]).valid) push('email', m[0].toLowerCase(), m.index, m.index + m[0].length);
    }
    while ((m = RE.ipv4.exec(text))) {
      // "version 1.2.3.4" and "v1.2.3.4" are versions, not addresses.
      if (/(?:\bv|\bver\.?|\bversion)\s*$/i.test(text.slice(Math.max(0, m.index - 10), m.index))) continue;
      push('ipv4', m[0], m.index, m.index + m[0].length);
    }
    while ((m = RE.ipv6.exec(text))) {
      if (validIpv6(m[0])) push('ipv6', m[0].toLowerCase(), m.index, m.index + m[0].length);
    }
    while ((m = RE.domain.exec(text))) {
      const v = m[0].replace(/\.$/, '');
      const info = domainInfo(v);
      if (!info.valid || (info.fileLike && !fileLike)) continue;
      if (/^[\d.]+$/.test(v)) continue;   // numbers like 1.2.3
      push('domain', v.toLowerCase(), m.index, m.index + v.length);
    }
    while ((m = RE.hash.exec(text))) {
      push(HASH_TYPES[m[0].length], m[0].toLowerCase(), m.index, m.index + m[0].length);
    }
    while ((m = RE.cve.exec(text))) push('cve', m[0].toUpperCase(), m.index, m.index + m[0].length);
    while ((m = RE.mitre.exec(text))) push('mitre', m[0], m.index, m.index + m[0].length);

    return out;
  }

  // Deduplicated, counted indicators, in first-seen order within each type.
  // Returns [{ type, value, count, note? }].
  function extract(text, { refangFirst = true, fileLike = false } = {}) {
    const source = refangFirst ? refang(text) : text;
    const byKey = new Map();
    for (const m of findAll(source, { fileLike })) {
      const key = `${m.type}\u0000${m.value}`;
      const item = byKey.get(key);
      if (item) item.count++;
      else byKey.set(key, { type: m.type, value: m.value, count: 1 });
    }
    const order = Object.fromEntries(TYPES.map((t, i) => [t.id, i]));
    const items = [...byKey.values()].sort((a, b) => order[a.type] - order[b.type]);
    for (const it of items) {
      if (it.type === 'ipv4' || it.type === 'ipv6') {
        const scope = ipScope(it.value);
        if (scope !== 'public') it.note = scope;
      }
      if (it.type === 'domain' && domainInfo(it.value).fileLike) it.note = 'may be a file name';
    }
    return items;
  }

  // ---------------------------------------------------------------- IP scope

  function ipv4Scope(ip) {
    const [a, b, c] = ip.split('.').map(Number);
    if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return 'private';
    if (a === 127) return 'loopback';
    if (a === 169 && b === 254) return 'link-local';
    if (a === 100 && b >= 64 && b <= 127) return 'carrier-grade NAT';
    if (a >= 224 && a <= 239) return 'multicast';
    if (a === 0 || a >= 240) return 'reserved';
    if ((a === 192 && b === 0 && c === 2) || (a === 198 && b === 51 && c === 100) || (a === 203 && b === 0 && c === 113)) return 'documentation';
    if (a === 198 && (b === 18 || b === 19)) return 'benchmarking';
    return 'public';
  }

  function ipv6Scope(ip) {
    const v = ip.toLowerCase();
    if (v === '::1') return 'loopback';
    if (/^fe[89ab]/.test(v)) return 'link-local';
    if (/^f[cd]/.test(v)) return 'private';
    if (/^ff/.test(v)) return 'multicast';
    if (/^2001:0?db8:/.test(v)) return 'documentation';
    const mapped = v.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return ipv4Scope(mapped[1]);
    return 'public';
  }

  function ipScope(ip) {
    return ip.includes(':') ? ipv6Scope(ip) : ipv4Scope(ip);
  }

  // What kind of indicator is this single value? Returns a type id or null.
  function classify(value) {
    const v = refang(value.trim());
    const found = outermost(findAll(v, { fileLike: true }));
    return found.length === 1 && found[0].start === 0 && found[0].end === v.length ? found[0].type : null;
  }

  return { TYPES, refang, defang, findAll, extract, ipScope, classify };
});
