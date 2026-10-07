/*
 * url.js: take a suspicious URL apart without visiting it.
 *
 *  - parts: scheme, credentials, host, port, path, query parameters, fragment
 *  - unwraps redirect wrappers layer by layer: Microsoft SafeLinks, Proofpoint
 *    URL Defense v1/v2/v3, Google, Facebook, Barracuda and generic ?url= params
 *  - flags look-alike (punycode) domains, obfuscated IP hosts, user@host tricks,
 *    shorteners, risky schemes and file downloads
 */
(function (root, factory) {
  const lib = factory();
  if (typeof module === 'object' && module.exports) module.exports = lib;
  else (root.OAT = root.OAT || {}).url = lib;
})(globalThis, function () {
  'use strict';

  const ioc = () => globalThis.OAT.ioc;
  const codecs = () => globalThis.OAT.codecs;

  // ---------------------------------------------------------------- Punycode (RFC 3492)

  const BASE = 36, T_MIN = 1, T_MAX = 26, SKEW = 38, DAMP = 700;

  function adapt(delta, numPoints, firstTime) {
    delta = firstTime ? Math.floor(delta / DAMP) : delta >> 1;
    delta += Math.floor(delta / numPoints);
    let k = 0;
    while (delta > ((BASE - T_MIN) * T_MAX) >> 1) { delta = Math.floor(delta / (BASE - T_MIN)); k += BASE; }
    return Math.floor(k + ((BASE - T_MIN + 1) * delta) / (delta + SKEW));
  }

  function punycodeDecode(input) {
    const output = [];
    let n = 128, i = 0, bias = 72;
    let basic = input.lastIndexOf('-');
    if (basic < 0) basic = 0;
    for (let j = 0; j < basic; j++) output.push(input.charCodeAt(j));
    for (let index = basic > 0 ? basic + 1 : 0; index < input.length;) {
      const oldi = i;
      let w = 1;
      for (let k = BASE; ; k += BASE) {
        if (index >= input.length) throw new Error('Invalid punycode');
        const c = input.charCodeAt(index++);
        const digit = c - 48 < 10 ? c - 22 : c - 65 < 26 ? c - 65 : c - 97 < 26 ? c - 97 : BASE;
        if (digit >= BASE) throw new Error('Invalid punycode');
        i += digit * w;
        const t = k <= bias ? T_MIN : k >= bias + T_MAX ? T_MAX : k - bias;
        if (digit < t) break;
        w *= BASE - t;
      }
      const out = output.length + 1;
      bias = adapt(i - oldi, out, oldi === 0);
      n += Math.floor(i / out);
      i %= out;
      output.splice(i++, 0, n);
    }
    return String.fromCodePoint(...output);
  }

  function toUnicodeHost(host) {
    return host.split('.').map((label) => {
      if (!/^xn--/i.test(label)) return label;
      try { return punycodeDecode(label.slice(4).toLowerCase()); } catch (_) { return label; }
    }).join('.');
  }

  // Characters from other scripts that look like Latin letters.
  const CONFUSABLE = {
    'а': 'a', 'в': 'b', 'е': 'e', 'ё': 'e', 'к': 'k', 'м': 'm', 'н': 'h', 'о': 'o', 'р': 'p', 'с': 'c', 'т': 't', 'у': 'y',
    'х': 'x', 'ѕ': 's', 'і': 'i', 'ї': 'i', 'ј': 'j', 'ӏ': 'l', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w', 'ɡ': 'g', 'һ': 'h', 'ո': 'n',
    'α': 'a', 'ο': 'o', 'ρ': 'p', 'ν': 'v', 'τ': 't', 'ι': 'i', 'κ': 'k', 'χ': 'x', 'υ': 'u', 'ε': 'e', 'β': 'b',
    'ı': 'i', 'ł': 'l', 'ß': 'b', 'ð': 'd', 'ø': 'o', 'ö': 'o', 'ó': 'o', 'ò': 'o', 'ô': 'o', 'õ': 'o', 'à': 'a', 'á': 'a',
    'â': 'a', 'ä': 'a', 'å': 'a', 'ã': 'a', 'è': 'e', 'é': 'e', 'ê': 'e', 'ë': 'e', 'ì': 'i', 'í': 'i', 'î': 'i', 'ï': 'i',
    'ù': 'u', 'ú': 'u', 'û': 'u', 'ü': 'u', 'ç': 'c', 'ñ': 'n', 'ý': 'y', 'ÿ': 'y',
  };

  function skeleton(text) {
    return [...text.normalize('NFC')].map((ch) => CONFUSABLE[ch] || CONFUSABLE[ch.toLowerCase()] || ch).join('');
  }

  function scriptsOf(label) {
    const found = new Set();
    for (const ch of label) {
      if (/[a-z0-9-]/i.test(ch)) found.add('Latin');
      else if (/\p{Script=Latin}/u.test(ch)) found.add('Latin');
      else if (/\p{Script=Cyrillic}/u.test(ch)) found.add('Cyrillic');
      else if (/\p{Script=Greek}/u.test(ch)) found.add('Greek');
      else if (/\p{Script=Armenian}/u.test(ch)) found.add('Armenian');
      else if (/\p{L}/u.test(ch)) found.add('Other');
    }
    return [...found];
  }

  // ---------------------------------------------------------------- Redirect unwrapping

  const REDIRECT_PARAMS = ['url', 'u', 'q', 'target', 'redirect', 'redirect_uri', 'redirect_url', 'redirecturl', 'next',
    'dest', 'destination', 'goto', 'link', 'r', 'return', 'returnurl', 'return_to', 'continue', 'to', 'out', 'href', 'uri', 'a'];

  // Proofpoint v3 replaces some characters with "*" and stores them (Base64URL) after "__;".
  function proofpointV3(href) {
    const m = href.match(/\/v3\/__(.+?)__;([^!]*)!/);
    if (!m) return null;
    const runLengths = {};
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'.split('').forEach((c, i) => { runLengths[c] = i + 2; });
    let chars;
    try { chars = [...codecs().text(codecs().base64Decode(m[2]))]; } catch (_) { chars = []; }
    let pos = 0;
    const url = m[1].replace(/\*(\*.)?/g, (tok, run) => {
      if (!run) return chars[pos++] || '';
      const len = runLengths[run[1]] || 0;
      const s = chars.slice(pos, pos + len).join('');
      pos += len;
      return s;
    });
    return url;
  }

  // Returns { url, via } for the next layer, or null if this URL does not wrap another.
  function unwrapOnce(u) {
    const host = u.hostname.toLowerCase();
    const p = u.searchParams;
    const get = (name) => { for (const [k, v] of p) if (k.toLowerCase() === name) return v; return null; };

    if (/\.safelinks\.protection\.outlook\.com$/.test(host) && get('url')) return { url: get('url'), via: 'Microsoft Defender SafeLinks' };
    if (host === 'urldefense.com' && u.pathname.startsWith('/v3/')) {
      const v = proofpointV3(u.href);
      if (v) return { url: v, via: 'Proofpoint URL Defense v3' };
    }
    if (/(^|\.)urldefense\.proofpoint\.com$/.test(host)) {
      if (u.pathname.startsWith('/v2/') && get('u')) return { url: decodeURIComponent(get('u').replace(/-/g, '%').replace(/_/g, '/')), via: 'Proofpoint URL Defense v2' };
      if (u.pathname.startsWith('/v1/') && get('u')) return { url: get('u'), via: 'Proofpoint URL Defense v1' };
    }
    if (/(^|\.)google\.[a-z.]+$/.test(host) && u.pathname === '/url' && (get('q') || get('url'))) return { url: get('q') || get('url'), via: 'Google redirect' };
    if (/^l\.(facebook|instagram|messenger)\.com$/.test(host) && get('u')) return { url: get('u'), via: 'Facebook link shim' };
    if (/(^|\.)linkprotect\.cudasvc\.com$/.test(host) && get('a')) return { url: get('a'), via: 'Barracuda Link Protection' };

    // Generic: a parameter whose value is (or Base64-encodes) an http(s) URL.
    for (const name of REDIRECT_PARAMS) {
      const v = get(name);
      if (!v) continue;
      if (/^(?:https?:)?\/\//i.test(v.trim())) return { url: v.trim().replace(/^\/\//, 'https://'), via: `"${name}" parameter (redirect)` };
      if (/^aHR0c[A-Za-z0-9+/_=-]{8,}$/.test(v)) {
        try {
          const decoded = codecs().text(codecs().base64Decode(v));
          if (/^https?:\/\//i.test(decoded)) return { url: decoded, via: `"${name}" parameter (Base64)` };
        } catch (_) { /* not Base64 */ }
      }
    }
    return null;
  }

  const SHORTENERS = new Set(['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly',
    'shorturl.at', 'rb.gy', 'tiny.cc', 'bl.ink', 'lnkd.in', 's.id', 't.ly', 'v.gd', 'qrco.de', 'shorturl.com', 'surl.li']);

  const RISKY_EXT = /\.(exe|scr|com|pif|bat|cmd|ps1|vbs|vbe|js|jse|wsf|hta|msi|msix|appx|dll|lnk|iso|img|vhd|vhdx|zip|rar|7z|cab|jar|apk|docm|xlsm|pptm|one|html?|svg)$/i;

  // ---------------------------------------------------------------- Analysis

  function rawAuthority(text) {
    const m = text.match(/^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)/i);
    return m ? m[1] : '';
  }

  function parse(text) {
    let t = ioc().refang(text.trim());
    if (!/^[a-z][a-z0-9+.-]*:/i.test(t)) t = `http://${t}`;
    const u = new URL(t);
    // Browsers differ here: Chrome percent-encodes some characters into the host
    // where the URL standard (and Node) refuse it. Treat those hosts as invalid everywhere.
    if (/[\s%<>"{}|\\^`]/.test(u.hostname)) throw new Error('Not a valid URL');
    return u;
  }

  // Returns { layers: [{ url, via, parts, findings }], final } or throws on an unparseable URL.
  function analyze(input) {
    const layers = [];
    let text = input.trim();
    let via = 'input';
    const seen = new Set();
    for (let depth = 0; depth < 10 && text; depth++) {
      let u;
      try { u = parse(text); } catch (_) {
        if (depth === 0) throw new Error('Not a valid URL');
        layers.push({ url: text, via, parts: null, findings: [{ level: 'medium', text: 'This layer is not a valid URL.' }] });
        break;
      }
      if (seen.has(u.href)) break;
      seen.add(u.href);
      const layer = { url: u.href, via, parts: partsOf(u), findings: findingsFor(u, ioc().refang(text)) };
      layers.push(layer);
      const next = unwrapOnce(u);
      if (!next) break;
      // A wrapper legitimately percent-encodes the URL it carries, so %25 is expected there.
      layer.findings = layer.findings.filter((f) => !/^Double URL encoding/.test(f.text));
      text = next.url;
      via = next.via;
    }
    return { layers, final: layers[layers.length - 1] };
  }

  function partsOf(u) {
    return {
      scheme: u.protocol.replace(/:$/, ''),
      username: decodeURIComponent(u.username),
      password: u.password ? '(present)' : '',
      host: u.hostname,
      hostUnicode: toUnicodeHost(u.hostname),
      port: u.port,
      path: safeDecode(u.pathname),
      query: [...u.searchParams].map(([k, v]) => ({ key: k, value: v })),
      fragment: safeDecode(u.hash.replace(/^#/, '')),
    };
  }

  function safeDecode(s) { try { return decodeURIComponent(s); } catch (_) { return s; } }

  function findingsFor(u, rawText) {
    const f = [];
    const add = (level, text) => f.push({ level, text });
    const scheme = u.protocol.replace(/:$/, '').toLowerCase();
    const host = u.hostname.toLowerCase();

    if (['javascript', 'data', 'vbscript', 'file'].includes(scheme)) add('high', `"${scheme}:" URL: runs code or opens local content instead of a web page.`);
    else if (scheme === 'http') add('low', 'Plain http: not encrypted.');

    if (u.username || u.password) {
      add('high', `Text before "@" ("${decodeURIComponent(u.username)}") is a username, not the site. The real host is ${host}.`);
    }

    const raw = rawAuthority(rawText).replace(/^.*@/, '').replace(/:\d+$/, '').replace(/^\[|\]$/g, '');
    if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) {
      if (raw && raw.toLowerCase() !== host) add('high', `Obfuscated IP address: "${raw}" is ${host}.`);
      else add('medium', `Host is a bare IP address (${host}), not a domain name.`);
      const scope = ioc().ipScope(host);
      if (scope !== 'public') add('info', `IP is ${scope}.`);
    }

    if (/(^|\.)xn--/.test(host)) {
      const uni = toUnicodeHost(host);
      const labels = uni.split('.');
      const mixed = labels.some((l) => scriptsOf(l).length > 1);
      const looks = skeleton(uni);
      add(mixed ? 'high' : 'medium', `Internationalised domain: ${host} displays as "${uni}"${looks !== uni ? ` and looks like "${looks}"` : ''}${mixed ? ' (mixes scripts in one label)' : ''}.`);
    }

    if (SHORTENERS.has(host)) add('medium', `${host} is a URL shortener: the real destination is hidden and cannot be resolved offline.`);
    if (u.port && !['80', '443'].includes(u.port)) add('low', `Non-standard port ${u.port}.`);
    if (host.split('.').length > 5) add('low', `Many subdomain levels (${host.split('.').length}): often used to push the real domain out of view.`);
    if (/%25[0-9a-f]{2}/i.test(u.href)) add('low', 'Double URL encoding (%25..): often used to slip past filters.');
    if (RISKY_EXT.test(u.pathname)) add('medium', `Path ends in a risky file type (${u.pathname.match(RISKY_EXT)[0]}).`);
    if (u.href.length > 500) add('info', `Very long URL (${u.href.length} characters).`);
    if (/^(mimecast|protect-\w+\.mimecast)\b/.test(host) || /\.mimecast\.com$/.test(host)) add('info', 'Mimecast-protected link: the destination is stored by Mimecast and cannot be decoded offline.');
    return f;
  }

  return { analyze, punycodeDecode, toUnicodeHost, skeleton, unwrapOnce: (s) => unwrapOnce(parse(s)) };
});
