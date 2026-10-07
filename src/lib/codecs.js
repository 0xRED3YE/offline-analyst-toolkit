/*
 * codecs.js: pure encode/decode functions used by the Encode / Decode module.
 *
 * Everything works on bytes (Uint8Array) so steps can be chained without losing
 * binary data. Text-level operations (HTML entities, ROT13, ...) decode bytes as
 * UTF-8, transform, and re-encode. No DOM access here, so the same file runs in
 * the browser and under Node for the unit tests.
 */
(function (root, factory) {
  const lib = factory();
  if (typeof module === 'object' && module.exports) module.exports = lib;
  else (root.OAT = root.OAT || {}).codecs = lib;
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const encoder = new TextEncoder();
  const decoder = new TextDecoder('utf-8');                  // lossy: bad bytes become U+FFFD
  const strictDecoder = new TextDecoder('utf-8', { fatal: true });

  const utf8 = (str) => encoder.encode(str);
  const text = (bytes) => decoder.decode(bytes);

  function concat(chunks) {
    let len = 0;
    for (const c of chunks) len += c.length;
    const out = new Uint8Array(len);
    let pos = 0;
    for (const c of chunks) { out.set(c, pos); pos += c.length; }
    return out;
  }

  // Collects bytes from mixed sources (single bytes, code points) during parsing.
  class ByteBuilder {
    constructor() { this.parts = []; this.cur = []; }
    byte(b) { this.cur.push(b); }
    str(s) { if (s) { this.flush(); this.parts.push(utf8(s)); } }
    flush() { if (this.cur.length) { this.parts.push(Uint8Array.from(this.cur)); this.cur = []; } }
    done() { this.flush(); return concat(this.parts); }
  }

  // ---------------------------------------------------------------- Base64 (RFC 4648)

  const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const B64_LOOKUP = new Int16Array(128).fill(-1);
  for (let i = 0; i < 64; i++) {
    B64_LOOKUP[B64.charCodeAt(i)] = i;
    B64_LOOKUP[B64URL.charCodeAt(i)] = i;   // accept both alphabets when decoding
  }

  function base64Encode(bytes, { urlSafe = false, pad = !urlSafe } = {}) {
    const abc = urlSafe ? B64URL : B64;
    let out = '';
    let i = 0;
    for (; i + 2 < bytes.length; i += 3) {
      const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
      out += abc[n >> 18] + abc[(n >> 12) & 63] + abc[(n >> 6) & 63] + abc[n & 63];
    }
    const rest = bytes.length - i;
    if (rest === 1) {
      const n = bytes[i] << 16;
      out += abc[n >> 18] + abc[(n >> 12) & 63] + (pad ? '==' : '');
    } else if (rest === 2) {
      const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
      out += abc[n >> 18] + abc[(n >> 12) & 63] + abc[(n >> 6) & 63] + (pad ? '=' : '');
    }
    return out;
  }

  // Tolerant decoder: ignores whitespace, accepts standard and URL-safe alphabets,
  // and missing padding. Throws on characters outside the alphabet.
  function base64Decode(str) {
    const s = str.replace(/\s+/g, '').replace(/=+$/, '');
    const out = new Uint8Array(Math.floor((s.length * 3) / 4));
    let buf = 0, bits = 0, o = 0;
    for (let i = 0; i < s.length; i++) {
      const c = s.charCodeAt(i);
      const v = c < 128 ? B64_LOOKUP[c] : -1;
      if (v < 0) throw new Error(`Invalid Base64 character "${s[i]}" at position ${i + 1}`);
      buf = (buf << 6) | v;
      bits += 6;
      if (bits >= 8) {
        bits -= 8;
        out[o++] = (buf >> bits) & 0xff;
      }
    }
    // Checked after the character scan so a bad character gets the more useful error.
    if (s.length % 4 === 1) throw new Error('Invalid Base64: length is not possible for Base64 data');
    return out.subarray(0, o);
  }

  // ---------------------------------------------------------------- Hex

  function hexEncode(bytes, sep = '') {
    const parts = new Array(bytes.length);
    for (let i = 0; i < bytes.length; i++) parts[i] = bytes[i].toString(16).padStart(2, '0');
    return parts.join(sep);
  }

  // Accepts "48 65", "48:65", "0x48,0x65", "\x48\x65", "4865".
  function hexDecode(str) {
    const s = str.replace(/0x|\\x/gi, '').replace(/[\s:,;-]+/g, '');
    const bad = s.search(/[^0-9a-f]/i);
    if (bad >= 0) throw new Error(`Invalid hex character "${s[bad]}"`);
    if (s.length % 2) throw new Error('Invalid hex: odd number of digits');
    const out = new Uint8Array(s.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
    return out;
  }

  // ---------------------------------------------------------------- URL (percent) encoding

  function isUnreserved(b) {
    return (b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x5a) || (b >= 0x61 && b <= 0x7a) ||
      b === 0x2d || b === 0x2e || b === 0x5f || b === 0x7e;   // - . _ ~
  }

  function urlEncode(bytes) {
    let out = '';
    for (const b of bytes) {
      out += isUnreserved(b) ? String.fromCharCode(b) : '%' + b.toString(16).toUpperCase().padStart(2, '0');
    }
    return out;
  }

  // Byte-level and tolerant: a stray "%" or "%zz" is kept as-is instead of throwing
  // (decodeURIComponent would throw), and "+" is left alone.
  function urlDecode(bytes) {
    const out = [];
    for (let i = 0; i < bytes.length; i++) {
      const b = bytes[i];
      if (b === 0x25 && isHexByte(bytes[i + 1]) && isHexByte(bytes[i + 2])) {
        out.push(parseInt(String.fromCharCode(bytes[i + 1], bytes[i + 2]), 16));
        i += 2;
      } else {
        out.push(b);
      }
    }
    return Uint8Array.from(out);
  }

  function isHexByte(b) {
    return b !== undefined && ((b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x46) || (b >= 0x61 && b <= 0x66));
  }

  // ---------------------------------------------------------------- HTML entities

  // Common named entities, plus the punctuation ones seen in obfuscated payloads
  // (e.g. "javascript&colon;alert&lpar;1&rpar;").
  const NAMED = {
    amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ',
    copy: '©', reg: '®', trade: '™', hellip: '…', mdash: '—', ndash: '–',
    lsquo: '‘', rsquo: '’', ldquo: '“', rdquo: '”', laquo: '«', raquo: '»',
    euro: '€', pound: '£', yen: '¥', cent: '¢', sect: '§', deg: '°',
    times: '×', divide: '÷', middot: '·', bull: '•',
    Tab: '\t', NewLine: '\n', colon: ':', semi: ';', lpar: '(', rpar: ')',
    sol: '/', bsol: '\\', period: '.', comma: ',', excl: '!', quest: '?',
    num: '#', percnt: '%', equals: '=', plus: '+', lowbar: '_', grave: '`',
    lbrack: '[', rbrack: ']', lsqb: '[', rsqb: ']', lcub: '{', rcub: '}',
    lbrace: '{', rbrace: '}', verbar: '|', vert: '|', ast: '*', dollar: '$',
    commat: '@', Hat: '^', hyphen: '-', dash: '-',
  };

  function codePointToString(cp) {
    if (!Number.isFinite(cp) || cp < 0 || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return '�';
    return String.fromCodePoint(cp);
  }

  function htmlEncode(str) {
    return str.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  // Numeric entities may omit the ";" (browsers accept "&#106avascript"), named ones may not.
  function htmlDecode(str) {
    return str.replace(/&#x([0-9a-f]+);?|&#(\d+);?|&([a-zA-Z][a-zA-Z0-9]*);/gi, (m, hex, dec, name) => {
      if (hex) return codePointToString(parseInt(hex, 16));
      if (dec) return codePointToString(parseInt(dec, 10));
      return Object.prototype.hasOwnProperty.call(NAMED, name) ? NAMED[name] : m;
    });
  }

  // ---------------------------------------------------------------- ROT13

  function rot13(bytes) {
    const out = new Uint8Array(bytes.length);
    for (let i = 0; i < bytes.length; i++) {
      const b = bytes[i];
      if (b >= 0x41 && b <= 0x5a) out[i] = ((b - 0x41 + 13) % 26) + 0x41;
      else if (b >= 0x61 && b <= 0x7a) out[i] = ((b - 0x61 + 13) % 26) + 0x61;
      else out[i] = b;
    }
    return out;
  }

  // ---------------------------------------------------------------- Binary

  function binaryEncode(bytes) {
    return Array.from(bytes, (b) => b.toString(2).padStart(8, '0')).join(' ');
  }

  function binaryDecode(str) {
    const s = str.replace(/[\s,]+/g, '');
    const bad = s.search(/[^01]/);
    if (bad >= 0) throw new Error(`Invalid binary character "${s[bad]}"`);
    if (s.length % 8) throw new Error('Invalid binary: bit count is not a multiple of 8');
    const out = new Uint8Array(s.length / 8);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 8, 8), 2);
    return out;
  }

  // ---------------------------------------------------------------- Unicode escapes

  // Printable ASCII stays as-is; everything else becomes \uXXXX (surrogate pairs for
  // characters above U+FFFF, which is how JavaScript and JSON write them).
  function unicodeEscape(str) {
    let out = '';
    for (let i = 0; i < str.length; i++) {
      const c = str.charCodeAt(i);
      if (c >= 0x20 && c < 0x7f && c !== 0x5c) out += str[i];
      else out += '\\u' + c.toString(16).padStart(4, '0');
    }
    return out;
  }

  const SIMPLE_ESCAPES = { n: '\n', r: '\r', t: '\t', 0: '\0', b: '\b', f: '\f', v: '\v', '\\': '\\', "'": "'", '"': '"', '/': '/' };

  // \uXXXX and \u{...} and \UXXXXXXXX are code points; \xXX is a raw byte, because in
  // payloads "\xc3\xa9" usually means UTF-8 bytes, not two Latin-1 characters.
  function unicodeUnescape(str) {
    const bb = new ByteBuilder();
    // Case-sensitive on purpose: \U (8 digits) and \u (4 digits) are different escapes.
    const re = /\\u\{([0-9a-fA-F]{1,6})\}|\\u([0-9a-fA-F]{4})|\\U([0-9a-fA-F]{8})|\\x([0-9a-fA-F]{2})|\\([nrt0bfv\\'"\/])/g;
    let last = 0;
    let pendingHigh = null;
    let m;
    const flushHigh = () => { if (pendingHigh !== null) { bb.str('�'); pendingHigh = null; } };
    while ((m = re.exec(str))) {
      if (m.index > last) { flushHigh(); bb.str(str.slice(last, m.index)); }
      last = re.lastIndex;
      if (m[4]) { flushHigh(); bb.byte(parseInt(m[4], 16)); continue; }
      if (m[5]) { flushHigh(); bb.str(SIMPLE_ESCAPES[m[5]]); continue; }
      const cp = parseInt(m[1] || m[2] || m[3], 16);
      if (m[2] && cp >= 0xd800 && cp <= 0xdbff) { flushHigh(); pendingHigh = cp; continue; }
      if (m[2] && cp >= 0xdc00 && cp <= 0xdfff && pendingHigh !== null) {
        bb.str(String.fromCodePoint(0x10000 + ((pendingHigh - 0xd800) << 10) + (cp - 0xdc00)));
        pendingHigh = null;
        continue;
      }
      flushHigh();
      bb.str(codePointToString(cp));
    }
    flushHigh();
    bb.str(str.slice(last));
    return bb.done();
  }

  // ---------------------------------------------------------------- UTF-16LE (PowerShell -EncodedCommand)

  function utf16leDecode(bytes) {
    if (bytes.length % 2) throw new Error('UTF-16LE needs an even number of bytes');
    return utf8(new TextDecoder('utf-16le').decode(bytes));
  }

  function utf16leEncode(str) {
    const out = new Uint8Array(str.length * 2);
    for (let i = 0; i < str.length; i++) {
      const c = str.charCodeAt(i);
      out[i * 2] = c & 0xff;
      out[i * 2 + 1] = c >> 8;
    }
    return out;
  }

  // ---------------------------------------------------------------- Operations and recipes

  const OPS = [
    { id: 'b64-decode', label: 'Base64 decode', group: 'Decode', run: (b) => base64Decode(text(b)) },
    { id: 'hex-decode', label: 'Hex decode', group: 'Decode', run: (b) => hexDecode(text(b)) },
    { id: 'url-decode', label: 'URL decode', group: 'Decode', run: urlDecode },
    { id: 'html-decode', label: 'HTML entities decode', group: 'Decode', run: (b) => utf8(htmlDecode(text(b))) },
    { id: 'unicode-unescape', label: 'Unicode unescape (\\u, \\x)', group: 'Decode', run: (b) => unicodeUnescape(text(b)) },
    { id: 'binary-decode', label: 'Binary decode', group: 'Decode', run: (b) => binaryDecode(text(b)) },
    { id: 'utf16le-decode', label: 'UTF-16LE to text', group: 'Decode', run: utf16leDecode },
    { id: 'b64-encode', label: 'Base64 encode', group: 'Encode', run: (b) => utf8(base64Encode(b)) },
    { id: 'b64url-encode', label: 'Base64 encode (URL-safe)', group: 'Encode', run: (b) => utf8(base64Encode(b, { urlSafe: true })) },
    { id: 'hex-encode', label: 'Hex encode', group: 'Encode', run: (b) => utf8(hexEncode(b)) },
    { id: 'url-encode', label: 'URL encode', group: 'Encode', run: (b) => utf8(urlEncode(b)) },
    { id: 'html-encode', label: 'HTML entities encode', group: 'Encode', run: (b) => utf8(htmlEncode(text(b))) },
    { id: 'unicode-escape', label: 'Unicode escape (\\u)', group: 'Encode', run: (b) => utf8(unicodeEscape(text(b))) },
    { id: 'binary-encode', label: 'Binary encode', group: 'Encode', run: (b) => utf8(binaryEncode(b)) },
    { id: 'utf16le-encode', label: 'Text to UTF-16LE', group: 'Encode', run: (b) => utf16leEncode(text(b)) },
    { id: 'rot13', label: 'ROT13', group: 'Other', run: rot13 },
  ];
  const OP_BY_ID = Object.fromEntries(OPS.map((o) => [o.id, o]));

  // Runs steps in order; stops at the first failing step.
  // Returns [{ id, ok, bytes?, error? }] with one entry per step that ran.
  function runRecipe(bytes, stepIds) {
    const results = [];
    let cur = bytes;
    for (const id of stepIds) {
      const op = OP_BY_ID[id];
      if (!op) { results.push({ id, ok: false, error: `Unknown operation "${id}"` }); break; }
      try {
        cur = op.run(cur);
        results.push({ id, ok: true, bytes: cur });
      } catch (e) {
        results.push({ id, ok: false, error: e.message });
        break;
      }
    }
    return results;
  }

  // ---------------------------------------------------------------- Analysis helpers

  // Share of printable characters (0..1). Valid UTF-8 is judged per character,
  // anything else per byte with a small penalty.
  function printableRatio(bytes) {
    if (!bytes.length) return 0;
    let str;
    try { str = strictDecoder.decode(bytes); } catch (_) {
      let ok = 0;
      for (const b of bytes) if ((b >= 0x20 && b < 0x7f) || b === 9 || b === 10 || b === 13) ok++;
      return (ok / bytes.length) * 0.9;
    }
    let ok = 0, n = 0;
    for (const ch of str) {
      n++;
      const c = ch.codePointAt(0);
      if (c === 9 || c === 10 || c === 13 || (c >= 0x20 && c !== 0x7f && !(c >= 0x80 && c < 0xa0) && c !== 0xfffd)) ok++;
    }
    return n ? ok / n : 0;
  }

  const MAGIC = [
    { sig: [0x1f, 0x8b], name: 'gzip data' },
    { sig: [0x50, 0x4b, 0x03, 0x04], name: 'ZIP archive (also docx/xlsx/jar)' },
    { sig: [0x4d, 0x5a], name: 'Windows executable (MZ)' },
    { sig: [0x25, 0x50, 0x44, 0x46], name: 'PDF document' },
    { sig: [0x89, 0x50, 0x4e, 0x47], name: 'PNG image' },
    { sig: [0xff, 0xd8, 0xff], name: 'JPEG image' },
    { sig: [0x7f, 0x45, 0x4c, 0x46], name: 'ELF executable' },
    { sig: [0xd0, 0xcf, 0x11, 0xe0], name: 'OLE file (old Office document)' },
    { sig: [0x78, 0x9c], name: 'zlib data' },
  ];

  function sniff(bytes) {
    for (const m of MAGIC) {
      if (bytes.length >= m.sig.length && m.sig.every((b, i) => bytes[i] === b)) return m.name;
    }
    return null;
  }

  // UTF-16LE text of mostly ASCII has a zero in every second byte.
  function looksUtf16le(bytes) {
    if (bytes.length < 4 || bytes.length % 2) return false;
    let zeros = 0;
    for (let i = 1; i < bytes.length; i += 2) if (bytes[i] === 0) zeros++;
    return zeros / (bytes.length / 2) >= 0.8;
  }

  function preview(bytes, max = 80) {
    const s = text(bytes.subarray(0, max * 4)).replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f�]/g, '.').replace(/\s+/g, ' ');
    return s.length > max ? s.slice(0, max) + '…' : s;
  }

  // Suggests decode steps for the given text, best first.
  // Returns [{ ops: [opId...], label, score, preview }].
  function detect(input) {
    const t = input.trim();
    if (t.length < 4) return [];
    const found = [];
    const add = (ops, label, bytes, score) => found.push({ ops, label, score, preview: preview(bytes) });

    // Judge a decoded byte buffer: text, UTF-16LE text, or a known file type.
    const judge = (ops, label, bytes) => {
      if (!bytes.length) return;
      if (looksUtf16le(bytes)) {
        const u = utf16leDecode(bytes);
        add([...ops, 'utf16le-decode'], `${label} → UTF-16LE text (PowerShell -EncodedCommand?)`, u, printableRatio(u) + 0.05);
        return;
      }
      const kind = sniff(bytes);
      if (kind) { add(ops, `${label} → ${kind}`, bytes, 0.8); return; }
      add(ops, label, bytes, printableRatio(bytes));
    };

    const compact = t.replace(/\s+/g, '');

    if (compact.length >= 8 && compact.length % 4 !== 1 && /^[A-Za-z0-9+/_-]+={0,2}$/.test(compact)) {
      try { judge(['b64-decode'], 'Base64', base64Decode(compact)); } catch (_) { /* not Base64 */ }
    }
    const hexCompact = t.replace(/0x|\\x/gi, '').replace(/[\s:,;-]+/g, '');
    if (hexCompact.length >= 4 && hexCompact.length % 2 === 0 && /^[0-9a-f]+$/i.test(hexCompact)) {
      try { judge(['hex-decode'], 'Hex', hexDecode(t)); } catch (_) { /* not hex */ }
    }
    if (/^[01\s,]+$/.test(t) && compact.replace(/,/g, '').length % 8 === 0) {
      try { judge(['binary-decode'], 'Binary', binaryDecode(t)); } catch (_) { /* not binary */ }
    }
    if (/%[0-9a-f]{2}/i.test(t)) {
      const out = urlDecode(utf8(t));
      add(['url-decode'], 'URL encoding', out, 0.6 + 0.3 * printableRatio(out));
    }
    if (/&(#x?[0-9a-f]+|[a-z][a-z0-9]*);/i.test(t)) {
      const out = utf8(htmlDecode(t));
      if (text(out) !== t) add(['html-decode'], 'HTML entities', out, 0.6 + 0.3 * printableRatio(out));
    }
    if (/\\u[0-9a-f]{4}|\\u\{[0-9a-f]+\}|\\x[0-9a-f]{2}/i.test(t)) {
      const out = unicodeUnescape(t);
      add(['unicode-unescape'], 'Unicode / \\x escapes', out, 0.65 + 0.3 * printableRatio(out));
    }

    return found
      .filter((f) => f.score >= 0.75)
      .sort((a, b) => b.score - a.score)
      .slice(0, 4);
  }

  // Classic hex dump: offset, 16 hex bytes, ASCII column.
  function hexdump(bytes, maxBytes = 65536) {
    const n = Math.min(bytes.length, maxBytes);
    const lines = [];
    for (let off = 0; off < n; off += 16) {
      const row = bytes.subarray(off, Math.min(off + 16, n));
      const hex = Array.from(row, (b) => b.toString(16).padStart(2, '0'));
      const left = hex.slice(0, 8).join(' ');
      const right = hex.slice(8).join(' ');
      const ascii = Array.from(row, (b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.')).join('');
      lines.push(`${off.toString(16).padStart(8, '0')}  ${left.padEnd(23)}  ${right.padEnd(23)}  |${ascii}|`);
    }
    return lines.join('\n');
  }

  return {
    utf8, text,
    base64Encode, base64Decode,
    hexEncode, hexDecode,
    urlEncode, urlDecode,
    htmlEncode, htmlDecode,
    rot13,
    binaryEncode, binaryDecode,
    unicodeEscape, unicodeUnescape,
    utf16leEncode, utf16leDecode,
    OPS, OP_BY_ID, runRecipe,
    printableRatio, sniff, looksUtf16le, detect, hexdump,
  };
});
