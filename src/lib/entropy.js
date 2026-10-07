/*
 * entropy.js: Shannon entropy and printable-string extraction, for triaging
 * unknown files ("is this packed or encrypted?") and spotting random-looking
 * values such as DGA domains or keys.
 */
(function (root, factory) {
  const lib = factory();
  if (typeof module === 'object' && module.exports) module.exports = lib;
  else (root.OAT = root.OAT || {}).entropy = lib;
})(globalThis, function () {
  'use strict';

  const ioc = () => globalThis.OAT.ioc;
  const k = (...p) => p.join('');

  // Bits per byte (0..8) for bytes[start, end).
  function shannon(bytes, start = 0, end = bytes.length) {
    const len = end - start;
    if (len <= 0) return 0;
    const counts = new Uint32Array(256);
    for (let i = start; i < end; i++) counts[bytes[i]]++;
    let h = 0;
    for (const c of counts) if (c) { const p = c / len; h -= p * Math.log2(p); }
    return h;
  }

  // Entropy over a string's characters (for short values like domains), in bits per character.
  function shannonText(text) {
    const chars = [...text];
    if (!chars.length) return 0;
    const counts = new Map();
    for (const c of chars) counts.set(c, (counts.get(c) || 0) + 1);
    let h = 0;
    for (const c of counts.values()) { const p = c / chars.length; h -= p * Math.log2(p); }
    return h;
  }

  function blocks(bytes, blockSize = 1024) {
    const out = [];
    for (let off = 0; off < bytes.length; off += blockSize) out.push(shannon(bytes, off, Math.min(off + blockSize, bytes.length)));
    return out;
  }

  function verdict(h) {
    if (h < 1) return 'very low: repetitive data or padding';
    if (h < 4.5) return 'low: plain text or structured data';
    if (h < 6.5) return 'medium: code, mixed or encoded data';
    if (h < 7.2) return 'high: possibly compressed or packed';
    return 'very high: likely encrypted or compressed';
  }

  const isPrint = (b) => (b >= 0x20 && b < 0x7f) || b === 0x09;

  // ASCII and UTF-16LE strings of at least `min` characters, in file order.
  // Returns { strings: [{ offset, enc, text }], truncated }.
  function strings(bytes, { min = 4, ascii = true, utf16 = true, max = 100000 } = {}) {
    const out = [];
    let truncated = false;
    if (ascii) {
      let start = -1;
      for (let i = 0; i <= bytes.length; i++) {
        if (i < bytes.length && isPrint(bytes[i])) { if (start < 0) start = i; continue; }
        if (start >= 0 && i - start >= min) {
          out.push({ offset: start, enc: 'ascii', text: String.fromCharCode(...bytes.subarray(start, Math.min(i, start + 4096))) });
          if (out.length >= max) { truncated = true; break; }
        }
        start = -1;
      }
    }
    if (utf16 && !truncated) {
      for (const parity of [0, 1]) {
        let start = -1;
        for (let i = parity; i + 1 <= bytes.length; i += 2) {
          const ok = i + 1 < bytes.length && isPrint(bytes[i]) && bytes[i + 1] === 0;
          if (ok) { if (start < 0) start = i; continue; }
          if (start >= 0 && (i - start) / 2 >= min) {
            let s = '';
            for (let j = start; j < i && s.length < 4096; j += 2) s += String.fromCharCode(bytes[j]);
            out.push({ offset: start, enc: 'utf16le', text: s });
            if (out.length >= max) { truncated = true; break; }
          }
          start = -1;
        }
        if (truncated) break;
      }
    }
    out.sort((x, y) => x.offset - y.offset);
    return { strings: out, truncated };
  }

  // Why a string deserves a second look, or null.
  const API = new RegExp(`\\b(${[k('Virtual', 'Alloc'), k('VirtualProt', 'ect'), k('WriteProcess', 'Memory'), k('CreateRemote', 'Thread'),
    k('LoadLib', 'rary'), k('GetProc', 'Address'), k('IsDebugger', 'Present'), k('SetWindows', 'HookEx'), k('Internet', 'OpenUrl'),
    k('URLDownload', 'ToFile'), k('WinHttp', 'Open'), k('Crypt', 'Encrypt'), k('Shell', 'Execute'), k('Adjust', 'TokenPrivileges'),
    k('NtUnmap', 'ViewOfSection'), k('Reg', 'SetValue')].join('|')})`, 'i');

  function interesting(text) {
    if (/https?:\/\/|ftp:\/\//i.test(text)) return 'URL';
    if (API.test(text)) return 'suspicious API';
    if (/\b(?:HKLM|HKCU|HKEY_[A-Z_]+|SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run)/i.test(text)) return 'registry';
    if (/\b(?:cmd\.exe|powershell|wscript|cscript|mshta|rundll32|regsvr32|schtasks|bitsadmin|certutil)\b/i.test(text)) return 'command';
    if (/\.pdb\b/i.test(text)) return 'debug path';
    if (/[a-z]:\\|\\\\[\w.-]+\\/i.test(text)) return 'path';
    if (/^Mozilla\/\d/.test(text)) return 'user agent';
    const found = ioc().extract(text, { refangFirst: false });
    if (found.some((x) => x.type === 'ipv4' || x.type === 'domain' || x.type === 'email')) return 'network indicator';
    return null;
  }

  // Per-line entropy for lists (domains, hostnames, tokens), highest first.
  function perLine(text) {
    return text.split(/\r?\n/).map((l) => l.trim()).filter(Boolean)
      .map((line) => {
        const label = line.includes('.') && !line.includes(' ') ? line.split('.').slice(0, -1).join('.') || line : line;
        return { line, length: line.length, entropy: shannonText(label) };
      })
      .sort((a, b) => b.entropy - a.entropy);
  }

  return { shannon, shannonText, blocks, verdict, strings, interesting, perLine };
});
