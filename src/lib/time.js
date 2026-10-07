/*
 * time.js: recognise and convert the timestamp formats analysts meet in logs
 * and forensic artefacts.
 *
 * Instants are held as BigInt "ticks": 100-nanosecond units since 1970-01-01 UTC,
 * so Windows FILETIME values keep their full precision.
 */
(function (root, factory) {
  const lib = factory();
  if (typeof module === 'object' && module.exports) module.exports = lib;
  else (root.OAT = root.OAT || {}).time = lib;
})(globalThis, function () {
  'use strict';

  const TICKS_PER_MS = 10000n;
  const TICKS_PER_S = 10000000n;
  const EPOCH_1601 = 116444736000000000n;   // 1601-01-01 to 1970-01-01, in ticks
  const EPOCH_2001_S = 978307200n;          // Cocoa / Apple epoch, in Unix seconds

  const MIN = -EPOCH_1601;                  // 1601-01-01
  const PLAUSIBLE_FROM = 0n;                // 1970-01-01
  const PLAUSIBLE_TO = 4102444800n * TICKS_PER_S;   // 2100-01-01

  // Each numeric format turns an integer into ticks.
  const NUMERIC = [
    { id: 'unix_s', label: 'Unix time (seconds)', toTicks: (n) => n * TICKS_PER_S },
    { id: 'unix_ms', label: 'Unix time (milliseconds)', toTicks: (n) => n * TICKS_PER_MS },
    { id: 'unix_us', label: 'Unix time (microseconds)', toTicks: (n) => n * 10n },
    { id: 'unix_ns', label: 'Unix time (nanoseconds)', toTicks: (n) => n / 100n },
    { id: 'filetime', label: 'Windows FILETIME / LDAP / AD (100 ns since 1601)', toTicks: (n) => n - EPOCH_1601 },
    { id: 'webkit', label: 'Chrome / WebKit (µs since 1601)', toTicks: (n) => n * 10n - EPOCH_1601 },
    { id: 'cocoa', label: 'Apple Cocoa / Mac absolute time (s since 2001)', toTicks: (n) => (n + EPOCH_2001_S) * TICKS_PER_S },
  ];

  const plausible = (ticks) => ticks >= PLAUSIBLE_FROM && ticks < PLAUSIBLE_TO;

  // Returns [{ id, label, ticks, likely }] for every plausible reading of the input.
  // "likely" means between 1995 and ten years from now; those come first.
  function interpret(input, nowMs = Date.now()) {
    const from = 788918400n * TICKS_PER_S;   // 1995-01-01
    const to = (BigInt(nowMs) + 315576000000n) * TICKS_PER_MS;
    return parse(input)
      .map((r) => ({ ...r, likely: r.ticks >= from && r.ticks < to }))
      .sort((a, b) => Number(b.likely) - Number(a.likely));
  }

  function parse(input) {
    const s = input.trim().replace(/,/g, '');
    if (!s) return [];
    const out = [];

    // Integer, possibly with a fractional part for Unix seconds (e.g. 1700000000.123).
    let m = s.match(/^(\d{1,20})(?:\.(\d{1,9}))?$/);
    if (m) {
      const n = BigInt(m[1]);
      if (m[2]) {
        const frac = BigInt(m[2].padEnd(7, '0').slice(0, 7));
        const ticks = n * TICKS_PER_S + frac;
        if (plausible(ticks)) out.push({ id: 'unix_s', label: 'Unix time (seconds, with fraction)', ticks });
        return out;
      }
      for (const f of NUMERIC) {
        const ticks = f.toTicks(n);
        if (plausible(ticks)) out.push({ id: f.id, label: f.label, ticks });
      }
      return out;
    }

    // FILETIME in hex: "0x01D9A8F2C3B4E500", "01D9A8F2C3B4E500" or "01D9A8F2:C3B4E500" (high:low).
    m = s.match(/^(?:0x)?([0-9a-f]{8}):?([0-9a-f]{8})$/i);
    if (m) {
      const n = BigInt(`0x${m[1]}${m[2]}`);
      const ticks = n - EPOCH_1601;
      if (plausible(ticks)) out.push({ id: 'filetime_hex', label: 'Windows FILETIME (hex)', ticks });
      return out;
    }

    // Date strings. A date-time without a zone is read as UTC, and the label says so.
    let text = s;
    let assumedUtc = false;
    if (/^\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?)?$/.test(s)) {
      text = s.length === 10 ? `${s}T00:00:00Z` : `${s.replace(' ', 'T')}Z`;
      assumedUtc = true;
    }
    const ms = Date.parse(text);
    if (!Number.isNaN(ms)) {
      let ticks = BigInt(ms) * TICKS_PER_MS;
      // Keep sub-millisecond digits that Date.parse drops.
      const frac = text.match(/\.(\d{4,7})/);
      if (frac) ticks += BigInt(frac[1].padEnd(7, '0').slice(3, 7));
      out.push({ id: 'date', label: assumedUtc ? 'Date and time (no zone given, read as UTC)' : 'Date and time', ticks });
    }
    return out;
  }

  function divFloor(a, b) {
    const q = a / b;
    return (a % b !== 0n && (a < 0n) !== (b < 0n)) ? q - 1n : q;
  }

  // ISO 8601 UTC with as many fraction digits as the value has (up to 7).
  function toIso(ticks) {
    const ms = divFloor(ticks, TICKS_PER_MS);
    const extra = Number(ticks - ms * TICKS_PER_MS);   // 0..9999 sub-ms ticks
    const iso = new Date(Number(ms)).toISOString();     // ...SS.mmmZ
    const fraction = (iso.slice(20, 23) + String(extra).padStart(4, '0')).replace(/0+$/, '');
    return iso.slice(0, 19) + (fraction ? `.${fraction}` : '') + 'Z';
  }

  // Every representation of an instant. Values before 1601 get no Windows forms.
  function conversions(ticks) {
    const unixS = divFloor(ticks, TICKS_PER_S);
    const ft = ticks + EPOCH_1601;
    const rows = [
      { id: 'iso', label: 'ISO 8601 (UTC)', value: toIso(ticks) },
      { id: 'unix_s', label: 'Unix seconds', value: String(unixS) },
      { id: 'unix_ms', label: 'Unix milliseconds', value: String(divFloor(ticks, TICKS_PER_MS)) },
    ];
    if (ticks >= MIN) {
      rows.push({ id: 'filetime', label: 'FILETIME / LDAP (decimal)', value: String(ft) });
      rows.push({ id: 'filetime_hex', label: 'FILETIME (hex)', value: '0x' + ft.toString(16).toUpperCase().padStart(16, '0') });
      rows.push({ id: 'webkit', label: 'Chrome / WebKit', value: String(divFloor(ft, 10n)) });
    }
    rows.push({ id: 'cocoa', label: 'Apple Cocoa', value: String(unixS - EPOCH_2001_S) });
    return rows;
  }

  // "2026-10-07 14:03:12 (GMT+2)" in the given IANA zone.
  function inZone(ticks, timeZone) {
    const d = new Date(Number(divFloor(ticks, TICKS_PER_MS)));
    const parts = Object.fromEntries(new Intl.DateTimeFormat('en-GB', {
      timeZone, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit',
      second: '2-digit', hourCycle: 'h23', timeZoneName: 'shortOffset', weekday: 'short',
    }).formatToParts(d).map((p) => [p.type, p.value]));
    return `${parts.weekday} ${parts.year}-${parts.month}-${parts.day} ${parts.hour}:${parts.minute}:${parts.second} (${parts.timeZoneName})`;
  }

  function relative(ticks, nowMs = Date.now()) {
    const diffS = Number(divFloor(ticks, TICKS_PER_MS) - BigInt(nowMs)) / 1000;
    const a = Math.abs(diffS);
    const unit = a < 90 ? [a, 'seconds'] : a < 5400 ? [a / 60, 'minutes'] : a < 129600 ? [a / 3600, 'hours']
      : a < 63072000 ? [a / 86400, 'days'] : [a / 31557600, 'years'];
    const n = unit[0] < 10 && unit[1] === 'years' ? unit[0].toFixed(1) : Math.round(unit[0]);
    return diffS < 0 ? `${n} ${unit[1]} ago` : `in ${n} ${unit[1]}`;
  }

  function nowTicks() { return BigInt(Date.now()) * TICKS_PER_MS; }

  return { interpret, conversions, toIso, inZone, relative, nowTicks };
});
