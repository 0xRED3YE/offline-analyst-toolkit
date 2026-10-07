/*
 * regex.js: run a JavaScript regular expression over text and collect matches.
 * The factory is self-contained so the Regex Tester can run it in a Web Worker
 * with a timeout (a catastrophic pattern must not freeze the page).
 */
(function (root, factory) {
  const lib = factory();
  lib.factorySource = '(' + factory.toString() + ')';
  if (typeof module === 'object' && module.exports) module.exports = lib;
  else (root.OAT = root.OAT || {}).regex = lib;
})(globalThis, function () {
  'use strict';

  // Returns { matches: [{ index, end, text, groups: [..], named: {..} }], truncated, replaced?, error? }
  function run(pattern, flags, text, { replacement = null, maxMatches = 5000 } = {}) {
    let re;
    try { re = new RegExp(pattern, flags.includes('g') ? flags : flags + 'g'); } catch (e) { return { error: e.message, matches: [] }; }
    const global = flags.includes('g');
    const unicode = flags.includes('u') || flags.includes('v');
    const matches = [];
    let truncated = false;
    let m;
    while ((m = re.exec(text))) {
      matches.push({
        index: m.index,
        end: m.index + m[0].length,
        text: m[0],
        groups: m.slice(1),
        named: m.groups ? { ...m.groups } : null,
      });
      if (!global) break;
      if (matches.length >= maxMatches) { truncated = true; break; }
      if (m[0] === '') {
        // Step past an empty match (a whole code point in unicode mode).
        const cp = unicode ? text.codePointAt(re.lastIndex) : 0;
        re.lastIndex += cp > 0xffff ? 2 : 1;
      }
    }
    const out = { matches, truncated };
    if (replacement !== null) {
      try { out.replaced = text.replace(new RegExp(pattern, flags), replacement); } catch (e) { out.error = e.message; }
    }
    return out;
  }

  // Common SOC patterns for the preset menu.
  const PRESETS = [
    { name: 'IPv4 address', pattern: '\\b(?:(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\b', flags: 'g' },
    { name: 'Email address', pattern: '[\\w.%+-]+@[\\w-]+(?:\\.[\\w-]+)+', flags: 'gi' },
    { name: 'URL', pattern: 'https?:\\/\\/[^\\s"\'<>]+', flags: 'gi' },
    { name: 'SHA-256 hash', pattern: '\\b[a-f0-9]{64}\\b', flags: 'gi' },
    { name: 'Windows path', pattern: '[a-z]:\\\\(?:[^\\\\/:*?"<>|\\r\\n]+\\\\)*[^\\\\/:*?"<>|\\r\\n]*', flags: 'gi' },
    { name: 'Registry key', pattern: '\\b(?:HKLM|HKCU|HKCR|HKU|HKEY_[A-Z_]+)\\\\[^\\s"\']+', flags: 'g' },
    { name: 'Windows SID', pattern: '\\bS-1-\\d+(?:-\\d+){1,14}\\b', flags: 'g' },
    { name: 'GUID', pattern: '\\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\b', flags: 'gi' },
    { name: 'Base64 blob (40+ chars)', pattern: '[A-Za-z0-9+/]{40,}={0,2}', flags: 'g' },
    { name: 'Event ID field', pattern: '\\bEventID[=:\\s]+(?<id>\\d{1,5})\\b', flags: 'gi' },
    { name: 'Username in DOMAIN\\user', pattern: '\\b(?<domain>[A-Z0-9_-]{1,15})\\\\(?<user>[\\w.$-]{1,20})\\b', flags: 'gi' },
  ];

  return { run, PRESETS };
});
