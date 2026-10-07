# Offline Analyst Toolkit

A SOC analyst's everyday utilities in **one HTML file that never touches the network**. Decode a suspicious payload, hash a file, pull IOCs from a log or read a JWT without pasting sensitive data into CyberChef-style websites or online decoders.

Part of **0xRED3YE**: free, defensive, auditable tools.

## Use it

1. Download `dist/analyst-toolkit.html` (about 150 KB).
2. Open it in Chrome, Edge or Firefox. No install and no internet needed. It works from a USB stick, a shared drive or a jump box.

The page sets a Content-Security-Policy with `connect-src 'none'`, so the browser itself blocks every network request, even if a bug tried to make one.

## Modules

| # | Module | What it does |
|---|---|---|
| 1 | **Encode / Decode** | Base64 (standard, URL-safe), hex, URL, HTML entities, ROT13, binary, Unicode escapes, UTF-16LE. Chain steps into a recipe; auto-detect suggests the next step, including PowerShell `-EncodedCommand` and file types (gzip, ZIP, PE, PDF). |
| 2 | **Hashing** | MD5, SHA-1, SHA-256, SHA-384, SHA-512 of text or files of any size. Files are read in 4 MB chunks in a Web Worker. Paste a known hash to compare. |
| 3 | **IOC Extractor** | IPv4/IPv6, domains (checked against the IANA TLD list), URLs, emails, MD5/SHA-1/SHA-256/SHA-512, CVE IDs, ATT&CK technique IDs. Refangs input, dedupes and counts, marks private IPs, exports CSV/JSON. |
| 4 | **Defang / Refang** | `https://evil.com` ⇄ `hxxps[://]evil[.]com`. Changes only the indicators; the rest of the text is untouched. |
| 5 | **JWT Decoder** | Header, payload and readable dates. Flags `alg: none`, missing signatures, expiry, `jku`/`x5u`/`jwk` key injection and odd `kid` values. Optional local HS256/384/512 signature check. |
| 6 | **Timestamp Converter** | Unix s/ms/µs/ns, Windows FILETIME and LDAP/AD (decimal or hex), Chrome/WebKit, Apple Cocoa, ISO 8601 and email dates. UTC beside a chosen time zone (default Africa/Kigali), plus every conversion. |
| 7 | **Email Header Analyzer** | Relay path (oldest first) with delays, SPF/DKIM/DMARC as recorded by the receiving server, From / Reply-To / Return-Path and display-name mismatches, originating IP. Accepts `.eml` files. |
| 8 | **Lookup Links** | VirusTotal, AbuseIPDB, Shodan, URLhaus, urlscan, MalwareBazaar, NVD, CISA KEV, MITRE ATT&CK. Links open only when you click, in a new tab with no referrer. |
| 9 | **URL Analyzer** | Unwraps Microsoft SafeLinks, Proofpoint URL Defense (v1/v2/v3), Google, Facebook, Barracuda and generic `?url=` / Base64 redirects layer by layer. Splits each URL into parts and flags look-alike (punycode) domains with a "looks like" skeleton, obfuscated IPs (`0x7f.1`, `3232235777`), `user@host` tricks, shorteners and risky file types. |
| 10 | **PowerShell Deobfuscator** | Decodes `-EncodedCommand` in any abbreviation, inline `FromBase64String`, and gzip/deflate payloads, layer by layer. Undoes backticks, `'a'+'b'`, `-f` format strings, `[char]` codes, `.Replace()`/`-replace` and reversed strings. Flags risky behaviour and extracts IOCs. Text only: nothing is run. |
| 11 | **Text Diff** | Side-by-side line diff (Myers) with word-level highlights; ignore whitespace or case; unified `.diff` export. |
| 12 | **Regex Tester** | JavaScript regex with highlighted matches, numbered and named groups, replace, and SOC presets (IPs, SIDs, registry keys, paths…). Runs in a worker with a 2 s limit, so a catastrophic pattern cannot freeze the page. |
| 13 | **Entropy / Strings** | File entropy with a per-block chart (packed or encrypted?), ASCII and UTF-16LE strings with offsets and "interesting" flags (URLs, APIs, registry, PDB paths), and per-line entropy for spotting DGA-style domains. |
| 14 | **Case Notes** | Collect indicators with verdicts, a timeline and notes; export Markdown, HTML (escaped, with its own CSP) or JSON, and import JSON to continue later. |

The sidebar groups them as **Decode & convert**, **Indicators**, **Analysis** and **Case**.

**Send to…** pipes one module's output into another, for example Base64 decode → IOC Extractor → Lookup Links.

### Good to know

- **Email authentication is not re-verified.** SPF, DKIM and DMARC need DNS, so the analyzer reports what the receiving server recorded in `Authentication-Results`.
- **Clicking a lookup link sends that indicator to the third-party site.** Some services show searches publicly. The toolkit itself never contacts them.
- **Domains:** names ending in TLDs that look like file extensions (`.zip`, `.mov`, `.py`…) are skipped unless you tick *Include file-like domains*.

### Keyboard

| Keys | Action |
|---|---|
| Alt+1 … Alt+9 | Switch to one of the first nine modules |

## Safety

- **Offline:** no network calls, no telemetry, no CDN, no web fonts. Enforced by CSP.
- **Untrusted input stays text:** output is written with `textContent`, never `innerHTML`, so malicious emails and payloads cannot run.
- **Nothing is saved by default:** no cookies and no storage of your input. The one exception is opt-in: Case Notes has a *Keep in this browser* box that stores the case in this browser's local storage, never anywhere else.
- **Antivirus-friendly:** detection keywords for PowerShell and malware APIs are assembled at runtime, so the toolkit file itself does not look like a malicious script.
- **No third-party code:** hashing (MD5, SHA family, HMAC) is implemented in `src/lib/hashes.js` and tested against NIST/RFC vectors and OpenSSL, so the whole file stays auditable and works inside a Web Worker.
- **CSV exports** prefix values starting with `=`, `+`, `-` or `@` so spreadsheets will not run them as formulas.

## Develop

```
src/
  index.html        shell and layout (development CSP)
  styles.css
  app.js            module registry, navigation, Send to…, shared UI helpers
  lib/              pure logic, no DOM; shared with the tests
    codecs.js  hashes.js  ioc.js  tlds.js  jwt.js  time.js  email.js  lookup.js
    url.js  psdeobf.js  diff.js  regex.js  entropy.js  casereport.js
  modules/          one file per module
tests/
  harness.js        tiny test harness (Node and browser)
  unit/             unit tests (RFC 4648, NIST, RFC 4231 vectors, IOC corpus, …)
  runner.html       run the unit tests in a browser
  run-node.js       run the unit tests in Node
  e2e/smoke.js      opens dist/ from file:// in Edge/Chrome; fails on any network request
scripts/
  serve.py          no-cache dev server
  update-tlds.js    refresh src/lib/tlds.js from IANA
build.js            bundles src/ into dist/analyst-toolkit.html
```

```
npm run dev          # http://127.0.0.1:8765/src/ (needs Python)
npm test             # unit tests in Node
npm run build        # writes dist/analyst-toolkit.html
npm run test:e2e     # end-to-end test against dist/ (needs Edge or Chrome)
npm run update-tlds  # refresh the IANA TLD list (the only script that goes online)
```

Unit tests also run in the browser at `http://127.0.0.1:8765/tests/runner.html`.

### Adding a module

Create `src/modules/<name>.js`, add a `<script>` tag for it in `src/index.html`, and register it:

```js
OAT.register({
  id: 'example',
  name: 'Example',
  summary: 'One line shown under the title.',
  render(root, ctx) {
    // ctx: h(), copy(), download(), toast(), sendTo(), and ctx.ui helpers
    // (panel, button, copyButton, sendSelect, table, findings, textarea, debounce…)
    root.append(ctx.ui.panel('Hello', null, ctx.h('p', null, 'Hi')));
    return { receive(text) { /* data from Send to… */ }, focus() {} };
  },
});
```

Put pure logic in `src/lib/` so it can be unit tested without a browser.

## License

MIT. See [LICENSE](LICENSE).
