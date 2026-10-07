# Changelog

## 1.1.0 (2026-10-07)

Six more modules, and a grouped sidebar (Decode & convert, Indicators, Analysis, Case).

- **URL Analyzer:** unwraps SafeLinks, Proofpoint v1/v2/v3, Google, Facebook, Barracuda and generic/Base64 redirects; URL parts; flags look-alike punycode domains (with a "looks like" skeleton), obfuscated IP hosts, `user@host`, shorteners and risky file types.
- **PowerShell Deobfuscator:** `-EncodedCommand` in any abbreviation, nested layers, `FromBase64String`/`GetString`, gzip/deflate payloads; undoes backticks, concatenation, `-f`, `[char]`, `.Replace()`/`-replace` and reversals; findings and IOCs.
- **Text Diff:** Myers line diff, side by side with word-level marks, ignore whitespace/case, unified `.diff` export.
- **Regex Tester:** highlighted matches, groups, replace, SOC presets; runs in a worker with a 2 s limit.
- **Entropy / Strings:** entropy and block chart, ASCII/UTF-16 strings with "interesting" flags, per-line entropy for DGA hunting.
- **Case Notes:** indicators with verdicts, timeline, notes; Markdown/HTML/JSON export and JSON import; optional local save.

### Fixed
- Timestamp Converter could show a stray "null" under the readings when a value had no less-likely readings.

## 1.0.0 (2026-10-07)

First release: all 8 MVP modules.

- **Encode / Decode:** Base64 (standard and URL-safe), hex, URL, HTML entities, ROT13, binary, Unicode escapes, UTF-16LE; recipes with per-step status; auto-detect including PowerShell `-EncodedCommand` and file types; text and hex views.
- **Hashing:** MD5, SHA-1, SHA-256, SHA-384, SHA-512 of text or files of any size, streamed in a Web Worker with progress and cancel; hash compare.
- **IOC Extractor:** IPv4/IPv6, domains (IANA TLD check), URLs, emails, hashes, CVE and ATT&CK IDs; refang, dedupe and count, private IP marking, type filters, CSV/JSON export.
- **Defang / Refang:** indicator-only defanging, idempotent.
- **JWT Decoder:** header and payload, time claims, risk findings, local HMAC verification.
- **Timestamp Converter:** Unix, FILETIME/LDAP (decimal and hex), WebKit, Cocoa and date strings; UTC and a chosen zone (default Africa/Kigali); all conversions.
- **Email Header Analyzer:** relay path with delays, recorded SPF/DKIM/DMARC, sender mismatches, originating IP, `.eml` input.
- **Lookup Links:** reputation-site links per indicator type, opened only on click.
- App shell: sidebar (dropdown on phones), light/dark theme, Alt+1…8, "100% offline" badge, strict CSP, Send to… between modules.
- Tests: 71 unit tests (RFC 4648, NIST FIPS 180, RFC 1321, RFC 4231, OpenSSL cross-check, IOC corpus); end-to-end smoke test from `file://` that fails on any network request; GitHub Actions CI.
- `build.js` bundles everything into `dist/analyst-toolkit.html` (~150 KB).
