#!/usr/bin/env node
/*
 * build.js: bundles src/ into one self-contained file, dist/analyst-toolkit.html.
 *
 *  - inlines every <link rel="stylesheet" href> and <script src> from src/index.html
 *  - swaps the development CSP for the production one (no 'self': nothing is loaded)
 *  - fails if anything external is still referenced
 *
 * No dependencies: `node build.js` (or `npm run build`).
 */
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const SRC = path.join(__dirname, 'src');
const OUT = path.join(__dirname, 'dist', 'analyst-toolkit.html');

const PROD_CSP = [
  "default-src 'none'",
  "script-src 'unsafe-inline'",
  "style-src 'unsafe-inline'",
  'img-src data: blob:',
  'worker-src blob:',
  "connect-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-src 'none'",
].join('; ');

function read(rel) {
  const file = path.resolve(SRC, rel);
  if (!file.startsWith(SRC + path.sep)) throw new Error(`Refusing to inline a file outside src/: ${rel}`);
  return fs.readFileSync(file, 'utf8');
}

let html = read('index.html');
const inlined = [];

html = html.replace(/<link rel="stylesheet" href="([^"]+)">/g, (_, href) => {
  inlined.push(href);
  return `<style>\n${read(href)}</style>`;
});

html = html.replace(/<script src="([^"]+)"><\/script>/g, (_, src) => {
  inlined.push(src);
  // A literal "</script" inside the code would end the inline block early.
  return `<script>\n${read(src).replace(/<\/script/gi, '<\\/script')}</script>`;
});

const cspRe = /<meta http-equiv="Content-Security-Policy" content="[^"]*">/;
if (!cspRe.test(html)) throw new Error('No CSP meta tag found in src/index.html');
html = html.replace(cspRe, () => `<meta http-equiv="Content-Security-Policy" content="${PROD_CSP}">`);
html = html.replace(/<!-- Development CSP\.[^>]*-->\n/, '');

// Anything still pointing at a file or URL means the page would not be self-contained.
const leftovers = html.match(/<(?:script|link|img|iframe)\b[^>]*\b(?:src|href)="(?!data:)[^"]*"/gi);
if (leftovers) throw new Error(`External references left after inlining:\n  ${leftovers.join('\n  ')}`);

fs.mkdirSync(path.dirname(OUT), { recursive: true });
fs.writeFileSync(OUT, html);

const sha256 = crypto.createHash('sha256').update(html).digest('hex');
console.log(`Inlined: ${inlined.join(', ')}`);
console.log(`Wrote ${path.relative(__dirname, OUT)} (${(Buffer.byteLength(html) / 1024).toFixed(1)} KB)`);
console.log(`SHA-256 ${sha256}`);
