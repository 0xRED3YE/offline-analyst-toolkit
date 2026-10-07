#!/usr/bin/env node
/* Runs the unit tests under Node: `npm test` (or `node tests/run-node.js`). */
'use strict';

const fs = require('fs');
const path = require('path');

require('./harness.js');

// Load every library in src/lib/ as OAT.<file name>, as the browser does.
globalThis.OAT = {};
const libDir = path.join(__dirname, '..', 'src', 'lib');
for (const f of fs.readdirSync(libDir).filter((f) => f.endsWith('.js'))) {
  globalThis.OAT[path.basename(f, '.js')] = require(path.join(libDir, f));
}

const unitDir = path.join(__dirname, 'unit');
for (const f of fs.readdirSync(unitDir).filter((f) => f.endsWith('.test.js')).sort()) {
  require(path.join(unitDir, f));
}

globalThis.runTests().then((results) => {
  let failed = 0;
  for (const r of results) {
    if (r.ok) console.log(`  ✓ ${r.name}`);
    else { failed++; console.log(`  ✗ ${r.name}\n      ${r.error}`); }
  }
  console.log(`\n${results.length - failed}/${results.length} passed`);
  process.exitCode = failed ? 1 : 0;
});
