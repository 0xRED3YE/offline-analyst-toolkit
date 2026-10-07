/*
 * Minimal test harness that runs the same test files in Node (tests/run-node.js)
 * and in a browser (tests/runner.html), with no dependencies.
 */
(function (root) {
  'use strict';

  const tests = [];

  function test(name, fn) { tests.push({ name, fn }); }

  function fmt(v) {
    if (v instanceof Uint8Array) return `Uint8Array[${Array.from(v).join(',')}]`;
    try { return JSON.stringify(v); } catch (_) { return String(v); }
  }

  const assert = {
    equal(actual, expected, msg) {
      if (actual !== expected) throw new Error(`${msg ? msg + ': ' : ''}expected ${fmt(expected)}, got ${fmt(actual)}`);
    },
    bytes(actual, expected, msg) {
      const exp = expected instanceof Uint8Array ? expected : Uint8Array.from(expected);
      if (!(actual instanceof Uint8Array) || actual.length !== exp.length || actual.some((b, i) => b !== exp[i])) {
        throw new Error(`${msg ? msg + ': ' : ''}expected ${fmt(exp)}, got ${fmt(actual)}`);
      }
    },
    ok(value, msg) {
      if (!value) throw new Error(msg || `expected a truthy value, got ${fmt(value)}`);
    },
    throws(fn, pattern, msg) {
      try { fn(); } catch (e) {
        if (pattern && !pattern.test(e.message)) throw new Error(`${msg ? msg + ': ' : ''}error "${e.message}" does not match ${pattern}`);
        return;
      }
      throw new Error(`${msg ? msg + ': ' : ''}expected an error`);
    },
  };

  async function runTests() {
    const results = [];
    for (const t of tests) {
      try {
        await t.fn();
        results.push({ name: t.name, ok: true });
      } catch (e) {
        results.push({ name: t.name, ok: false, error: e.message });
      }
    }
    return results;
  }

  root.test = test;
  root.assert = assert;
  root.runTests = runTests;
})(typeof globalThis !== 'undefined' ? globalThis : this);
