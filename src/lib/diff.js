/*
 * diff.js: line and word diffs (Myers' O(ND) algorithm) and unified diff output.
 */
(function (root, factory) {
  const lib = factory();
  if (typeof module === 'object' && module.exports) module.exports = lib;
  else (root.OAT = root.OAT || {}).diff = lib;
})(globalThis, function () {
  'use strict';

  const MAX_EDITS = 4000;   // beyond this the inputs are "too different" for a useful diff

  // Edit script between arrays a and b (compared with ===).
  // Returns [{ op: '=', a: i, b: j } | { op: '-', a: i } | { op: '+', b: j }], or null if too different.
  function myers(a, b) {
    let start = 0;
    while (start < a.length && start < b.length && a[start] === b[start]) start++;
    let endA = a.length, endB = b.length;
    while (endA > start && endB > start && a[endA - 1] === b[endB - 1]) { endA--; endB--; }

    const n = endA - start, m = endB - start;
    const max = n + m;
    const off = max + 1;
    const v = new Int32Array(2 * max + 3);
    const trace = [];
    let found = -1;

    outer:
    for (let d = 0; d <= max; d++) {
      if (d > MAX_EDITS) return null;
      trace.push(v.slice(off - d, off + d + 1));
      for (let k = -d; k <= d; k += 2) {
        let x = (k === -d || (k !== d && v[off + k - 1] < v[off + k + 1])) ? v[off + k + 1] : v[off + k - 1] + 1;
        let y = x - k;
        while (x < n && y < m && a[start + x] === b[start + y]) { x++; y++; }
        v[off + k] = x;
        if (x >= n && y >= m) { found = d; break outer; }
      }
    }

    // Walk back through the saved states.
    const rev = [];
    let x = n, y = m;
    for (let d = found; d > 0; d--) {
      const saved = trace[d];                    // state before step d; index k + d
      const at = (k) => saved[k + d];
      const k = x - y;
      const prevK = (k === -d || (k !== d && at(k - 1) < at(k + 1))) ? k + 1 : k - 1;
      const prevX = at(prevK);
      const prevY = prevX - prevK;
      while (x > prevX && y > prevY) { x--; y--; rev.push({ op: '=', a: start + x, b: start + y }); }
      if (x === prevX) { y--; rev.push({ op: '+', b: start + y }); }
      else { x--; rev.push({ op: '-', a: start + x }); }
    }
    while (x > 0 && y > 0) { x--; y--; rev.push({ op: '=', a: start + x, b: start + y }); }

    const ops = [];
    for (let i = 0; i < start; i++) ops.push({ op: '=', a: i, b: i });
    for (let i = rev.length - 1; i >= 0; i--) ops.push(rev[i]);
    for (let i = 0; i < a.length - endA; i++) ops.push({ op: '=', a: endA + i, b: endB + i });
    return ops;
  }

  function splitLines(text) {
    if (text === '') return [];
    const lines = text.replace(/\r\n?/g, '\n').split('\n');
    if (lines[lines.length - 1] === '') lines.pop();
    return lines;
  }

  // Line diff with options. Returns { ops, a, b, added, removed, tooDifferent }.
  function diffText(left, right, { ignoreWhitespace = false, ignoreCase = false } = {}) {
    const a = splitLines(left), b = splitLines(right);
    const key = (s) => {
      let t = ignoreWhitespace ? s.replace(/\s+/g, ' ').trim() : s;
      if (ignoreCase) t = t.toLowerCase();
      return t;
    };
    let ops = myers(a.map(key), b.map(key));
    let tooDifferent = false;
    if (!ops) {
      tooDifferent = true;
      ops = [...a.map((_, i) => ({ op: '-', a: i })), ...b.map((_, j) => ({ op: '+', b: j }))];
    }
    return {
      ops, a, b, tooDifferent,
      added: ops.filter((o) => o.op === '+').length,
      removed: ops.filter((o) => o.op === '-').length,
    };
  }

  // Rows for a side-by-side view: changed blocks are paired line by line.
  // [{ type: 'equal'|'change'|'delete'|'insert', left?: {n, text}, right?: {n, text} }]
  function sideBySide(result) {
    const rows = [];
    const { ops, a, b } = result;
    let i = 0;
    while (i < ops.length) {
      if (ops[i].op === '=') {
        rows.push({ type: 'equal', left: { n: ops[i].a + 1, text: a[ops[i].a] }, right: { n: ops[i].b + 1, text: b[ops[i].b] } });
        i++;
        continue;
      }
      const dels = [], ins = [];
      while (i < ops.length && ops[i].op !== '=') { (ops[i].op === '-' ? dels : ins).push(ops[i]); i++; }
      const len = Math.max(dels.length, ins.length);
      for (let r = 0; r < len; r++) {
        const d = dels[r], s = ins[r];
        rows.push({
          type: d && s ? 'change' : d ? 'delete' : 'insert',
          left: d ? { n: d.a + 1, text: a[d.a] } : null,
          right: s ? { n: s.b + 1, text: b[s.b] } : null,
        });
      }
    }
    return rows;
  }

  // Word-level diff of two lines: [{ op: '='|'-'|'+', text }].
  function wordDiff(left, right) {
    const tok = (s) => s.match(/\s+|[\p{L}\p{N}_]+|[^\s\p{L}\p{N}_]/gu) || [];
    const a = tok(left), b = tok(right);
    if (a.length * b.length > 250000) return [{ op: '-', text: left }, { op: '+', text: right }];
    const ops = myers(a, b);
    if (!ops) return [{ op: '-', text: left }, { op: '+', text: right }];
    const out = [];
    for (const o of ops) {
      const text = o.op === '+' ? b[o.b] : a[o.a];
      const last = out[out.length - 1];
      if (last && last.op === o.op) last.text += text;
      else out.push({ op: o.op, text });
    }
    return out;
  }

  // Standard unified diff with `context` lines around each change.
  function unified(result, { nameA = 'a', nameB = 'b', context = 3 } = {}) {
    const { ops, a, b } = result;
    if (!ops.some((o) => o.op !== '=')) return '';
    const lines = [`--- ${nameA}`, `+++ ${nameB}`];
    const changeIdx = ops.map((o, i) => (o.op !== '=' ? i : -1)).filter((i) => i >= 0);
    let h = 0;
    while (h < changeIdx.length) {
      let from = Math.max(0, changeIdx[h] - context);
      let to = Math.min(ops.length - 1, changeIdx[h] + context);
      while (h + 1 < changeIdx.length && changeIdx[h + 1] - context <= to + 1) { h++; to = Math.min(ops.length - 1, changeIdx[h] + context); }
      h++;
      const slice = ops.slice(from, to + 1);
      const firstA = slice.find((o) => o.a !== undefined);
      const firstB = slice.find((o) => o.b !== undefined);
      const countA = slice.filter((o) => o.op !== '+').length;
      const countB = slice.filter((o) => o.op !== '-').length;
      const startA = countA ? firstA.a + 1 : (firstA ? firstA.a : precedingA(ops, from));
      const startB = countB ? firstB.b + 1 : (firstB ? firstB.b : precedingB(ops, from));
      lines.push(`@@ -${startA},${countA} +${startB},${countB} @@`);
      for (const o of slice) lines.push(o.op === '=' ? ` ${a[o.a]}` : o.op === '-' ? `-${a[o.a]}` : `+${b[o.b]}`);
    }
    return lines.join('\n') + '\n';
  }

  function precedingA(ops, i) { for (let j = i - 1; j >= 0; j--) if (ops[j].a !== undefined) return ops[j].a + 1; return 0; }
  function precedingB(ops, i) { for (let j = i - 1; j >= 0; j--) if (ops[j].b !== undefined) return ops[j].b + 1; return 0; }

  return { myers, diffText, sideBySide, wordDiff, unified, splitLines };
});
