/*
 * Regex Tester module: test a pattern against sample logs with highlighted
 * matches, groups and replace. Matching runs in a Web Worker with a time limit,
 * so a catastrophic-backtracking pattern cannot freeze the page.
 */
(function () {
  'use strict';

  const R = window.OAT.regex;
  const TIMEOUT_MS = 2000;
  const HIGHLIGHT_LIMIT = 500000;   // characters rendered with highlights

  const WORKER_SOURCE = `'use strict';
const R = ${R.factorySource}();
self.onmessage = (e) => {
  const { id, pattern, flags, text, replacement } = e.data;
  self.postMessage({ id, result: R.run(pattern, flags, text, { replacement }) });
};`;

  let workerUrl = null;
  function newWorker() {
    try {
      if (!workerUrl) workerUrl = URL.createObjectURL(new Blob([WORKER_SOURCE], { type: 'text/javascript' }));
      return new Worker(workerUrl);
    } catch (_) {
      return null;
    }
  }

  window.OAT.register({
    id: 'regex',
    name: 'Regex Tester',
    summary: 'Test JavaScript regular expressions against sample logs: highlighted matches, capture groups, replace, and ready-made SOC patterns. Runs with a time limit.',

    render(root, ctx) {
      const { h, ui } = ctx;
      let worker = null;
      let seq = 0;
      let timer = null;
      let lastResult = null;

      const pattern = h('input', { type: 'text', class: 'input mono big', spellcheck: 'false', autocomplete: 'off', placeholder: 'Pattern, e.g. (?<ip>\\d+\\.\\d+\\.\\d+\\.\\d+)', 'aria-label': 'Regular expression' });
      const flagBoxes = Object.fromEntries(['g', 'i', 'm', 's', 'u'].map((f) => [f, h('input', { type: 'checkbox', checked: f === 'g' })]));
      const flagHelp = { g: 'global', i: 'ignore case', m: 'multiline ^$', s: 'dot matches newline', u: 'unicode' };
      const presets = h('select', { 'aria-label': 'Preset patterns' }, h('option', { value: '' }, 'Presets…'), R.PRESETS.map((p, i) => h('option', { value: String(i) }, p.name)));
      const text = ui.textarea('Sample text or log lines to test against', 'Test text', { rows: '8' });
      const replaceOn = h('input', { type: 'checkbox' });
      const replacement = h('input', { type: 'text', class: 'input mono', placeholder: 'Replacement, e.g. [$1] or $<ip>', 'aria-label': 'Replacement', disabled: true });
      const status = h('span', { class: 'meta' });
      const highlighted = h('pre', { class: 'output', tabindex: '0', 'aria-label': 'Text with matches highlighted' });
      const matchesBox = h('div');
      const replacedOut = h('pre', { class: 'output', tabindex: '0', 'aria-label': 'Replaced text', hidden: true });

      root.append(
        ui.panel('Pattern', [presets],
          h('div', { class: 'row' }, h('span', { class: 'mono slash' }, '/'), pattern, h('span', { class: 'mono slash' }, '/')),
          h('div', { class: 'row options' }, Object.entries(flagBoxes).map(([f, box]) => h('label', { class: 'check', title: flagHelp[f] }, box, h('code', null, f), h('span', { class: 'meta' }, flagHelp[f])))),
          h('p', { class: 'meta' }, 'JavaScript regex flavour: close to PCRE, but no possessive quantifiers or atomic groups, and lookbehind must be fixed-width in other engines.')),
        ui.panel('Test text', [h('label', { class: 'check' }, replaceOn, 'Replace'), replacement], text),
        ui.panel('Matches', [status, ui.copyButton(() => (lastResult ? lastResult.matches.map((m) => m.text).join('\n') : ''), 'Copy matches'),
          ui.sendSelect(() => (lastResult ? lastResult.matches.map((m) => m.text).join('\n') : ''))],
          highlighted, replacedOut, matchesBox));

      function flags() { return Object.entries(flagBoxes).filter(([, b]) => b.checked).map(([f]) => f).join(''); }

      function run() {
        clearTimeout(timer);
        if (!pattern.value) { show({ matches: [] }, true); status.textContent = ''; return; }
        if (!worker) worker = newWorker();
        const msg = { id: ++seq, pattern: pattern.value, flags: flags(), text: text.value, replacement: replaceOn.checked ? replacement.value : null };
        if (!worker) { show(R.run(msg.pattern, msg.flags, msg.text, { replacement: msg.replacement })); return; }   // no workers: run inline
        status.textContent = 'Running…';
        worker.onmessage = (e) => { if (e.data.id === seq) { clearTimeout(timer); show(e.data.result); } };
        worker.onerror = (e) => {   // worker could not start (e.g. blocked by policy): run inline instead
          e.preventDefault();
          clearTimeout(timer);
          worker = null;
          show(R.run(msg.pattern, msg.flags, msg.text, { replacement: msg.replacement }));
        };
        timer = setTimeout(() => {
          worker.terminate();
          worker = null;
          status.textContent = '';
          matchesBox.replaceChildren(h('p', { class: 'notice' }, `Stopped after ${TIMEOUT_MS / 1000} s: the pattern is probably backtracking catastrophically (nested quantifiers like (a+)+ are the usual cause).`));
          highlighted.textContent = text.value.slice(0, HIGHLIGHT_LIMIT);
        }, TIMEOUT_MS);
        worker.postMessage(msg);
      }

      function show(result, empty = false) {
        lastResult = result;
        if (result.error) {
          status.textContent = '';
          matchesBox.replaceChildren(h('p', { class: 'notice' }, result.error));
          highlighted.textContent = text.value.slice(0, HIGHLIGHT_LIMIT);
          replacedOut.hidden = true;
          return;
        }
        const ms = result.matches;
        if (!empty) status.textContent = `${ms.length}${result.truncated ? '+' : ''} match${ms.length === 1 ? '' : 'es'}`;

        // Highlight: alternate plain text nodes and <mark> elements.
        const t = text.value.slice(0, HIGHLIGHT_LIMIT);
        const frag = document.createDocumentFragment();
        let pos = 0;
        for (const m of ms) {
          if (m.index >= t.length) break;
          if (m.index > pos) frag.append(t.slice(pos, m.index));
          frag.append(h('mark', { class: m.text ? '' : 'empty-match' }, m.text || '​'));
          pos = Math.max(pos, m.end);
        }
        frag.append(t.slice(pos));
        highlighted.replaceChildren(frag);

        replacedOut.hidden = result.replaced === undefined;
        if (result.replaced !== undefined) replacedOut.textContent = result.replaced;

        const groupCount = ms.length ? ms[0].groups.length : 0;
        const named = ms.length && ms[0].named ? Object.keys(ms[0].named) : [];
        matchesBox.replaceChildren(ms.length
          ? ui.table(['#', 'Index', 'Match', ...Array.from({ length: groupCount }, (_, i) => named[i] ? `$${i + 1} (${named[i]})` : `$${i + 1}`)],
            ms.slice(0, 1000).map((m, i) => [String(i + 1), String(m.index), h('code', null, m.text), ...m.groups.map((g) => (g === undefined ? h('span', { class: 'meta' }, '—') : h('code', null, g)))]))
          : h('p', { class: 'meta' }, empty ? '' : 'No matches.'));
      }

      presets.addEventListener('change', () => {
        const p = R.PRESETS[Number(presets.value)];
        presets.value = '';
        if (!p) return;
        pattern.value = p.pattern;
        for (const [f, box] of Object.entries(flagBoxes)) box.checked = p.flags.includes(f);
        run();
      });
      const rerun = ui.debounce(run, 200);
      for (const el of [pattern, text, replacement]) el.addEventListener('input', rerun);
      for (const box of Object.values(flagBoxes)) box.addEventListener('change', run);
      replaceOn.addEventListener('change', () => { replacement.disabled = !replaceOn.checked; run(); });

      return {
        receive(value) { text.value = value; run(); },
        focus() { pattern.focus(); },
      };
    },
  });
})();
