/*
 * Text Diff module: compare two configs, scripts or logs side by side, with
 * word-level highlights, and export a unified .diff.
 */
(function () {
  'use strict';

  const D = window.OAT.diff;
  const BIG = 3000;          // rows above this: show only changes with context
  const CONTEXT = 3;

  window.OAT.register({
    id: 'diff',
    name: 'Text Diff',
    summary: 'Compare two configs, scripts or logs side by side with word-level highlights. Ignore whitespace or case; export a unified .diff.',

    render(root, ctx) {
      const { h, ui } = ctx;
      let last = null;

      const left = ui.textarea('Original (paste or drop a file)', 'Original text', { rows: '10' });
      const right = ui.textarea('Changed (paste or drop a file)', 'Changed text', { rows: '10' });
      const leftName = h('span', { class: 'meta' }, '');
      const rightName = h('span', { class: 'meta' }, '');
      const ignoreWs = h('input', { type: 'checkbox' });
      const ignoreCase = h('input', { type: 'checkbox' });
      const onlyChanges = h('input', { type: 'checkbox' });
      const stats = h('span', { class: 'meta' });
      const view = h('div', { class: 'diff-view' });

      const pane = (title, ta, nameEl) => {
        const fileInput = h('input', { type: 'file', hidden: true });
        fileInput.addEventListener('change', () => { if (fileInput.files[0]) load(fileInput.files[0], ta, nameEl); fileInput.value = ''; });
        ui.onFileDrop(ta, (files) => load(files[0], ta, nameEl));
        return ui.panel(title, [nameEl, ui.button('Open file…', () => fileInput.click())], ta, fileInput);
      };

      root.append(
        h('div', { class: 'grid-2' }, pane('Original', left, leftName), pane('Changed', right, rightName)),
        h('div', { class: 'row options panel-lite' },
          h('label', { class: 'check' }, ignoreWs, 'Ignore whitespace'),
          h('label', { class: 'check' }, ignoreCase, 'Ignore case'),
          h('label', { class: 'check' }, onlyChanges, 'Only show changes'),
          ui.button('Swap', () => { [left.value, right.value] = [right.value, left.value]; [leftName.textContent, rightName.textContent] = [rightName.textContent, leftName.textContent]; run(); })),
        ui.panel('Differences', [stats, ui.copyButton(unifiedText, 'Copy .diff'),
          ui.button('Download .diff', () => ctx.download('changes.diff', unifiedText(), 'text/x-diff;charset=utf-8'))], view));

      async function load(file, ta, nameEl) {
        const text = await ui.readTextFile(file);
        if (text === null) return;
        ta.value = text;
        nameEl.textContent = file.name;
        run();
      }

      function unifiedText() {
        return last ? D.unified(last, { nameA: leftName.textContent || 'original', nameB: rightName.textContent || 'changed' }) : '';
      }

      function cell(side, row) {
        const line = row[side];
        if (!line) return [h('td', { class: 'ln' }), h('td', { class: 'code empty' })];
        const code = h('td', { class: 'code' });
        if (row.type === 'change' && line.text.length < 2000 && row.left.text.length < 2000 && row.right.text.length < 2000) {
          for (const part of D.wordDiff(row.left.text, row.right.text)) {
            if (part.op === '=') code.append(part.text);
            else if ((part.op === '-' && side === 'left') || (part.op === '+' && side === 'right')) code.append(h('mark', null, part.text));
          }
        } else {
          code.textContent = line.text;
        }
        return [h('td', { class: 'ln' }, String(line.n)), code];
      }

      function run() {
        if (!left.value && !right.value) { last = null; view.replaceChildren(h('p', { class: 'meta' }, 'Paste two texts to compare.')); stats.textContent = ''; return; }
        last = D.diffText(left.value, right.value, { ignoreWhitespace: ignoreWs.checked, ignoreCase: ignoreCase.checked });
        const rows = D.sideBySide(last);
        stats.textContent = last.added || last.removed ? `+${last.added} −${last.removed} lines` : 'Identical';
        if (!last.added && !last.removed) { view.replaceChildren(h('p', { class: 'meta ok' }, '✓ No differences.')); return; }

        // Collapse long unchanged stretches when asked, or when the diff is big.
        const collapse = onlyChanges.checked || rows.length > BIG;
        const keep = new Uint8Array(rows.length);
        rows.forEach((r, i) => { if (r.type !== 'equal') for (let j = Math.max(0, i - CONTEXT); j <= Math.min(rows.length - 1, i + CONTEXT); j++) keep[j] = 1; });

        const tbody = h('tbody');
        let skipped = 0;
        const flushSkip = () => {
          if (skipped) tbody.append(h('tr', { class: 'skip' }, h('td', { colspan: '4' }, `… ${skipped} unchanged line${skipped === 1 ? '' : 's'} …`)));
          skipped = 0;
        };
        rows.forEach((r, i) => {
          if (collapse && !keep[i]) { skipped++; return; }
          flushSkip();
          tbody.append(h('tr', { class: `row-${r.type}` }, ...cell('left', r), ...cell('right', r)));
        });
        flushSkip();
        view.replaceChildren(...[
          last.tooDifferent ? h('p', { class: 'notice' }, 'The texts are too different for a line-by-line match; showing them as fully replaced.') : null,
          h('div', { class: 'table-wrap' }, h('table', { class: 'diff' }, tbody)),
        ].filter(Boolean));
      }

      const rerun = ui.debounce(run, 250);
      for (const el of [left, right]) el.addEventListener('input', rerun);
      for (const el of [ignoreWs, ignoreCase, onlyChanges]) el.addEventListener('change', run);
      run();

      return {
        receive(text) { if (!left.value) left.value = text; else right.value = text; run(); },
        focus() { left.focus(); },
      };
    },
  });
})();
