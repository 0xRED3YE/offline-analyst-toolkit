/*
 * IOC Extractor module: pull indicators out of pasted text or a log file,
 * dedupe and count them, filter, and export as text, CSV or JSON.
 */
(function () {
  'use strict';

  const I = window.OAT.ioc;
  const AUTO_LIMIT = 1024 * 1024;   // above this many characters, extraction waits for a click

  window.OAT.register({
    id: 'ioc',
    name: 'IOC Extractor',
    summary: 'Pull IPs, domains, URLs, emails, hashes, CVE IDs and ATT&CK technique IDs from text or a log. Defanged input is refanged first.',

    render(root, ctx) {
      const { h, ui } = ctx;
      let items = [];
      const hiddenTypes = new Set();

      const input = ui.textarea('Paste a log, alert, email or report, or drop a text file', 'Text to extract from');
      const inputMeta = h('span', { class: 'meta' });
      const runBtn = h('button', { type: 'button', class: 'btn btn-primary btn-small', hidden: true, onclick: run }, 'Extract');
      const fileInput = h('input', { type: 'file', hidden: true });

      const opt = (label, checked = false) => {
        const box = h('input', { type: 'checkbox', checked });
        return { box, el: h('label', { class: 'check' }, box, label) };
      };
      const optRefang = opt('Refang input first', true);
      const optHidePrivate = opt('Hide private and reserved IPs');
      const optFileLike = opt('Include file-like domains (.zip, .mov, .py…)');
      const optDefang = opt('Defang output');

      const typeFilters = h('div', { class: 'row type-filters', role: 'group', 'aria-label': 'Show types' });
      const results = h('div');
      const resultMeta = h('span', { class: 'meta' });

      const inputPanel = ui.panel('Input', [inputMeta, runBtn, ui.button('Open file…', () => fileInput.click()), ui.button('Clear', () => { input.value = ''; run(); })],
        input, fileInput,
        h('div', { class: 'row options' }, optRefang.el, optHidePrivate.el, optFileLike.el, optDefang.el));
      const resultPanel = ui.panel('Indicators', [resultMeta,
        ui.copyButton(() => visible().map(display).join('\n'), 'Copy'),
        ui.button('CSV', exportCsv), ui.button('JSON', exportJson),
        ui.sendSelect(() => visible().map(display).join('\n'))],
        typeFilters, results);
      root.append(inputPanel, resultPanel);

      // ---------------------------------------------------------- Logic

      const display = (it) => (optDefang.box.checked ? I.defang(it.value, { fileLike: true }).text : it.value);

      function visible() {
        return items.filter((it) => !hiddenTypes.has(it.type) && !(optHidePrivate.box.checked && it.note && (it.type === 'ipv4' || it.type === 'ipv6')));
      }

      function run() {
        items = input.value ? I.extract(input.value, { refangFirst: optRefang.box.checked, fileLike: optFileLike.box.checked }) : [];
        runBtn.hidden = true;
        render();
      }

      function render() {
        const counts = {};
        for (const it of items) counts[it.type] = (counts[it.type] || 0) + 1;
        typeFilters.replaceChildren(...I.TYPES.filter((t) => counts[t.id]).map((t) => {
          const box = h('input', { type: 'checkbox', checked: !hiddenTypes.has(t.id) });
          box.addEventListener('change', () => { if (box.checked) hiddenTypes.delete(t.id); else hiddenTypes.add(t.id); render(); });
          return h('label', { class: 'check chip-check' }, box, `${t.label} (${counts[t.id]})`);
        }));

        const list = visible();
        const hidden = items.length - list.length;
        resultMeta.textContent = items.length ? `${list.length} shown${hidden ? `, ${hidden} hidden` : ''}` : '';
        if (!items.length) {
          results.replaceChildren(h('p', { class: 'meta' }, input.value ? 'No indicators found.' : 'Indicators appear here.'));
          return;
        }
        const label = Object.fromEntries(I.TYPES.map((t) => [t.id, t.label]));
        results.replaceChildren(ui.table(['Type', 'Indicator', 'Count', 'Note', ''], list.map((it) => [
          label[it.type],
          h('code', { class: 'ioc-value' }, display(it)),
          String(it.count),
          it.note ? h('span', { class: 'badge badge-info' }, it.note) : '',
          h('span', { class: 'row nowrap' },
            ui.copyButton(() => display(it)),
            it.type !== 'email' ? ui.button('Look up', () => ctx.sendTo('lookup', it.value)) : null),
        ]), { 'aria-label': 'Extracted indicators' }));
      }

      // Values that start with = + - @ are prefixed with ' so spreadsheets do not run them as formulas.
      function csvCell(v) {
        let s = String(v);
        if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
        return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
      }

      function exportCsv() {
        const rows = [['type', 'value', 'count', 'note'], ...visible().map((it) => [it.type, display(it), it.count, it.note || ''])];
        ctx.download('iocs.csv', rows.map((r) => r.map(csvCell).join(',')).join('\r\n') + '\r\n', 'text/csv;charset=utf-8');
      }

      function exportJson() {
        const data = visible().map((it) => ({ type: it.type, value: display(it), count: it.count, ...(it.note ? { note: it.note } : {}) }));
        ctx.download('iocs.json', JSON.stringify(data, null, 2), 'application/json');
      }

      function onInput() {
        inputMeta.textContent = input.value ? `${input.value.length.toLocaleString()} characters` : '';
        if (input.value.length > AUTO_LIMIT) { runBtn.hidden = false; return; }
        run();
      }

      async function loadFile(file) {
        const text = await ui.readTextFile(file);
        if (text === null) return;
        input.value = text;
        onInput();
      }

      input.addEventListener('input', ui.debounce(onInput, 250));
      for (const o of [optRefang, optFileLike]) o.box.addEventListener('change', run);
      for (const o of [optHidePrivate, optDefang]) o.box.addEventListener('change', render);
      fileInput.addEventListener('change', () => { if (fileInput.files[0]) loadFile(fileInput.files[0]); fileInput.value = ''; });
      ui.onFileDrop(input, (files) => loadFile(files[0]));

      render();

      return {
        receive(text) { input.value = text; onInput(); },
        focus() { input.focus(); },
      };
    },
  });
})();
