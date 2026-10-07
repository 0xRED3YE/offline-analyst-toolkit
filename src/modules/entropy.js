/*
 * Entropy / Strings module: is this file packed or encrypted? What readable
 * strings are inside it? Which values in a list look random (DGA domains)?
 */
(function () {
  'use strict';

  const E = window.OAT.entropy;
  const C = window.OAT.codecs;
  const H = window.OAT.hashes;
  const MAX_FILE = 200 * 1024 * 1024;
  const SHOW_STRINGS = 2000;
  const SVG_NS = 'http://www.w3.org/2000/svg';

  window.OAT.register({
    id: 'entropy',
    name: 'Entropy / Strings',
    summary: 'Shannon entropy of a file or text (packed? encrypted?), an entropy profile, ASCII and UTF-16 strings with offsets, and per-line entropy for spotting random-looking domains.',

    render(root, ctx) {
      const { h, ui } = ctx;
      let bytes = null;
      let fileName = '';
      let found = [];

      const fileInput = h('input', { type: 'file', hidden: true });
      const drop = h('div', { class: 'dropzone', tabindex: '0', role: 'button', 'aria-label': 'Choose a file to analyse' },
        h('strong', null, 'Drop a file here'), ' or click to choose (up to 200 MB). Read locally; nothing is uploaded.');
      const textIn = ui.textarea('…or paste text. One value per line gives a per-line entropy ranking (e.g. domains from DNS logs).', 'Text', { rows: '5' });

      const summary = h('div');
      const chart = h('div', { class: 'entropy-chart' });
      const minLen = h('input', { type: 'number', class: 'input narrow', min: '3', max: '64', value: '6', 'aria-label': 'Minimum string length' });
      const onlyInteresting = h('input', { type: 'checkbox' });
      const filter = h('input', { type: 'text', class: 'input', placeholder: 'Filter strings', 'aria-label': 'Filter strings' });
      const stringsBox = h('div');
      const stringsMeta = h('span', { class: 'meta' });
      const perLineBox = h('div');

      const filePanels = h('div', { hidden: true },
        ui.panel('Summary', null, summary, chart),
        ui.panel('Strings', [stringsMeta,
          ui.copyButton(() => visibleStrings().map((s) => s.text).join('\n'), 'Copy'),
          ui.button('Download', () => ctx.download(`${fileName || 'data'}.strings.txt`, visibleStrings().map((s) => `${s.offset.toString(16).padStart(8, '0')}  ${s.enc === 'ascii' ? 'A' : 'U'}  ${s.text}`).join('\n'), 'text/plain;charset=utf-8')),
          ui.sendSelect(() => visibleStrings().map((s) => s.text).join('\n'))],
          h('div', { class: 'row options' }, h('label', { class: 'row' }, 'Min length', minLen), h('label', { class: 'check' }, onlyInteresting, 'Only interesting'), filter),
          stringsBox));
      const textPanel = h('div', { hidden: true }, ui.panel('Text entropy', null, perLineBox));

      root.append(ui.panel('Input', [ui.button('Clear', clearAll)], drop, fileInput, textIn), filePanels, textPanel);

      // ---------------------------------------------------------- File analysis

      async function loadFile(file) {
        if (file.size > MAX_FILE) { ctx.toast('File is over 200 MB'); return; }
        bytes = new Uint8Array(await file.arrayBuffer());
        fileName = file.name;
        textIn.value = '';
        textPanel.hidden = true;
        analyseBytes();
      }

      function analyseBytes() {
        const h0 = E.shannon(bytes);
        // At least 1 KB per block: on fewer samples even random data measures below 7.2 bits/byte.
        const blockSize = bytes.length > 64 * 1024 * 1024 ? 65536 : bytes.length > 4 * 1024 * 1024 ? 16384 : bytes.length > 256 * 1024 ? 4096 : 1024;
        const profile = E.blocks(bytes, blockSize);
        const highShare = profile.filter((x) => x >= 7.2).length / (profile.length || 1);
        const kind = C.sniff(bytes);
        summary.replaceChildren(h('dl', { class: 'kv' },
          h('dt', null, 'File'), h('dd', null, `${fileName} · ${formatSize(bytes.length)}${kind ? ` · ${kind}` : ''}`),
          h('dt', null, 'Entropy'), h('dd', null, h('strong', null, `${h0.toFixed(3)} bits/byte`), ` · ${E.verdict(h0)}`),
          h('dt', null, 'High-entropy blocks'), h('dd', null, `${Math.round(highShare * 100)}% of ${profile.length} blocks of ${formatSize(blockSize)} are ≥ 7.2`),
          bytes.length <= 50 * 1024 * 1024 ? [h('dt', null, 'SHA-256'), h('dd', null, h('code', null, H.toHex(H.hash('sha256', bytes))))] : null));
        chart.replaceChildren(renderChart(profile, blockSize));
        found = E.strings(bytes, { min: Number(minLen.value) || 6 });
        for (const s of found.strings) s.why = undefined;
        filePanels.hidden = false;
        renderStrings();
      }

      // Entropy per block as bars (0–8), with the 7.2 "likely packed/encrypted" line.
      function renderChart(profile, blockSize) {
        const width = Math.min(600, profile.length) || 1;
        const per = profile.length / width;
        const svg = document.createElementNS(SVG_NS, 'svg');
        svg.setAttribute('viewBox', `0 0 ${width} 100`);
        svg.setAttribute('preserveAspectRatio', 'none');
        svg.setAttribute('class', 'entropy-svg');
        svg.setAttribute('role', 'img');
        svg.setAttribute('aria-label', 'Entropy per block, 0 to 8 bits per byte');
        for (let x = 0; x < width; x++) {
          let v = 0;
          for (let i = Math.floor(x * per); i < Math.max(Math.floor((x + 1) * per), Math.floor(x * per) + 1) && i < profile.length; i++) v = Math.max(v, profile[i]);
          const r = document.createElementNS(SVG_NS, 'rect');
          r.setAttribute('x', String(x));
          r.setAttribute('width', '1');
          r.setAttribute('y', String(100 - (v / 8) * 100));
          r.setAttribute('height', String((v / 8) * 100));
          r.setAttribute('class', v >= 7.2 ? 'bar-hot' : 'bar');
          svg.append(r);
        }
        const line = document.createElementNS(SVG_NS, 'line');
        for (const [k, v] of Object.entries({ x1: 0, x2: width, y1: 10, y2: 10, class: 'threshold' })) line.setAttribute(k, String(v));
        svg.append(line);
        return h('div', null, svg, h('p', { class: 'meta' }, `Each bar is the highest entropy in its slice of the file (block size ${formatSize(blockSize)}). Dashed line: 7.2 bits/byte; red bars above it are likely compressed or encrypted.`));
      }

      function visibleStrings() {
        const q = filter.value.trim().toLowerCase();
        return found.strings.filter((s) => {
          if (q && !s.text.toLowerCase().includes(q)) return false;
          if (onlyInteresting.checked) {
            if (s.why === undefined) s.why = E.interesting(s.text);
            return Boolean(s.why);
          }
          return true;
        });
      }

      function renderStrings() {
        const list = visibleStrings();
        stringsMeta.textContent = `${list.length.toLocaleString()} of ${found.strings.length.toLocaleString()}${found.truncated ? '+' : ''} strings`;
        const shown = list.slice(0, SHOW_STRINGS);
        stringsBox.replaceChildren(...[
          ui.table(['Offset', 'Enc', 'String', ''], shown.map((s) => {
            if (s.why === undefined) s.why = E.interesting(s.text);
            return [h('code', null, s.offset.toString(16).padStart(8, '0')), s.enc === 'ascii' ? 'ASCII' : 'UTF-16', h('code', { class: 'ioc-value' }, s.text),
              s.why ? h('span', { class: 'badge badge-medium' }, s.why) : ''];
          })),
          list.length > SHOW_STRINGS ? h('p', { class: 'meta' }, `Showing the first ${SHOW_STRINGS.toLocaleString()}. Use the filter, or Download for all.`) : null,
        ].filter(Boolean));
      }

      // ---------------------------------------------------------- Text analysis

      function analyseText() {
        const t = textIn.value;
        if (!t.trim()) { textPanel.hidden = true; return; }
        bytes = null;
        filePanels.hidden = true;
        textPanel.hidden = false;
        const b = C.utf8(t);
        const lines = E.perLine(t);
        perLineBox.replaceChildren(
          h('dl', { class: 'kv' }, h('dt', null, 'Whole text'), h('dd', null, h('strong', null, `${E.shannon(b).toFixed(3)} bits/byte`), ` · ${E.verdict(E.shannon(b))}`)),
          ...(lines.length > 1 ? [
            h('p', { class: 'meta' }, 'Per line, highest first. For domains the TLD is ignored. Random-looking names (DGA, tunnelling) usually score above 3.5 bits/char when 10+ characters long.'),
            ui.table(['Value', 'Length', 'Bits/char'], lines.slice(0, 2000).map((l) => [h('code', { class: 'ioc-value' }, l.line), String(l.length),
              h('span', { class: l.entropy >= 3.5 && l.length >= 10 ? 'badge badge-medium' : '' }, l.entropy.toFixed(2))])),
          ] : []));
      }

      function clearAll() {
        bytes = null; found = []; fileName = ''; textIn.value = '';
        filePanels.hidden = true; textPanel.hidden = true;
      }

      drop.addEventListener('click', () => fileInput.click());
      drop.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileInput.click(); } });
      fileInput.addEventListener('change', () => { if (fileInput.files[0]) loadFile(fileInput.files[0]); fileInput.value = ''; });
      ui.onFileDrop(drop, (files) => loadFile(files[0]));
      textIn.addEventListener('input', ui.debounce(analyseText, 200));
      minLen.addEventListener('change', () => { if (bytes) { found = E.strings(bytes, { min: Math.max(3, Number(minLen.value) || 6) }); renderStrings(); } });
      onlyInteresting.addEventListener('change', renderStrings);
      filter.addEventListener('input', ui.debounce(renderStrings, 150));

      return {
        receive(text) { textIn.value = text; analyseText(); },
        focus() { textIn.focus(); },
      };
    },
  });

  function formatSize(n) {
    if (n < 1024) return `${n} B`;
    if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / 1048576).toFixed(1)} MB`;
  }
})();
