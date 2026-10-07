/*
 * Defang / Refang module: make indicators safe to paste into tickets, emails and
 * reports (hxxps[://]evil[.]com), or turn defanged text back into the real thing.
 * Only indicators are changed; the rest of the text is left exactly as it was.
 */
(function () {
  'use strict';

  const I = window.OAT.ioc;

  window.OAT.register({
    id: 'defang',
    name: 'Defang / Refang',
    summary: 'Defang URLs, domains, IPs and emails for tickets and reports (example[.]com, hxxps://), or refang them back.',

    render(root, ctx) {
      const { h, ui } = ctx;
      let mode = 'defang';

      const input = ui.textarea('Paste text containing URLs, domains, IPs or email addresses', 'Text to convert');
      const output = h('pre', { class: 'output', tabindex: '0', 'aria-label': 'Result', 'aria-live': 'polite', 'data-empty': 'Result appears here' });
      const meta = h('span', { class: 'meta' });
      const fileLikeBox = h('input', { type: 'checkbox' });

      const btnDefang = h('button', { type: 'button', 'aria-pressed': 'true', onclick: () => setMode('defang') }, 'Defang');
      const btnRefang = h('button', { type: 'button', 'aria-pressed': 'false', onclick: () => setMode('refang') }, 'Refang');
      const fileLikeLabel = h('label', { class: 'check' }, fileLikeBox, 'Also defang file-like domains (.zip, .mov…)');

      root.append(
        ui.panel('Input', [h('span', { class: 'seg', role: 'group', 'aria-label': 'Direction' }, btnDefang, btnRefang)],
          input, h('div', { class: 'row options' }, fileLikeLabel)),
        ui.panel('Result', [meta, ui.copyButton(() => output.textContent),
          ui.button('Download', () => ctx.download(`${mode}ed.txt`, output.textContent, 'text/plain;charset=utf-8')),
          ui.sendSelect(() => output.textContent)], output));

      function setMode(m) {
        mode = m;
        btnDefang.setAttribute('aria-pressed', String(m === 'defang'));
        btnRefang.setAttribute('aria-pressed', String(m === 'refang'));
        fileLikeLabel.hidden = m !== 'defang';
        run();
      }

      function run() {
        const text = input.value;
        if (!text) { output.textContent = ''; meta.textContent = ''; return; }
        if (mode === 'defang') {
          const r = I.defang(text, { fileLike: fileLikeBox.checked });
          output.textContent = r.text;
          meta.textContent = `${r.count} indicator${r.count === 1 ? '' : 's'} defanged`;
        } else {
          const r = I.refang(text);
          output.textContent = r;
          meta.textContent = r === text ? 'Nothing to refang' : 'Refanged';
        }
      }

      input.addEventListener('input', ui.debounce(run, 120));
      fileLikeBox.addEventListener('change', run);

      return {
        receive(text) { input.value = text; run(); },
        focus() { input.focus(); },
      };
    },
  });
})();
