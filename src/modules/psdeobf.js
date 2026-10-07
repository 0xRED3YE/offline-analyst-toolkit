/*
 * PowerShell Deobfuscator module: decode -EncodedCommand layers, compressed
 * payloads and common string obfuscation into readable script. The script is
 * only ever treated as text: nothing is run.
 */
(function () {
  'use strict';

  const P = window.OAT.psdeobf;
  const L = window.OAT.ioc;

  window.OAT.register({
    id: 'ps',
    name: 'PowerShell Deobfuscator',
    summary: 'Decode -EncodedCommand (any abbreviation), Base64 and gzip/deflate payloads; undo backticks, string joins, -f format strings, [char] codes and reversals. Text only: nothing is executed.',

    render(root, ctx) {
      const { h, ui } = ctx;
      let result = null;
      let runId = 0;

      const input = ui.textarea('Paste a PowerShell command line or script, e.g. from an EDR alert, Event ID 4688/4104, or a scheduled task', 'PowerShell');
      const out = h('div');
      root.append(ui.panel('Script', ui.button('Clear', () => { input.value = ''; run(); }), input,
        h('p', { class: 'meta' }, 'Deobfuscation is pattern-based. It can miss tricks it does not know, and the output is for reading only, never for running.')), out);

      async function run() {
        const value = input.value;
        const id = ++runId;
        if (!value.trim()) { result = null; out.replaceChildren(); return; }
        let r;
        try { r = await P.deobfuscateAll(value); } catch (e) { out.replaceChildren(h('p', { class: 'notice' }, e.message)); return; }
        if (id !== runId) return;   // a newer run started while we were decompressing
        result = r;

        const finalOut = h('pre', { class: 'output', tabindex: '0', 'aria-label': 'Deobfuscated script' });
        finalOut.textContent = r.final;
        const labels = Object.fromEntries(L.TYPES.map((t) => [t.id, t.label]));

        out.replaceChildren(...[
          ui.panel('Findings', null, ui.findings(r.findings)),
          ui.panel(`Result${r.layers.length > 2 ? ` (${r.layers.length - 1} steps)` : ''}`,
            [ui.copyButton(() => r.final), ui.button('Download', () => ctx.download('deobfuscated.ps1.txt', r.final, 'text/plain;charset=utf-8')), ui.sendSelect(() => r.final)],
            finalOut),
          r.iocs.length ? ui.panel('Indicators in the script', [ui.button('Send to IOC Extractor', () => ctx.sendTo('ioc', r.iocs.map((x) => x.value).join('\n')))],
            ui.table(['Type', 'Indicator', ''], r.iocs.map((x) => [labels[x.type], h('code', { class: 'ioc-value' }, x.value), ui.button('Look up', () => ctx.sendTo('lookup', x.value))]))) : null,
          r.layers.length > 2 ? ui.panel('All steps', null, ...r.layers.slice(1, -1).map((l) => {
            const pre = h('pre', { class: 'output' });
            pre.textContent = l.text;
            return h('details', null, h('summary', null, l.title), pre);
          })) : null,
        ].filter(Boolean));
      }

      input.addEventListener('input', ui.debounce(run, 250));

      return {
        receive(text) { input.value = text; run(); },
        focus() { input.focus(); },
      };
    },
  });
})();
