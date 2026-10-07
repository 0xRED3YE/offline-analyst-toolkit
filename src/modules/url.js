/*
 * URL Analyzer module: unwrap redirect layers (SafeLinks, Proofpoint, Google…),
 * show each URL's parts and flag look-alike domains, obfuscated IPs and tricks.
 * Nothing is fetched: the analysis is purely on the text of the URL.
 */
(function () {
  'use strict';

  const U = window.OAT.url;
  const I = window.OAT.ioc;

  window.OAT.register({
    id: 'url',
    name: 'URL Analyzer',
    summary: 'Unwrap SafeLinks, Proofpoint, Google and other redirect wrappers, split a URL into parts, and flag look-alike domains, hidden IPs and other tricks. Nothing is visited.',

    render(root, ctx) {
      const { h, ui } = ctx;
      let result = null;

      const input = ui.textarea('Paste a URL (defanged is fine), e.g. a SafeLinks or Proofpoint link from a phishing email', 'URL', { rows: '3' });
      const out = h('div');
      root.append(ui.panel('URL', ui.button('Clear', () => { input.value = ''; run(); }), input), out);

      function partsList(p) {
        const rows = [
          ['Scheme', p.scheme],
          p.username ? ['Username', h('span', { class: 'error' }, p.username)] : null,
          p.password ? ['Password', h('span', { class: 'error' }, p.password)] : null,
          ['Host', h('code', null, p.host)],
          p.hostUnicode !== p.host ? ['Host (as displayed)', h('code', null, p.hostUnicode)] : null,
          p.port ? ['Port', p.port] : null,
          ['Path', h('code', null, p.path)],
          p.fragment ? ['Fragment', h('code', null, p.fragment)] : null,
        ].filter(Boolean);
        return h('dl', { class: 'kv' }, rows.flatMap(([k, v]) => [h('dt', null, k), h('dd', null, v)]));
      }

      function run() {
        const value = input.value.trim();
        result = null;
        if (!value) { out.replaceChildren(); return; }
        try {
          result = U.analyze(value);
        } catch (e) {
          out.replaceChildren(h('p', { class: 'notice' }, e.message));
          return;
        }
        const final = result.final;
        const finalPanel = ui.panel(result.layers.length > 1 ? `Final destination (after ${result.layers.length - 1} redirect layer${result.layers.length > 2 ? 's' : ''})` : 'Destination',
          [ui.copyButton(() => final.url), ui.copyButton(() => I.defang(final.url, { fileLike: true }).text, 'Copy defanged'),
            ui.button('Look up', () => ctx.sendTo('lookup', final.url)), ui.sendSelect(() => final.url)],
          h('p', null, h('code', { class: 'ioc-value big-url' }, final.url)));

        const layerPanels = result.layers.map((l, i) => ui.panel(i === 0 ? 'Layer 1: as pasted' : `Layer ${i + 1}: unwrapped from ${l.via}`, null,
          h('p', null, h('code', { class: 'ioc-value' }, l.url)),
          l.findings.length ? ui.findings(l.findings) : null,
          l.parts ? h('details', { open: result.layers.length === 1 }, h('summary', null, 'Parts'), partsList(l.parts),
            l.parts.query.length ? ui.table(['Parameter', 'Value'], l.parts.query.map((q) => [h('code', null, q.key), h('code', { class: 'ioc-value' }, q.value)])) : null) : null));

        out.replaceChildren(finalPanel, ...layerPanels);
      }

      input.addEventListener('input', ui.debounce(run, 200));

      return {
        receive(text) { input.value = text.trim().split(/\s*\n/)[0]; run(); },
        focus() { input.focus(); },
      };
    },
  });
})();
