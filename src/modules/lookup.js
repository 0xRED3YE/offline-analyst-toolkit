/*
 * Lookup Links module: one-click links to reputation sites for each indicator.
 * The toolkit never contacts these sites itself; a link opens only when the
 * analyst clicks it, in a new tab without a referrer.
 */
(function () {
  'use strict';

  const I = window.OAT.ioc;
  const L = window.OAT.lookup;

  window.OAT.register({
    id: 'lookup',
    name: 'Lookup Links',
    summary: 'Links to VirusTotal, AbuseIPDB, Shodan, URLhaus, urlscan and more for each indicator. Nothing is contacted until you click.',

    render(root, ctx) {
      const { h, ui } = ctx;

      const input = ui.textarea('Paste indicators (one per line, or any text; defanged is fine)', 'Indicators', { rows: '5' });
      const out = h('div');

      root.append(
        ui.panel('Indicators', ui.button('Clear', () => { input.value = ''; run(); }), input,
          h('p', { class: 'notice notice-warn' },
            'Clicking a link sends that indicator to the third-party site. For sensitive cases, think about who can see the lookup: some services show searches publicly, and an attacker watching their own infrastructure may notice.')),
        ui.panel('Links', null, out));

      const label = Object.fromEntries(I.TYPES.map((t) => [t.id, t.label]));

      function run() {
        const items = input.value.trim() ? I.extract(input.value, { fileLike: true }) : [];
        if (!items.length) {
          out.replaceChildren(h('p', { class: 'meta' }, input.value.trim() ? 'No indicators recognised.' : 'Links appear here.'));
          return;
        }
        out.replaceChildren(ui.table(['Indicator', 'Type', 'Look up on'], items.map((it) => {
          const links = L.linksFor(it.type, it.value);
          return [
            h('code', { class: 'ioc-value' }, it.value),
            h('span', null, label[it.type], it.note ? h('span', { class: 'badge badge-info' }, it.note) : null),
            links.length
              ? h('span', { class: 'row links' }, links.map((l) =>
                h('a', { class: 'btn btn-small', href: l.url, target: '_blank', rel: 'noopener noreferrer', referrerpolicy: 'no-referrer' }, l.name)))
              : h('span', { class: 'meta' }, 'No lookups for this type'),
          ];
        }), { 'aria-label': 'Lookup links' }));
      }

      input.addEventListener('input', ui.debounce(run, 200));
      run();

      return {
        receive(text) { input.value = text; run(); },
        focus() { input.focus(); },
      };
    },
  });
})();
