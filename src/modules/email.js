/*
 * Email Header Analyzer module: paste raw headers (or drop a .eml) and see the
 * relay path, recorded authentication results, sender mismatches and the
 * originating IP. Nothing is re-checked online.
 */
(function () {
  'use strict';

  const E = window.OAT.email;

  window.OAT.register({
    id: 'email',
    name: 'Email Header Analyzer',
    summary: 'Relay path with delays, SPF/DKIM/DMARC as recorded by the receiving server, From / Reply-To / Return-Path mismatches and the originating IP.',

    render(root, ctx) {
      const { h, ui } = ctx;

      const input = ui.textarea('Paste the raw headers (Outlook: File › Properties › Internet headers; Gmail: Show original), or drop a .eml file', 'Raw email headers');
      const fileInput = h('input', { type: 'file', accept: '.eml,.txt,message/rfc822', hidden: true });
      const out = h('div');

      root.append(
        ui.panel('Headers', [ui.button('Open .eml…', () => fileInput.click()), ui.button('Clear', () => { input.value = ''; run(); })],
          input, fileInput,
          h('p', { class: 'meta' }, 'SPF, DKIM and DMARC are shown as the receiving server recorded them. They cannot be re-verified offline (that needs DNS).')),
        out);

      function badgeFor(result) {
        const level = result === 'pass' ? 'pass' : ['fail', 'softfail', 'permerror', 'temperror'].includes(result) ? 'high' : 'info';
        return h('span', { class: `badge badge-${level}` }, result);
      }

      function addressCell(a) {
        if (!a) return h('span', { class: 'meta' }, '(none)');
        return h('span', null, a.display ? `${a.display} ` : '', h('code', null, `<${a.address}>`));
      }

      function run() {
        const raw = input.value;
        if (!raw.trim()) { out.replaceChildren(); return; }
        const r = E.analyze(raw);
        if (!r.headers.length) { out.replaceChildren(h('p', { class: 'notice' }, 'No headers found. Paste the full header block, starting at the first header line.')); return; }
        const s = r.summary;

        const summaryRows = [
          ['From', addressCell(s.from)],
          ['Reply-To', addressCell(s.replyTo)],
          ['Return-Path', addressCell(s.returnPath)],
          ['To', s.to],
          ['Subject', s.subject],
          ['Date', s.date],
          ['Message-ID', h('code', null, s.messageId)],
          ['Mailer', s.mailer || h('span', { class: 'meta' }, '(none)')],
          ['Originating IP', s.originatingIp
            ? h('span', { class: 'row nowrap' }, h('code', null, s.originatingIp), h('span', { class: 'meta' }, `from ${s.originatingSource}`),
              ui.button('Look up', () => ctx.sendTo('lookup', s.originatingIp)))
            : h('span', { class: 'meta' }, 'No public IP found in the headers')],
        ];

        const fmtDate = (d) => (d ? d.toISOString().replace('.000Z', 'Z') : '');
        const fmtDelay = (s) => (s === null ? '' : s < 0 ? `${s}s ⚠` : s < 120 ? `${s}s` : `${Math.round(s / 60)} min`);

        out.replaceChildren(
          ui.panel('Findings', null, ui.findings(r.findings)),
          ui.panel('Summary', null, h('dl', { class: 'kv' }, summaryRows.flatMap(([k, v]) => [h('dt', null, k), h('dd', null, v)]))),
          ui.panel('Authentication', null, r.auth.length
            ? ui.table(['Method', 'Result', 'Details', 'Source'], r.auth.map((a) => [a.method.toUpperCase(), badgeFor(a.result), a.detail, a.source]))
            : h('p', { class: 'meta' }, 'No authentication results recorded.')),
          ui.panel(`Relay path (${r.hops.length} hop${r.hops.length === 1 ? '' : 's'}, oldest first)`, null, r.hops.length
            ? ui.table(['#', 'From', 'IPs', 'By', 'With', 'Time (UTC)', 'Delay'], r.hops.map((hop, i) => [
              String(i + 1), hop.from || '', hop.ips.join(', '), hop.by, hop.with, fmtDate(hop.date), fmtDelay(hop.delay)]))
            : h('p', { class: 'meta' }, 'No Received headers.')),
          ui.panel('All headers', [ui.sendSelect(() => input.value)],
            h('details', null, h('summary', null, `${r.headers.length} headers`),
              ui.table(['Name', 'Value'], r.headers.map((x) => [x.name, x.value])))));
      }

      async function loadFile(file) {
        const text = await ui.readTextFile(file, 50 * 1024 * 1024);
        if (text === null) return;
        input.value = text;
        run();
      }

      input.addEventListener('input', ui.debounce(run, 200));
      fileInput.addEventListener('change', () => { if (fileInput.files[0]) loadFile(fileInput.files[0]); fileInput.value = ''; });
      ui.onFileDrop(input, (files) => loadFile(files[0]));

      return {
        receive(text) { input.value = text; run(); },
        focus() { input.focus(); },
      };
    },
  });
})();
