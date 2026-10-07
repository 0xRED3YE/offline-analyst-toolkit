/*
 * Case Notes module: collect indicators, verdicts, a timeline and notes during
 * an investigation, and export a report (Markdown, HTML or JSON).
 *
 * Nothing is stored unless the analyst ticks "Keep in this browser". Then the
 * case lives in this browser's local storage only (never sent anywhere).
 */
(function () {
  'use strict';

  const CR = window.OAT.casereport;
  const I = window.OAT.ioc;
  const STORE_KEY = 'oat.case.v1';

  const storage = {
    load() { try { const v = localStorage.getItem(STORE_KEY); return v ? CR.fromJson(v) : null; } catch (_) { return null; } },
    save(c) { try { localStorage.setItem(STORE_KEY, CR.toJson(c)); return true; } catch (_) { return false; } },
    clear() { try { localStorage.removeItem(STORE_KEY); } catch (_) { /* nothing stored */ } },
  };

  window.OAT.register({
    id: 'case',
    name: 'Case Notes',
    summary: 'Collect indicators with verdicts, a timeline and notes during an investigation, then export a report. Kept only in this page unless you choose to save it in this browser.',

    render(root, ctx) {
      const { h, ui } = ctx;
      const saved = storage.load();
      let c = saved || CR.emptyCase();

      // ---------------------------------------------------------- Header fields

      const field = (label, key, attrs = {}) => {
        const el = h('input', { type: 'text', class: 'input', value: c[key], 'aria-label': label, ...attrs });
        el.addEventListener('input', () => { c[key] = el.value; changed(); });
        return { el, wrap: h('label', { class: 'field' }, h('span', { class: 'meta' }, label), el), key };
      };
      const fTitle = field('Case title', 'title', { placeholder: 'e.g. Phishing wave targeting finance' });
      const fTicket = field('Ticket / incident ID', 'ticket');
      const fAnalyst = field('Analyst', 'analyst');

      const keepBox = h('input', { type: 'checkbox', checked: Boolean(saved) });
      const keepNote = h('span', { class: 'meta' });

      // ---------------------------------------------------------- IOCs

      const iocIn = ui.textarea('Paste indicators or any text containing them (defanged is fine), then Add', 'Indicators to add', { rows: '3' });
      const iocTable = h('div');

      // ---------------------------------------------------------- Timeline

      const tlTime = h('input', { type: 'datetime-local', class: 'input narrow-time', 'aria-label': 'Event time', step: '1' });
      const tlText = h('input', { type: 'text', class: 'input', placeholder: 'What happened, e.g. "User clicked the link"', 'aria-label': 'Event' });
      const tlList = h('div');

      // ---------------------------------------------------------- Notes

      const notes = ui.textarea('Free notes: hypotheses, findings, next steps…', 'Notes', { rows: '6' });
      notes.value = c.notes;

      const defangBox = h('input', { type: 'checkbox', checked: true });
      const importInput = h('input', { type: 'file', accept: '.json,application/json', hidden: true });

      root.append(
        ui.panel('Case', [h('label', { class: 'check' }, keepBox, 'Keep in this browser'), keepNote],
          h('div', { class: 'grid-3' }, fTitle.wrap, fTicket.wrap, fAnalyst.wrap)),
        ui.panel('Indicators', [ui.button('Add', addIocs), ui.button('Send all to Lookup', () => ctx.sendTo('lookup', c.iocs.map((x) => x.value).join('\n')))], iocIn, iocTable),
        ui.panel('Timeline', null, h('div', { class: 'row' }, tlTime, tlText, ui.button('Add event', addEvent)), tlList),
        ui.panel('Notes', null, notes),
        ui.panel('Report', [h('label', { class: 'check' }, defangBox, 'Defang indicators')],
          h('div', { class: 'row' },
            ui.button('Download Markdown', () => ctx.download(`${slug()}.md`, CR.toMarkdown(c, { defang: defangBox.checked }), 'text/markdown;charset=utf-8')),
            ui.copyButton(() => CR.toMarkdown(c, { defang: defangBox.checked }), 'Copy Markdown'),
            ui.button('Download HTML', () => ctx.download(`${slug()}.html`, CR.toHtml(c, { defang: defangBox.checked }), 'text/html;charset=utf-8')),
            ui.button('Export JSON', () => ctx.download(`${slug()}.json`, CR.toJson(c), 'application/json')),
            ui.button('Import JSON…', () => importInput.click()),
            ui.button('New case', newCase)),
          importInput,
          h('p', { class: 'meta' }, 'Export JSON to keep a case or share it with a colleague; Import JSON to continue it later.')));

      // ---------------------------------------------------------- Behaviour

      function slug() {
        return (c.title || 'case').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 60) || 'case';
      }

      function changed() {
        if (keepBox.checked) keepNote.textContent = storage.save(c) ? 'Saved' : 'Could not save (storage blocked)';
      }

      function addIocs() {
        const n = CR.addIocsFromText(c, iocIn.value);
        if (!iocIn.value.trim()) return;
        ctx.toast(n ? `Added ${n} indicator${n === 1 ? '' : 's'}` : 'No new indicators found');
        if (n) iocIn.value = '';
        renderIocs();
        changed();
      }

      function renderIocs() {
        const labels = Object.fromEntries(I.TYPES.map((t) => [t.id, t.label]));
        if (!c.iocs.length) { iocTable.replaceChildren(h('p', { class: 'meta' }, 'No indicators yet. Paste above, or use Send to… from another module.')); return; }
        iocTable.replaceChildren(ui.table(['Type', 'Indicator', 'Verdict', 'Note', ''], c.iocs.map((x, i) => {
          const verdict = h('select', { 'aria-label': `Verdict for ${x.value}`, class: `verdict-${x.verdict}` }, CR.VERDICTS.map((v) => h('option', { value: v }, v)));
          verdict.value = x.verdict;
          verdict.addEventListener('change', () => { x.verdict = verdict.value; verdict.className = `verdict-${x.verdict}`; changed(); });
          const note = h('input', { type: 'text', class: 'input', value: x.note, 'aria-label': `Note for ${x.value}` });
          note.addEventListener('input', () => { x.note = note.value; changed(); });
          return [labels[x.type] || x.type, h('code', { class: 'ioc-value' }, x.value), verdict, note,
            h('span', { class: 'row nowrap' }, ui.button('Look up', () => ctx.sendTo('lookup', x.value)),
              ui.button('✕', () => { c.iocs.splice(i, 1); renderIocs(); changed(); }, { 'aria-label': `Remove ${x.value}` }))];
        })));
      }

      function nowLocal() {
        const d = new Date();
        d.setMinutes(d.getMinutes() - d.getTimezoneOffset());
        return d.toISOString().slice(0, 19);
      }

      function addEvent() {
        const text = tlText.value.trim();
        if (!text) { tlText.focus(); return; }
        c.timeline.push({ time: tlTime.value || nowLocal(), text });
        tlText.value = '';
        tlTime.value = nowLocal();
        renderTimeline();
        changed();
      }

      function renderTimeline() {
        const items = c.timeline.map((t, i) => ({ t, i })).sort((a, b) => (a.t.time < b.t.time ? -1 : a.t.time > b.t.time ? 1 : 0));
        tlList.replaceChildren(items.length
          ? ui.table(['Time (local)', 'Event', ''], items.map(({ t, i }) => [h('code', null, t.time.replace('T', ' ')), t.text,
            ui.button('✕', () => { c.timeline.splice(i, 1); renderTimeline(); changed(); }, { 'aria-label': 'Remove event' })]))
          : h('p', { class: 'meta' }, 'No events yet.'));
      }

      function renderAll() {
        for (const f of [fTitle, fTicket, fAnalyst]) f.el.value = c[f.key];
        notes.value = c.notes;
        renderIocs();
        renderTimeline();
      }

      function newCase() {
        if ((c.iocs.length || c.timeline.length || c.notes) && !window.confirm('Start a new case? The current one is cleared (export it first if you need it).')) return;
        c = CR.emptyCase();
        changed();
        renderAll();
      }

      keepBox.addEventListener('change', () => {
        if (keepBox.checked) changed();
        else { storage.clear(); keepNote.textContent = 'Removed from this browser'; }
      });
      notes.addEventListener('input', ui.debounce(() => { c.notes = notes.value; changed(); }, 300));
      tlText.addEventListener('keydown', (e) => { if (e.key === 'Enter') addEvent(); });
      importInput.addEventListener('change', async () => {
        const file = importInput.files[0];
        importInput.value = '';
        if (!file) return;
        try {
          c = CR.fromJson(await file.text());
          renderAll();
          changed();
          ctx.toast('Case imported');
        } catch (e) {
          ctx.toast(`Import failed: ${e.message}`);
        }
      });

      tlTime.value = nowLocal();
      if (saved) keepNote.textContent = 'Restored from this browser';
      renderAll();

      return {
        // Indicators in the text are added; if there are none, the text becomes a note.
        receive(text) {
          const n = CR.addIocsFromText(c, text);
          if (n) ctx.toast(`Added ${n} indicator${n === 1 ? '' : 's'} to the case`);
          else {
            c.notes = c.notes ? `${c.notes}\n\n${text}` : text;
            notes.value = c.notes;
            ctx.toast('Added to case notes');
          }
          renderIocs();
          changed();
        },
        focus() { fTitle.el.focus(); },
      };
    },
  });
})();
