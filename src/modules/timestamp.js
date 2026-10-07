/*
 * Timestamp Converter module: recognise Unix (s/ms/µs/ns), Windows FILETIME /
 * LDAP, Chrome/WebKit, Apple Cocoa and date strings; show UTC and a chosen time
 * zone side by side (Africa/Kigali by default), and convert to every format.
 */
(function () {
  'use strict';

  const T = window.OAT.time;
  const DEFAULT_ZONE = 'Africa/Kigali';
  const FALLBACK_ZONES = ['UTC', 'Africa/Kigali', 'Africa/Nairobi', 'Africa/Johannesburg', 'Africa/Lagos', 'Europe/London',
    'Europe/Paris', 'Europe/Berlin', 'America/New_York', 'America/Chicago', 'America/Los_Angeles', 'Asia/Dubai',
    'Asia/Kolkata', 'Asia/Singapore', 'Asia/Tokyo', 'Australia/Sydney'];

  window.OAT.register({
    id: 'time',
    name: 'Timestamp Converter',
    summary: 'Unix seconds/ms/µs, Windows FILETIME and LDAP/AD time, Chrome/WebKit, Apple Cocoa, ISO 8601 and email dates. UTC and your time zone side by side.',

    render(root, ctx) {
      const { h, ui } = ctx;
      let readings = [];
      let selected = 0;

      const input = h('input', { type: 'text', class: 'input mono big', spellcheck: 'false', autocomplete: 'off',
        placeholder: 'e.g. 1700000000, 133444736000000000, 0x01DA1747C66D0000, 2026-10-07 14:00:00', 'aria-label': 'Timestamp' });

      const zones = typeof Intl.supportedValuesOf === 'function' ? Intl.supportedValuesOf('timeZone') : FALLBACK_ZONES;
      const zoneSelect = h('select', { 'aria-label': 'Time zone' },
        h('option', { value: Intl.DateTimeFormat().resolvedOptions().timeZone }, `Browser (${Intl.DateTimeFormat().resolvedOptions().timeZone})`),
        zones.map((z) => h('option', { value: z }, z)));
      zoneSelect.value = DEFAULT_ZONE;
      if (zoneSelect.value !== DEFAULT_ZONE) zoneSelect.selectedIndex = 0;

      const readingsBox = h('div', { class: 'readings' });
      const convBox = h('div');

      root.append(
        ui.panel('Input', [h('label', { class: 'row' }, 'Time zone', zoneSelect), ui.button('Now', () => { input.value = String(Math.floor(Date.now() / 1000)); run(); })],
          input),
        ui.panel('Readings', null, readingsBox),
        ui.panel('Convert to', null, convBox));

      function run() {
        readings = input.value.trim() ? T.interpret(input.value) : [];
        selected = 0;
        render();
      }

      function render() {
        const zone = zoneSelect.value;
        if (!input.value.trim()) {
          readingsBox.replaceChildren(h('p', { class: 'meta' }, 'Enter a timestamp, or press Now.'));
          convBox.replaceChildren();
          return;
        }
        if (!readings.length) {
          readingsBox.replaceChildren(h('p', { class: 'notice' }, 'Not a recognised timestamp, or outside 1970–2100.'));
          convBox.replaceChildren();
          return;
        }
        const card = (r, i) => h('button', {
          type: 'button', class: 'reading', 'aria-pressed': String(i === selected),
          onclick: () => { selected = i; render(); },
        },
        h('span', { class: 'reading-label' }, r.label),
        h('span', { class: 'reading-utc mono' }, T.toIso(r.ticks)),
        h('span', { class: 'reading-zone' }, `${T.inZone(r.ticks, zone)} · ${T.relative(r.ticks)}`));

        const likely = readings.map((r, i) => [r, i]).filter(([r]) => r.likely);
        const other = readings.map((r, i) => [r, i]).filter(([r]) => !r.likely);
        readingsBox.replaceChildren(
          ...likely.map(([r, i]) => card(r, i)),
          other.length ? h('details', { class: 'other-readings', open: likely.length === 0 || other.some(([, i]) => i === selected) },
            h('summary', null, `${other.length} less likely reading${other.length === 1 ? '' : 's'}`),
            ...other.map(([r, i]) => card(r, i))) : null);

        const ticks = readings[selected].ticks;
        convBox.replaceChildren(ui.table(['Format', 'Value', ''], [
          ...T.conversions(ticks).map((c) => [c.label, h('code', null, c.value), ui.copyButton(() => c.value)]),
          [`Time zone (${zone})`, h('code', null, T.inZone(ticks, zone)), ui.copyButton(() => T.inZone(ticks, zone))],
        ]));
      }

      input.addEventListener('input', ui.debounce(run, 100));
      zoneSelect.addEventListener('change', render);
      render();

      return {
        receive(text) { input.value = text.trim().split(/\s*\n/)[0]; run(); },
        focus() { input.focus(); },
      };
    },
  });
})();
