/*
 * JWT Decoder module: header, payload, readable time claims, risk flags, and an
 * optional local HMAC signature check. The token never leaves the page.
 */
(function () {
  'use strict';

  const J = window.OAT.jwt;
  const T = window.OAT.time;
  const H = window.OAT.hashes;

  window.OAT.register({
    id: 'jwt',
    name: 'JWT Decoder',
    summary: 'Decode a JSON Web Token: header, payload, readable dates, and flags such as alg "none", expiry and remote keys. Optional HMAC check with your secret.',

    render(root, ctx) {
      const { h, ui } = ctx;
      let decoded = null;

      const input = ui.textarea('Paste a JWT (eyJ…), with or without "Bearer "', 'Token', { rows: '4' });
      const errorBox = h('p', { class: 'notice', hidden: true });
      const findingsBox = h('div');
      const headerOut = h('pre', { class: 'output json', tabindex: '0', 'aria-label': 'Header' });
      const payloadOut = h('pre', { class: 'output json', tabindex: '0', 'aria-label': 'Payload' });
      const timesBox = h('div');
      const sigMeta = h('p', { class: 'meta' });

      const secretInput = h('input', { type: 'password', class: 'input mono', autocomplete: 'off', spellcheck: 'false', placeholder: 'Shared secret', 'aria-label': 'Secret' });
      const showSecret = h('input', { type: 'checkbox' });
      const b64Secret = h('input', { type: 'checkbox' });
      const verifyResult = h('span', { class: 'meta' });

      const resultsWrap = h('div', { hidden: true },
        ui.panel('Findings', null, findingsBox),
        h('div', { class: 'grid-2' },
          ui.panel('Header', ui.copyButton(() => headerOut.textContent), headerOut),
          ui.panel('Payload', [ui.copyButton(() => payloadOut.textContent), ui.sendSelect(() => payloadOut.textContent)], payloadOut)),
        ui.panel('Time claims', null, timesBox),
        ui.panel('Signature', null, sigMeta,
          h('div', { class: 'row' }, secretInput,
            h('label', { class: 'check' }, showSecret, 'Show'),
            h('label', { class: 'check' }, b64Secret, 'Secret is Base64'),
            ui.button('Verify', verify), verifyResult),
          h('p', { class: 'meta' }, 'HS256/384/512 only. The check runs in this page; the secret is never stored.')));

      root.append(ui.panel('Token', ui.button('Clear', () => { input.value = ''; run(); }), input, errorBox), resultsWrap);

      function run() {
        verifyResult.textContent = '';
        verifyResult.className = 'meta';
        const value = input.value.trim();
        decoded = null;
        if (!value) { errorBox.hidden = true; resultsWrap.hidden = true; return; }
        try {
          decoded = J.decode(value);
        } catch (e) {
          errorBox.textContent = e.message;
          errorBox.hidden = false;
          resultsWrap.hidden = true;
          return;
        }
        errorBox.hidden = true;
        resultsWrap.hidden = false;

        findingsBox.replaceChildren(ui.findings(decoded.findings));
        headerOut.textContent = JSON.stringify(decoded.header, null, 2);
        payloadOut.textContent = decoded.payload ? JSON.stringify(decoded.payload, null, 2) : '(encrypted)';

        timesBox.replaceChildren(decoded.times.length
          ? ui.table(['Claim', 'Value', 'UTC', 'Relative'], decoded.times.map((t) => {
            const ticks = BigInt(Math.round(t.seconds * 1000)) * 10000n;
            return [t.claim, String(t.seconds), T.toIso(ticks), T.relative(ticks)];
          }))
          : h('p', { class: 'meta' }, 'No time claims.'));

        const alg = decoded.header.alg || '?';
        sigMeta.textContent = decoded.signature.length
          ? `alg ${alg} · ${decoded.signature.length}-byte signature · ${H.toHex(decoded.signature).slice(0, 32)}${decoded.signature.length > 16 ? '…' : ''}`
          : `alg ${alg} · no signature`;
      }

      function verify() {
        if (!decoded) return;
        try {
          const ok = J.verifyHmac(input.value, secretInput.value, { secretIsBase64: b64Secret.checked });
          verifyResult.textContent = ok ? '✓ Signature valid with this secret' : '✗ Signature does not match this secret';
          verifyResult.className = ok ? 'meta ok' : 'meta err';
        } catch (e) {
          verifyResult.textContent = e.message;
          verifyResult.className = 'meta err';
        }
      }

      input.addEventListener('input', ui.debounce(run, 120));
      showSecret.addEventListener('change', () => { secretInput.type = showSecret.checked ? 'text' : 'password'; });
      secretInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') verify(); });

      return {
        receive(text) { input.value = text; run(); },
        focus() { input.focus(); },
      };
    },
  });
})();
