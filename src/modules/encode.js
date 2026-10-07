/*
 * Encode / Decode module: build a recipe of byte-level steps (Base64, hex, URL,
 * HTML entities, ROT13, binary, Unicode escapes, UTF-16LE). Runs live as you type.
 * Auto-detect looks at the current output and suggests the next decode steps.
 */
(function () {
  'use strict';

  const C = window.OAT.codecs;
  const DISPLAY_LIMIT = 1024 * 1024;   // characters shown in Text view; copy/download use everything

  window.OAT.register({
    id: 'encode',
    name: 'Encode / Decode',
    summary: 'Base64, hex, URL, HTML entities, ROT13, binary, Unicode escapes and UTF-16LE. Chain steps into a recipe; auto-detect suggests what to decode next.',

    render(root, ctx) {
      const { h } = ctx;

      const state = {
        fileBytes: null,     // set when a file is loaded; overrides the text box
        fileName: null,
        steps: [],           // op ids
        view: 'text',        // 'text' | 'hex'
        output: new Uint8Array(0),
      };

      // ---------------------------------------------------------- Input

      const input = h('textarea', {
        class: 'io', spellcheck: 'false', autocomplete: 'off', 'aria-label': 'Input',
        placeholder: 'Paste or type data here, or drop a file',
      });
      const fileInput = h('input', { type: 'file', hidden: true, 'aria-hidden': 'true' });
      const fileChip = h('span', { class: 'chip', hidden: true });
      const inputMeta = h('span', { class: 'meta' });

      const inputPanel = h('div', { class: 'panel' },
        h('div', { class: 'panel-head' },
          h('h2', { class: 'panel-title' }, 'Input'),
          h('div', { class: 'row' },
            fileChip,
            inputMeta,
            h('button', { type: 'button', class: 'btn btn-small', onclick: () => fileInput.click() }, 'Open file…'),
            h('button', { type: 'button', class: 'btn btn-small', onclick: clearAll }, 'Clear'))),
        input,
        fileInput);

      // ---------------------------------------------------------- Recipe

      const stepList = h('ol', { class: 'steps', 'aria-label': 'Recipe steps' });
      const stepsEmpty = h('p', { class: 'steps-empty' }, 'No steps yet. Add one below, or pick an auto-detect suggestion.');
      const addSelect = opSelect('', 'Add step…');
      addSelect.setAttribute('aria-label', 'Add a step');
      addSelect.addEventListener('change', () => {
        if (addSelect.value) { state.steps.push(addSelect.value); addSelect.value = ''; renderSteps(); run(); }
      });

      const quick = ['b64-decode', 'hex-decode', 'url-decode', 'b64-encode'].map((id) =>
        h('button', { type: 'button', class: 'btn btn-small', onclick: () => { state.steps.push(id); renderSteps(); run(); } },
          `+ ${C.OP_BY_ID[id].label}`));

      const recipePanel = h('div', { class: 'panel' },
        h('div', { class: 'panel-head' },
          h('h2', { class: 'panel-title' }, 'Recipe'),
          h('button', { type: 'button', class: 'btn btn-small', onclick: () => { state.steps = []; renderSteps(); run(); } }, 'Clear steps')),
        stepsEmpty,
        stepList,
        h('div', { class: 'row' }, addSelect, quick));

      // ---------------------------------------------------------- Suggestions

      const suggestionList = h('div', { class: 'suggestions' });
      const suggestPanel = h('div', { class: 'panel', hidden: true },
        h('div', { class: 'panel-head' },
          h('h2', { class: 'panel-title' }, 'Auto-detect'),
          h('span', { class: 'meta' }, 'Looks like… (click to add as steps)')),
        suggestionList);

      // ---------------------------------------------------------- Output

      const output = h('pre', { class: 'output', tabindex: '0', 'aria-label': 'Output', 'aria-live': 'polite', 'data-empty': 'Output appears here' });
      const outputMeta = h('span', { class: 'meta' });
      const outputNotice = h('p', { class: 'notice', hidden: true });

      const viewText = h('button', { type: 'button', 'aria-pressed': 'true', onclick: () => setView('text') }, 'Text');
      const viewHex = h('button', { type: 'button', 'aria-pressed': 'false', onclick: () => setView('hex') }, 'Hex');

      const sendSelect = h('select', { 'aria-label': 'Send output to another module' });
      sendSelect.addEventListener('change', () => {
        if (sendSelect.value) { ctx.sendTo(sendSelect.value, C.text(state.output)); sendSelect.value = ''; }
      });

      const outputPanel = h('div', { class: 'panel' },
        h('div', { class: 'panel-head' },
          h('div', { class: 'row' },
            h('h2', { class: 'panel-title' }, 'Output'),
            h('span', { class: 'seg', role: 'group', 'aria-label': 'Output view' }, viewText, viewHex),
            outputMeta),
          h('div', { class: 'row' },
            h('button', { type: 'button', class: 'btn btn-small', onclick: copyOutput }, 'Copy'),
            h('button', { type: 'button', class: 'btn btn-small', onclick: downloadOutput }, 'Download'),
            sendSelect,
            h('button', { type: 'button', class: 'btn btn-small', title: 'Use the output as the new input and clear the recipe', onclick: outputToInput }, 'Use as input'))),
        outputNotice,
        output);

      root.append(inputPanel, recipePanel, suggestPanel, outputPanel);

      // ---------------------------------------------------------- Behaviour

      function opSelect(value, placeholder) {
        const sel = h('select', null);
        if (placeholder) sel.append(h('option', { value: '' }, placeholder));
        for (const group of ['Decode', 'Encode', 'Other']) {
          const og = h('optgroup', { label: group });
          for (const op of C.OPS.filter((o) => o.group === group)) og.append(h('option', { value: op.id }, op.label));
          sel.append(og);
        }
        sel.value = value;
        return sel;
      }

      function renderSteps(results = []) {
        stepList.replaceChildren();
        stepsEmpty.hidden = state.steps.length > 0;
        state.steps.forEach((id, i) => {
          const sel = opSelect(id);
          sel.setAttribute('aria-label', `Step ${i + 1} operation`);
          sel.addEventListener('change', () => { state.steps[i] = sel.value; run(); });
          const r = results[i];
          const status = h('span', { class: 'step-status' });
          if (r && r.ok) { status.classList.add('ok'); status.textContent = `${formatSize(r.bytes.length)}`; }
          else if (r && !r.ok) { status.classList.add('err'); status.textContent = r.error; }
          else if (results.length) { status.textContent = 'not run'; }
          stepList.append(h('li', { class: 'step' },
            sel,
            h('button', { type: 'button', class: 'btn btn-small', 'aria-label': `Move step ${i + 1} up`, disabled: i === 0, onclick: () => moveStep(i, -1) }, '↑'),
            h('button', { type: 'button', class: 'btn btn-small', 'aria-label': `Remove step ${i + 1}`, onclick: () => { state.steps.splice(i, 1); renderSteps(); run(); } }, '✕'),
            status));
        });
      }

      function moveStep(i, delta) {
        const j = i + delta;
        if (j < 0 || j >= state.steps.length) return;
        [state.steps[i], state.steps[j]] = [state.steps[j], state.steps[i]];
        renderSteps();
        run();
      }

      function inputBytes() {
        return state.fileBytes || C.utf8(input.value);
      }

      function run() {
        const src = inputBytes();
        const results = C.runRecipe(src, state.steps);
        renderSteps(results);

        const failed = results.find((r) => !r.ok);
        const lastGood = [...results].reverse().find((r) => r.ok);
        state.output = lastGood ? lastGood.bytes : src;

        if (failed) {
          const n = results.indexOf(failed) + 1;
          outputNotice.textContent = `Step ${n} failed: ${failed.error}. ${n > 1 ? `Showing the output of step ${n - 1}.` : 'Showing the input unchanged.'}`;
          outputNotice.hidden = false;
        } else {
          outputNotice.hidden = true;
        }

        renderOutput();
        renderSuggestions();
        refreshSendTargets();
      }

      function renderOutput() {
        const bytes = state.output;
        const printable = C.printableRatio(bytes);
        const kind = C.sniff(bytes);
        outputMeta.textContent = bytes.length
          ? `${formatSize(bytes.length)}${kind ? ` · ${kind}` : printable < 0.85 ? ' · looks binary' : ''}`
          : '';
        if (state.view === 'hex') {
          output.classList.add('hexview');
          const dump = C.hexdump(bytes);
          output.textContent = bytes.length > 65536 ? `${dump}\n… (hex view shows the first 64 KB)` : dump;
        } else {
          output.classList.remove('hexview');
          const t = C.text(bytes);
          output.textContent = t.length > DISPLAY_LIMIT ? `${t.slice(0, DISPLAY_LIMIT)}\n… (display truncated; Copy and Download include everything)` : t;
        }
      }

      function renderSuggestions() {
        // Only suggest for text-sized output; detection on huge binary is pointless.
        const bytes = state.output;
        const list = bytes.length && bytes.length < 5 * 1024 * 1024 ? C.detect(C.text(bytes)) : [];
        suggestionList.replaceChildren(...list.map((s) =>
          h('button', {
            type: 'button', class: 'suggestion',
            onclick: () => { state.steps.push(...s.ops); renderSteps(); run(); },
          },
          h('span', { class: 'suggestion-label' }, s.label),
          h('span', { class: 'suggestion-score' }, `${Math.round(Math.min(s.score, 1) * 100)}% confidence`),
          h('span', { class: 'suggestion-preview' }, s.preview))));
        suggestPanel.hidden = list.length === 0;
      }

      function refreshSendTargets() {
        const targets = ctx.sendTargets();
        sendSelect.replaceChildren(h('option', { value: '' }, targets.length ? 'Send to…' : 'Send to… (more modules soon)'),
          ...targets.map((t) => h('option', { value: t.id }, t.name)));
        sendSelect.disabled = targets.length === 0;
      }

      function setView(v) {
        state.view = v;
        viewText.setAttribute('aria-pressed', String(v === 'text'));
        viewHex.setAttribute('aria-pressed', String(v === 'hex'));
        renderOutput();
      }

      function copyOutput() {
        ctx.copy(state.view === 'hex' ? C.hexdump(state.output, Infinity) : C.text(state.output));
      }

      function downloadOutput() {
        const isText = C.printableRatio(state.output) >= 0.85;
        ctx.download(isText ? 'output.txt' : 'output.bin', state.output, isText ? 'text/plain;charset=utf-8' : 'application/octet-stream');
      }

      function outputToInput() {
        const bytes = state.output;
        state.steps = [];
        if (C.printableRatio(bytes) >= 0.85) setText(C.text(bytes));
        else setFile(bytes, 'previous output');
        renderSteps();
        run();
      }

      function setText(value) {
        clearFile();
        input.value = value;
      }

      function setFile(bytes, name) {
        state.fileBytes = bytes;
        state.fileName = name;
        input.value = '';
        input.disabled = true;
        input.placeholder = 'Using file input. Remove the file to type again.';
        fileChip.replaceChildren(`File: ${name} (${formatSize(bytes.length)})`,
          h('button', { type: 'button', class: 'btn btn-ghost btn-small', 'aria-label': 'Remove file', onclick: () => { clearFile(); run(); } }, '✕'));
        fileChip.hidden = false;
      }

      function clearFile() {
        state.fileBytes = null;
        state.fileName = null;
        input.disabled = false;
        input.placeholder = 'Paste or type data here, or drop a file';
        fileChip.hidden = true;
        updateInputMeta();
      }

      function clearAll() {
        clearFile();
        input.value = '';
        updateInputMeta();
        run();
        input.focus();
      }

      async function loadFile(file) {
        if (!file) return;
        if (file.size > 200 * 1024 * 1024) {
          ctx.toast('File is over 200 MB; too large for in-page decoding');
          return;
        }
        const bytes = new Uint8Array(await file.arrayBuffer());
        setFile(bytes, file.name);
        updateInputMeta();
        run();
      }

      function updateInputMeta() {
        inputMeta.textContent = state.fileBytes ? '' : input.value ? `${formatSize(C.utf8(input.value).length)}` : '';
      }

      let timer = null;
      input.addEventListener('input', () => {
        updateInputMeta();
        clearTimeout(timer);
        timer = setTimeout(run, 120);
      });

      fileInput.addEventListener('change', () => { loadFile(fileInput.files[0]); fileInput.value = ''; });

      // Drop a file anywhere on the input panel.
      inputPanel.addEventListener('dragover', (e) => { e.preventDefault(); input.classList.add('dragover'); });
      inputPanel.addEventListener('dragleave', () => input.classList.remove('dragover'));
      inputPanel.addEventListener('drop', (e) => {
        e.preventDefault();
        input.classList.remove('dragover');
        const file = e.dataTransfer && e.dataTransfer.files[0];
        if (file) loadFile(file);
      });

      renderSteps();
      run();

      return {
        receive(value) { state.steps = []; setText(value); updateInputMeta(); renderSteps(); run(); },
        focus() { if (!input.disabled) input.focus(); },
      };
    },
  });

  function formatSize(n) {
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / 1024 / 1024).toFixed(1)} MB`;
  }
})();
