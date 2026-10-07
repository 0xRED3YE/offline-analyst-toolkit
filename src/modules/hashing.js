/*
 * Hashing module: MD5 / SHA-1 / SHA-256 / SHA-384 / SHA-512 of text or files.
 * Files are read in 4 MB chunks inside a Web Worker (built from an inline blob,
 * so it also works when the page is opened from file://). If a worker cannot
 * start, hashing falls back to the main thread with the same chunking.
 */
(function () {
  'use strict';

  const H = window.OAT.hashes;
  const C = window.OAT.codecs;
  const ALGS = ['md5', 'sha1', 'sha256', 'sha384', 'sha512'];
  const DEFAULT_ON = new Set(['md5', 'sha1', 'sha256', 'sha512']);
  const CHUNK = 4 * 1024 * 1024;

  const WORKER_SOURCE = `'use strict';
const H = ${H.factorySource}();
self.onmessage = async (e) => {
  const { file, algs, chunk } = e.data;
  try {
    const hashers = algs.map((a) => H.createHash(a));
    for (let off = 0; off < file.size; off += chunk) {
      const buf = new Uint8Array(await file.slice(off, off + chunk).arrayBuffer());
      for (const h of hashers) h.update(buf);
      self.postMessage({ type: 'progress', done: Math.min(off + chunk, file.size) });
    }
    self.postMessage({ type: 'done', results: hashers.map((h) => [h.algorithm, H.toHex(h.digest())]) });
  } catch (err) {
    self.postMessage({ type: 'error', message: String(err && err.message || err) });
  }
};`;

  let workerUrl = null;
  function getWorkerUrl() {
    if (!workerUrl) workerUrl = URL.createObjectURL(new Blob([WORKER_SOURCE], { type: 'text/javascript' }));
    return workerUrl;
  }

  // Hash a File. Returns { promise, cancel }. promise resolves to { results: [[alg, hex]], mode }.
  function hashFile(file, algs, onProgress) {
    let cancelled = false;
    let worker = null;

    const mainThread = async () => {
      const hashers = algs.map((a) => H.createHash(a));
      for (let off = 0; off < file.size; off += CHUNK) {
        if (cancelled) throw new Error('Cancelled');
        const buf = new Uint8Array(await file.slice(off, off + CHUNK).arrayBuffer());
        for (const h of hashers) h.update(buf);
        onProgress(Math.min(off + CHUNK, file.size));
        await new Promise((r) => setTimeout(r, 0));   // keep the page responsive
      }
      return { results: hashers.map((h) => [h.algorithm, H.toHex(h.digest())]), mode: 'main thread' };
    };

    let rejectPromise = null;
    const promise = new Promise((resolve, reject) => {
      rejectPromise = reject;
      let started = false;
      const fallback = () => { if (worker) worker.terminate(); worker = null; mainThread().then(resolve, reject); };
      try {
        worker = new Worker(getWorkerUrl());
      } catch (_) {
        fallback();
        return;
      }
      worker.onmessage = (e) => {
        const m = e.data;
        if (m.type === 'progress') { started = true; onProgress(m.done); }
        else if (m.type === 'done') { worker.terminate(); resolve({ results: m.results, mode: 'Web Worker' }); }
        else if (m.type === 'error') { worker.terminate(); reject(new Error(m.message)); }
      };
      worker.onerror = (e) => {
        e.preventDefault();
        if (!started && !cancelled) fallback();
        else { worker.terminate(); reject(new Error(e.message || 'Worker error')); }
      };
      worker.postMessage({ file, algs, chunk: CHUNK });
    });

    return {
      promise,
      cancel() {
        cancelled = true;
        if (worker) { worker.terminate(); rejectPromise(new Error('Cancelled')); }
        // On the main-thread path the loop sees `cancelled` and rejects itself.
      },
    };
  }

  window.OAT.register({
    id: 'hash',
    name: 'Hashing',
    summary: 'MD5, SHA-1, SHA-256, SHA-384 and SHA-512 of text or files of any size. Files are read in chunks on your machine and never uploaded.',

    render(root, ctx) {
      const { h, ui } = ctx;
      const state = { textResults: [], files: [], upper: false };

      // ---------------------------------------------------------- Options

      const algBoxes = Object.fromEntries(ALGS.map((a) => [a, h('input', { type: 'checkbox', checked: DEFAULT_ON.has(a) })]));
      const upperBox = h('input', { type: 'checkbox' });
      const options = h('div', { class: 'row options' },
        ALGS.map((a) => h('label', { class: 'check' }, algBoxes[a], H.NAMES[a])),
        h('span', { class: 'sep' }),
        h('label', { class: 'check' }, upperBox, 'Uppercase'));
      const selectedAlgs = () => ALGS.filter((a) => algBoxes[a].checked);

      // ---------------------------------------------------------- Compare

      const compareInput = h('input', { type: 'text', class: 'input mono', placeholder: 'Paste a known hash to compare (any of the above)', 'aria-label': 'Hash to compare', spellcheck: 'false' });
      const compareStatus = h('span', { class: 'meta' });

      // ---------------------------------------------------------- Text

      const textInput = ui.textarea('Type or paste text to hash (hashed as UTF-8)', 'Text to hash', { rows: '4' });
      const textResults = h('div');
      const textMeta = h('span', { class: 'meta' });

      // ---------------------------------------------------------- Files

      const fileInput = h('input', { type: 'file', multiple: true, hidden: true });
      const dropZone = h('div', { class: 'dropzone', tabindex: '0', role: 'button', 'aria-label': 'Choose files to hash' },
        h('strong', null, 'Drop files here'), ' or click to choose. Any size; read in chunks, nothing is uploaded.');
      const fileList = h('div', { class: 'file-jobs' });

      root.append(
        ui.panel('Algorithms', null, options),
        ui.panel('Text', textMeta, textInput, textResults),
        ui.panel('Files', ui.button('Clear finished', clearFinished), dropZone, fileInput, fileList),
        ui.panel('Compare', compareStatus, compareInput));

      // ---------------------------------------------------------- Rendering

      const fmt = (hex) => (state.upper ? hex.toUpperCase() : hex);

      function resultTable(results, label) {
        return ui.table(['Algorithm', 'Hash', ''], results.map(([alg, hex]) => [
          H.NAMES[alg],
          h('code', { class: 'hash', dataset: { hash: hex } }, fmt(hex)),
          ui.copyButton(() => fmt(hex)),
        ]), { 'aria-label': label });
      }

      function allHashesText() {
        const lines = state.textResults.map(([alg, hex]) => `${H.NAMES[alg]}  ${fmt(hex)}  (text)`);
        for (const job of state.files) {
          if (job.results) for (const [alg, hex] of job.results) lines.push(`${H.NAMES[alg]}  ${fmt(hex)}  ${job.file.name}`);
        }
        return lines.join('\n');
      }

      function hashValuesOnly() {
        const set = new Set(state.textResults.map(([, hex]) => hex));
        for (const job of state.files) if (job.results) job.results.forEach(([, hex]) => set.add(hex));
        return [...set].join('\n');
      }

      function runText() {
        const value = textInput.value;
        if (!value) { state.textResults = []; textResults.replaceChildren(); textMeta.textContent = ''; compare(); return; }
        const bytes = C.utf8(value);
        state.textResults = selectedAlgs().map((a) => [a, H.toHex(H.hash(a, bytes))]);
        textMeta.textContent = `${bytes.length} bytes`;
        textResults.replaceChildren(resultTable(state.textResults, 'Text hashes'),
          h('div', { class: 'row actions' }, ui.copyButton(allHashesText, 'Copy all'), ui.sendSelect(hashValuesOnly)));
        compare();
      }

      function addFiles(files) {
        const algs = selectedAlgs();
        if (!algs.length) { ctx.toast('Pick at least one algorithm'); return; }
        for (const file of files) {
          const job = { file, algs, results: null, error: null, done: false, el: h('div', { class: 'file-job' }) };
          state.files.push(job);
          fileList.append(job.el);
        }
        pump();
      }

      // One file at a time keeps memory and CPU use predictable.
      let busy = false;
      async function pump() {
        if (busy) return;
        const job = state.files.find((j) => !j.done && !j.running);
        if (!job) return;
        busy = true;
        job.running = true;
        const started = performance.now();
        const bar = h('progress', { max: String(job.file.size || 1), value: '0' });
        const pct = h('span', { class: 'meta' }, '0%');
        const task = hashFile(job.file, job.algs, (done) => {
          bar.value = done;
          pct.textContent = `${Math.floor((done / (job.file.size || 1)) * 100)}%`;
        });
        job.cancel = task.cancel;
        renderJob(job, h('div', { class: 'row' }, bar, pct, ui.button('Cancel', () => task.cancel())));
        try {
          const { results, mode } = await task.promise;
          job.results = results;
          job.mode = mode;
          job.seconds = (performance.now() - started) / 1000;
        } catch (e) {
          job.error = e.message;
        }
        job.done = true;
        job.running = false;
        renderJob(job);
        compare();
        busy = false;
        pump();
      }

      function renderJob(job, progress) {
        const head = h('div', { class: 'file-job-head' },
          h('strong', null, job.file.name),
          h('span', { class: 'meta' }, formatSize(job.file.size)),
          job.done && job.results ? h('span', { class: 'meta' }, `${job.seconds.toFixed(1)} s · ${job.mode}`) : null);
        const body = [];
        if (progress) body.push(progress);
        if (job.error) body.push(h('p', { class: 'error' }, job.error === 'Cancelled' ? 'Cancelled.' : `Failed: ${job.error}`));
        if (job.results) {
          body.push(resultTable(job.results, `Hashes of ${job.file.name}`));
          body.push(h('div', { class: 'row actions' }, ui.copyButton(allHashesText, 'Copy all'), ui.sendSelect(hashValuesOnly)));
        }
        if (!job.done && !progress) body.push(h('p', { class: 'meta' }, 'Waiting…'));
        job.el.replaceChildren(head, ...body);
      }

      function clearFinished() {
        state.files = state.files.filter((j) => {
          if (j.done) j.el.remove();
          return !j.done;
        });
      }

      // Highlight any hash equal to the one pasted in Compare.
      function compare() {
        const want = compareInput.value.trim().toLowerCase().replace(/^0x/, '');
        let hits = 0;
        for (const code of root.querySelectorAll('code.hash')) {
          const match = want && code.dataset.hash === want;
          code.classList.toggle('match', Boolean(match));
          if (match) hits++;
        }
        if (!want) compareStatus.textContent = '';
        else if (!/^[0-9a-f]+$/.test(want)) compareStatus.textContent = 'Not a hex hash';
        else compareStatus.textContent = hits ? `✓ Match (${hits})` : '✗ No match';
        compareStatus.className = want ? (hits ? 'meta ok' : 'meta err') : 'meta';
      }

      function rerenderAll() {
        state.upper = upperBox.checked;
        runText();
        state.files.filter((j) => j.done).forEach((j) => renderJob(j));
        compare();
      }

      // ---------------------------------------------------------- Events

      textInput.addEventListener('input', ui.debounce(runText, 120));
      for (const box of Object.values(algBoxes)) box.addEventListener('change', runText);
      upperBox.addEventListener('change', rerenderAll);
      compareInput.addEventListener('input', compare);
      dropZone.addEventListener('click', () => fileInput.click());
      dropZone.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileInput.click(); } });
      fileInput.addEventListener('change', () => { addFiles([...fileInput.files]); fileInput.value = ''; });
      ui.onFileDrop(dropZone, addFiles);

      return {
        receive(text) { textInput.value = text; runText(); },
        focus() { textInput.focus(); },
      };
    },
  });

  function formatSize(n) {
    if (n < 1024) return `${n} B`;
    if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
    if (n < 1073741824) return `${(n / 1048576).toFixed(1)} MB`;
    return `${(n / 1073741824).toFixed(2)} GB`;
  }
})();
