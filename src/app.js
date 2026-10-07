/*
 * app.js: the shell. Modules call OAT.register({ id, name, summary, render }) and
 * the shell builds navigation, mounts modules lazily, and gives each one a small
 * context: DOM helper, copy, download, toast and Send to….
 *
 * Rule for every module: untrusted data is written with textContent (h() does
 * this for strings), never innerHTML.
 */
(function () {
  'use strict';

  const OAT = (window.OAT = window.OAT || {});
  const modules = [];
  const mounted = new Map();   // id -> { section, api }
  let activeId = null;

  OAT.register = function (mod) {
    if (!mod || !mod.id || typeof mod.render !== 'function') throw new Error('Invalid module definition');
    modules.push(mod);
  };

  // ------------------------------------------------------------- DOM helper

  // h('div', { class: 'x', onclick: fn }, 'text', childNode, [more])
  // Strings become text nodes. Event handlers must be functions: string "on*"
  // attributes are refused so untrusted text can never become inline script.
  function h(tag, attrs, ...children) {
    const el = document.createElement(tag);
    if (attrs) {
      for (const [k, v] of Object.entries(attrs)) {
        if (v == null || v === false) continue;
        if (k.startsWith('on')) {
          if (typeof v === 'function') el.addEventListener(k.slice(2), v);
          continue;
        }
        if (k === 'class') el.className = v;
        else if (k === 'dataset') Object.assign(el.dataset, v);
        else if (k === 'value') el.value = v;
        else if (v === true) el.setAttribute(k, '');
        else el.setAttribute(k, String(v));
      }
    }
    for (const c of children.flat(Infinity)) {
      if (c == null || c === false) continue;
      el.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return el;
  }

  // ------------------------------------------------------------- Services for modules

  let toastTimer = null;
  function toast(message) {
    const el = document.getElementById('toast');
    el.textContent = message;
    el.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.remove('show'), 2200);
  }

  async function copy(textValue) {
    try {
      await navigator.clipboard.writeText(textValue);
      toast('Copied');
      return;
    } catch (_) { /* fall back below: clipboard API can be unavailable on file:// */ }
    const ta = h('textarea', { class: 'offscreen', readonly: true, 'aria-hidden': 'true' });
    ta.value = textValue;
    document.body.append(ta);
    ta.select();
    let ok = false;
    try { ok = document.execCommand('copy'); } catch (_) { ok = false; }
    ta.remove();
    toast(ok ? 'Copied' : 'Copy failed: select the output and press Ctrl+C');
  }

  function download(filename, data, type = 'application/octet-stream') {
    const blob = data instanceof Blob ? data : new Blob([data], { type });
    const url = URL.createObjectURL(blob);
    const a = h('a', { href: url, download: filename });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  }

  // Modules that can receive data from another module's output.
  function sendTargets(fromId) {
    return modules.filter((m) => m.id !== fromId && m.acceptsInput !== false).map((m) => ({ id: m.id, name: m.name }));
  }

  function sendTo(targetId, textValue) {
    show(targetId);
    const entry = mounted.get(targetId);
    if (entry && entry.api && typeof entry.api.receive === 'function') {
      entry.api.receive(textValue);
      toast(`Sent to ${modules.find((m) => m.id === targetId).name}`);
    }
  }

  // ------------------------------------------------------------- Shared UI pieces

  function makeUi(mod) {
    return {
      // <div class="panel"> with a title row; extras go on the right of the title.
      panel(title, extras, ...children) {
        return h('div', { class: 'panel' },
          h('div', { class: 'panel-head' }, h('h2', { class: 'panel-title' }, title), extras ? h('div', { class: 'row' }, extras) : null),
          ...children);
      },

      button(label, onclick, attrs = {}) {
        return h('button', { type: 'button', class: 'btn btn-small', ...attrs, onclick }, label);
      },

      copyButton(getText, label = 'Copy') {
        return h('button', { type: 'button', class: 'btn btn-small', onclick: () => copy(getText()) }, label);
      },

      // "Send to…" dropdown that pipes getText() into another module.
      sendSelect(getText) {
        const targets = sendTargets(mod.id);
        const sel = h('select', { 'aria-label': 'Send to another module' },
          h('option', { value: '' }, 'Send to…'),
          targets.map((t) => h('option', { value: t.id }, t.name)));
        sel.addEventListener('change', () => {
          const id = sel.value;
          sel.value = '';
          if (!id) return;
          const text = getText();
          if (!text) { toast('Nothing to send yet'); return; }
          sendTo(id, text);
        });
        return sel;
      },

      textarea(placeholder, label, attrs = {}) {
        return h('textarea', { class: 'io', spellcheck: 'false', autocomplete: 'off', placeholder, 'aria-label': label, ...attrs });
      },

      // Findings as a list with severity badges: [{ level, text }].
      findings(list) {
        if (!list.length) return h('p', { class: 'meta' }, 'Nothing notable found.');
        return h('ul', { class: 'findings' }, list.map((f) =>
          h('li', null, h('span', { class: `badge badge-${f.level}` }, f.level), h('span', null, f.text))));
      },

      // Simple data table. cells may be strings or nodes.
      table(columns, rows, attrs = {}) {
        return h('div', { class: 'table-wrap' },
          h('table', { class: 'data', ...attrs },
            h('thead', null, h('tr', null, columns.map((c) => h('th', { scope: 'col' }, c)))),
            h('tbody', null, rows.map((r) => h('tr', null, r.map((c) => h('td', null, c)))))));
      },

      // Read a dropped or chosen file as text, with a size guard.
      async readTextFile(file, maxBytes = 20 * 1024 * 1024) {
        if (file.size > maxBytes) { toast(`File is over ${Math.round(maxBytes / 1048576)} MB`); return null; }
        return file.text();
      },

      // Wire drag-and-drop of a file onto an element.
      onFileDrop(el, handler) {
        el.addEventListener('dragover', (e) => { e.preventDefault(); el.classList.add('dragover'); });
        el.addEventListener('dragleave', () => el.classList.remove('dragover'));
        el.addEventListener('drop', (e) => {
          e.preventDefault();
          el.classList.remove('dragover');
          const files = e.dataTransfer ? [...e.dataTransfer.files] : [];
          if (files.length) handler(files);
        });
      },

      debounce(fn, ms = 150) {
        let t = null;
        return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
      },
    };
  }

  function contextFor(mod) {
    return { h, toast, copy, download, sendTo, sendTargets: () => sendTargets(mod.id), ui: makeUi(mod) };
  }

  // ------------------------------------------------------------- Navigation

  function mount(mod) {
    let entry = mounted.get(mod.id);
    if (entry) return entry;
    const section = h('section', { class: 'module', id: `mod-${mod.id}`, 'aria-labelledby': `mod-${mod.id}-title` },
      h('header', { class: 'module-head' },
        h('h1', { id: `mod-${mod.id}-title` }, mod.name),
        mod.summary ? h('p', { class: 'module-summary' }, mod.summary) : null));
    const body = h('div', { class: 'module-body' });
    section.append(body);
    document.getElementById('main').append(section);
    let api = null;
    try {
      api = mod.render(body, contextFor(mod)) || null;
    } catch (e) {
      body.append(h('p', { class: 'error' }, `This module failed to load: ${e.message}`));
      console.error(e);
    }
    entry = { section, api };
    mounted.set(mod.id, entry);
    return entry;
  }

  function show(id) {
    const mod = modules.find((m) => m.id === id) || modules[0];
    if (!mod) return;
    const entry = mount(mod);
    for (const [mid, e] of mounted) e.section.hidden = mid !== mod.id;
    activeId = mod.id;
    for (const btn of document.querySelectorAll('#module-list button')) {
      btn.setAttribute('aria-current', btn.dataset.id === mod.id ? 'page' : 'false');
    }
    document.getElementById('module-select').value = mod.id;
    document.title = `${mod.name} · Offline Analyst Toolkit`;
    if (location.hash !== `#${mod.id}`) history.replaceState(null, '', `#${mod.id}`);
    if (entry.api && typeof entry.api.focus === 'function') entry.api.focus();
  }

  // Sidebar groups, in display order. Modules not listed go into a final "More" group.
  const NAV_GROUPS = [
    ['Decode & convert', ['encode', 'hash', 'time', 'jwt', 'ps']],
    ['Indicators', ['ioc', 'defang', 'url', 'lookup', 'email']],
    ['Analysis', ['diff', 'regex', 'entropy']],
    ['Case', ['case']],
  ];

  function groupOf(id) {
    const g = NAV_GROUPS.findIndex(([, ids]) => ids.includes(id));
    return g < 0 ? NAV_GROUPS.length : g;
  }

  function buildNav() {
    // Order modules by group, then by their position in the group.
    modules.sort((a, b) => groupOf(a.id) - groupOf(b.id) ||
      (NAV_GROUPS[groupOf(a.id)] ? NAV_GROUPS[groupOf(a.id)][1].indexOf(a.id) - NAV_GROUPS[groupOf(b.id)][1].indexOf(b.id) : 0));
    const list = document.getElementById('module-list');
    const select = document.getElementById('module-select');
    let currentGroup = -1;
    let optgroup = null;
    modules.forEach((m, i) => {
      const g = groupOf(m.id);
      if (g !== currentGroup) {
        currentGroup = g;
        const label = NAV_GROUPS[g] ? NAV_GROUPS[g][0] : 'More';
        list.append(h('li', { class: 'module-group', role: 'presentation' }, label));
        optgroup = h('optgroup', { label });
        select.append(optgroup);
      }
      list.append(h('li', null,
        h('button', { type: 'button', class: 'module-link', dataset: { id: m.id }, onclick: () => show(m.id) },
          h('span', { class: 'module-key', 'aria-hidden': 'true' }, i < 9 ? String(i + 1) : ''),
          m.name)));
      optgroup.append(h('option', { value: m.id }, m.name));
    });
    select.addEventListener('change', () => show(select.value));
  }

  // ------------------------------------------------------------- Theme

  function initTheme() {
    const btn = document.getElementById('theme-toggle');
    const media = window.matchMedia('(prefers-color-scheme: dark)');
    const current = () => document.documentElement.dataset.theme || (media.matches ? 'dark' : 'light');
    const label = () => { btn.textContent = current() === 'dark' ? 'Light mode' : 'Dark mode'; };
    btn.addEventListener('click', () => {
      document.documentElement.dataset.theme = current() === 'dark' ? 'light' : 'dark';
      label();
    });
    media.addEventListener('change', label);
    label();
  }

  // ------------------------------------------------------------- Keyboard

  function initKeys() {
    document.addEventListener('keydown', (e) => {
      if (e.altKey && !e.ctrlKey && !e.metaKey && /^Digit[1-9]$/.test(e.code)) {
        const mod = modules[Number(e.code.slice(5)) - 1];
        if (mod) { e.preventDefault(); show(mod.id); }
      }
    });
  }

  // Inline module scripts have all run by the time DOMContentLoaded fires.
  document.addEventListener('DOMContentLoaded', () => {
    buildNav();
    initTheme();
    initKeys();
    show(location.hash.slice(1));
    window.addEventListener('hashchange', () => {
      const id = location.hash.slice(1);
      if (id && id !== activeId) show(id);
    });
  });

  OAT.h = h;
})();
