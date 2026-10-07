/*
 * casereport.js: the Case Notes data model and its exports (Markdown, HTML, JSON).
 * Exports escape everything: notes and IOCs often contain attacker-controlled text.
 */
(function (root, factory) {
  const lib = factory();
  if (typeof module === 'object' && module.exports) module.exports = lib;
  else (root.OAT = root.OAT || {}).casereport = lib;
})(globalThis, function () {
  'use strict';

  const ioc = () => globalThis.OAT.ioc;
  const VERDICTS = ['unknown', 'malicious', 'suspicious', 'benign'];
  const VERSION = 1;

  function emptyCase(now = new Date()) {
    return { version: VERSION, title: '', analyst: '', ticket: '', created: now.toISOString(), notes: '', iocs: [], timeline: [] };
  }

  // Add indicators found in text; returns how many were new.
  function addIocsFromText(c, text, now = new Date()) {
    let added = 0;
    for (const it of ioc().extract(text, { fileLike: false })) {
      if (c.iocs.some((x) => x.type === it.type && x.value === it.value)) continue;
      c.iocs.push({ type: it.type, value: it.value, verdict: 'unknown', note: it.note || '', added: now.toISOString() });
      added++;
    }
    return added;
  }

  // Accepts only the fields we know, with the right types (imported files are untrusted).
  function fromJson(json) {
    const d = typeof json === 'string' ? JSON.parse(json) : json;
    if (!d || typeof d !== 'object') throw new Error('Not a case file');
    const str = (v, max = 100000) => (typeof v === 'string' ? v.slice(0, max) : '');
    const c = emptyCase();
    c.title = str(d.title, 300);
    c.analyst = str(d.analyst, 200);
    c.ticket = str(d.ticket, 200);
    c.created = str(d.created, 40) || c.created;
    c.notes = str(d.notes);
    c.iocs = (Array.isArray(d.iocs) ? d.iocs : []).slice(0, 5000).map((x) => ({
      type: str(x && x.type, 20) || 'unknown',
      value: str(x && x.value, 2000),
      verdict: VERDICTS.includes(x && x.verdict) ? x.verdict : 'unknown',
      note: str(x && x.note, 2000),
      added: str(x && x.added, 40),
    })).filter((x) => x.value);
    c.timeline = (Array.isArray(d.timeline) ? d.timeline : []).slice(0, 5000).map((x) => ({
      time: str(x && x.time, 40),
      text: str(x && x.text, 10000),
    })).filter((x) => x.text);
    return c;
  }

  const sortedTimeline = (c) => [...c.timeline].sort((a, b) => (a.time < b.time ? -1 : a.time > b.time ? 1 : 0));
  const show = (v, defang) => (defang ? ioc().defang(v, { fileLike: true }).text : v);
  // Some Markdown viewers render raw HTML, so < and > are escaped everywhere.
  const mdText = (s) => String(s).replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const mdCell = (s) => mdText(s).replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
  const mdCode = (s) => { const t = String(s); const fence = t.includes('`') ? '``' : '`'; return `${fence}${t}${fence}`; };

  function toMarkdown(c, { defang = true } = {}) {
    const out = [];
    out.push(`# ${mdCell(c.title || 'Untitled case')}`, '');
    const meta = [['Ticket', c.ticket], ['Analyst', c.analyst], ['Created', c.created]].filter(([, v]) => v);
    for (const [kname, v] of meta) out.push(`- **${kname}:** ${mdCell(v)}`);
    if (meta.length) out.push('');
    if (c.notes.trim()) out.push('## Notes', '', mdText(c.notes.trim()), '');
    if (c.iocs.length) {
      out.push(`## Indicators (${c.iocs.length})`, '', '| Type | Indicator | Verdict | Note |', '|---|---|---|---|');
      for (const x of c.iocs) out.push(`| ${mdCell(x.type)} | ${mdCode(mdCell(show(x.value, defang)))} | ${x.verdict} | ${mdCell(x.note)} |`);
      out.push('');
    }
    if (c.timeline.length) {
      out.push('## Timeline', '', '| Time | Event |', '|---|---|');
      for (const t of sortedTimeline(c)) out.push(`| ${mdCell(t.time)} | ${mdCell(t.text)} |`);
      out.push('');
    }
    out.push(`_Generated with Offline Analyst Toolkit${defang ? '. Indicators are defanged' : ''}._`);
    return out.join('\n') + '\n';
  }

  const esc = (s) => String(s).replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));

  function toHtml(c, { defang = true } = {}) {
    const rows = (list, cells) => list.map((x) => `<tr>${cells(x).map((v) => `<td>${v}</td>`).join('')}</tr>`).join('\n');
    return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(c.title || 'Untitled case')}</title>
<style>
body{font:15px/1.5 system-ui,sans-serif;max-width:960px;margin:24px auto;padding:0 16px;color:#1b1f24;background:#fff}
h1{font-size:24px}h2{font-size:18px;margin-top:28px}table{border-collapse:collapse;width:100%;font-size:14px}
th,td{border:1px solid #d9dde3;padding:6px 8px;text-align:left;vertical-align:top;overflow-wrap:anywhere}th{background:#eef0f3}
code{font:13px ui-monospace,Consolas,monospace}.meta{color:#5f6b7a}pre{white-space:pre-wrap;background:#f6f7f9;padding:10px;border-radius:6px}
.malicious{color:#b42318;font-weight:600}.suspicious{color:#9a5b00;font-weight:600}.benign{color:#1e7f4f}
</style></head><body>
<h1>${esc(c.title || 'Untitled case')}</h1>
<p class="meta">${[c.ticket && `Ticket: ${esc(c.ticket)}`, c.analyst && `Analyst: ${esc(c.analyst)}`, c.created && `Created: ${esc(c.created)}`].filter(Boolean).join(' · ')}</p>
${c.notes.trim() ? `<h2>Notes</h2>\n<pre>${esc(c.notes.trim())}</pre>` : ''}
${c.iocs.length ? `<h2>Indicators (${c.iocs.length})</h2>
<table><thead><tr><th>Type</th><th>Indicator</th><th>Verdict</th><th>Note</th></tr></thead><tbody>
${rows(c.iocs, (x) => [esc(x.type), `<code>${esc(show(x.value, defang))}</code>`, `<span class="${esc(x.verdict)}">${esc(x.verdict)}</span>`, esc(x.note)])}
</tbody></table>` : ''}
${c.timeline.length ? `<h2>Timeline</h2>
<table><thead><tr><th>Time</th><th>Event</th></tr></thead><tbody>
${rows(sortedTimeline(c), (t) => [esc(t.time), esc(t.text)])}
</tbody></table>` : ''}
<p class="meta">Generated with Offline Analyst Toolkit${defang ? '. Indicators are defanged' : ''}.</p>
</body></html>
`;
  }

  function toJson(c) {
    return JSON.stringify({ ...c, version: VERSION }, null, 2);
  }

  return { VERDICTS, emptyCase, addIocsFromText, fromJson, toMarkdown, toHtml, toJson };
});
