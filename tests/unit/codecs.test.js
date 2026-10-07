/* Unit tests for src/lib/codecs.js. Uses the globals from tests/harness.js. */
(function () {
  'use strict';
  const C = globalThis.OAT.codecs;
  const u = C.utf8;

  // ------------------------------------------------------------ Base64: RFC 4648 section 10

  const RFC4648 = [['', ''], ['f', 'Zg=='], ['fo', 'Zm8='], ['foo', 'Zm9v'], ['foob', 'Zm9vYg=='], ['fooba', 'Zm9vYmE='], ['foobar', 'Zm9vYmFy']];

  test('Base64 encode: RFC 4648 vectors', () => {
    for (const [plain, b64] of RFC4648) assert.equal(C.base64Encode(u(plain)), b64, JSON.stringify(plain));
  });

  test('Base64 decode: RFC 4648 vectors', () => {
    for (const [plain, b64] of RFC4648) assert.equal(C.text(C.base64Decode(b64)), plain, b64);
  });

  test('Base64 decode: tolerates whitespace and missing padding', () => {
    assert.equal(C.text(C.base64Decode('Zm9v\nYmE')), 'fooba');
    assert.equal(C.text(C.base64Decode('  Zg  ')), 'f');
  });

  test('Base64 URL-safe round trip with bytes that need - and _', () => {
    const bytes = Uint8Array.from([0xfb, 0xff, 0xbf, 0x3e]);
    assert.equal(C.base64Encode(bytes), '+/+/Pg==');
    assert.equal(C.base64Encode(bytes, { urlSafe: true }), '-_-_Pg');
    assert.bytes(C.base64Decode('-_-_Pg'), bytes);
    assert.bytes(C.base64Decode('+/+/Pg=='), bytes);
  });

  test('Base64 decode: rejects invalid input', () => {
    assert.throws(() => C.base64Decode('Zm9v!'), /Invalid Base64 character "!"/);
    assert.throws(() => C.base64Decode('Zm9vY'), /length/);
  });

  test('Base64: all 256 byte values round trip', () => {
    const all = Uint8Array.from({ length: 256 }, (_, i) => i);
    assert.bytes(C.base64Decode(C.base64Encode(all)), all);
  });

  // ------------------------------------------------------------ Hex: RFC 4648 base16

  test('Hex encode: RFC 4648 base16 vector', () => {
    assert.equal(C.hexEncode(u('foobar')), '666f6f626172');
    assert.equal(C.hexEncode(u('foo'), ' '), '66 6f 6f');
  });

  test('Hex decode: common formats', () => {
    for (const s of ['666F6F', '66 6f 6f', '66:6f:6f', '0x66,0x6f,0x6f', '\\x66\\x6f\\x6f', '66-6F-6F']) {
      assert.equal(C.text(C.hexDecode(s)), 'foo', s);
    }
  });

  test('Hex decode: rejects bad input', () => {
    assert.throws(() => C.hexDecode('abc'), /odd/);
    assert.throws(() => C.hexDecode('zz'), /Invalid hex character "z"/);
  });

  // ------------------------------------------------------------ URL

  test('URL encode: reserved and non-ASCII characters', () => {
    assert.equal(C.urlEncode(u('a b&c=d/é~')), 'a%20b%26c%3Dd%2F%C3%A9~');
  });

  test('URL decode: UTF-8 sequences, and tolerant of malformed escapes', () => {
    assert.equal(C.text(C.urlDecode(u('a%20b%26c%3Dd%2F%C3%A9'))), 'a b&c=d/é');
    assert.equal(C.text(C.urlDecode(u('100% sure %zz %4'))), '100% sure %zz %4');
    assert.equal(C.text(C.urlDecode(u('a+b'))), 'a+b', 'plus is left alone');
  });

  test('URL decode: double encoding needs two steps', () => {
    const once = C.urlDecode(u('%253Cscript%253E'));
    assert.equal(C.text(once), '%3Cscript%3E');
    assert.equal(C.text(C.urlDecode(once)), '<script>');
  });

  // ------------------------------------------------------------ HTML entities

  test('HTML encode: the five special characters', () => {
    assert.equal(C.htmlEncode(`<a href="x">'&'</a>`), '&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;');
  });

  test('HTML decode: named, decimal, hex, and obfuscation tricks', () => {
    assert.equal(C.htmlDecode('&lt;b&gt; &amp;amp; &#65;&#x42;&#X43;'), '<b> &amp; ABC');
    assert.equal(C.htmlDecode('javascript&colon;alert&lpar;1&rpar;'), 'javascript:alert(1)');
    assert.equal(C.htmlDecode('&#106&#97&#118&#97'), 'java', 'numeric without semicolons');
    assert.equal(C.htmlDecode('&unknown; &amp'), '&unknown; &amp', 'unknown or unterminated named entities stay');
    assert.equal(C.htmlDecode('&#x110000; &#xD800;'), '\ufffd \ufffd', 'invalid code points');
    assert.equal(C.htmlDecode('&#x1F600;'), '😀');
  });

  // ------------------------------------------------------------ ROT13

  test('ROT13: letters only, involutive', () => {
    assert.equal(C.text(C.rot13(u('Hello, World! 123'))), 'Uryyb, Jbeyq! 123');
    assert.equal(C.text(C.rot13(C.rot13(u('Attack at dawn')))), 'Attack at dawn');
  });

  // ------------------------------------------------------------ Binary

  test('Binary encode and decode', () => {
    assert.equal(C.binaryEncode(u('Hi')), '01001000 01101001');
    assert.equal(C.text(C.binaryDecode('0100100001101001')), 'Hi');
    assert.equal(C.text(C.binaryDecode('01001000, 01101001\n')), 'Hi');
    assert.throws(() => C.binaryDecode('0100100'), /multiple of 8/);
    assert.throws(() => C.binaryDecode('01001002'), /Invalid binary/);
  });

  // ------------------------------------------------------------ Unicode escapes

  test('Unicode escape: non-ASCII, control characters and backslash', () => {
    assert.equal(C.unicodeEscape('aé\n😀\\'), 'a\\u00e9\\u000a\\ud83d\\ude00\\u005c');
  });

  test('Unicode unescape: \\u, surrogate pairs, \\u{}, \\U and simple escapes', () => {
    assert.equal(C.text(C.unicodeUnescape('a\\u00e9\\ud83d\\ude00')), 'aé😀');
    assert.equal(C.text(C.unicodeUnescape('\\u{1F600} \\U0001F600')), '😀 😀');
    assert.equal(C.text(C.unicodeUnescape('line1\\nline2\\t\\"q\\"')), 'line1\nline2\t"q"');
  });

  test('Unicode unescape: \\x is a raw byte, so UTF-8 byte escapes decode correctly', () => {
    assert.equal(C.text(C.unicodeUnescape('caf\\xc3\\xa9')), 'café');
    assert.bytes(C.unicodeUnescape('\\x4d\\x5a\\x90\\x00'), [0x4d, 0x5a, 0x90, 0x00]);
  });

  test('Unicode unescape: lone surrogate becomes U+FFFD, unknown escapes stay', () => {
    assert.equal(C.text(C.unicodeUnescape('\\ud83dx')), '\ufffdx');
    assert.equal(C.text(C.unicodeUnescape('C:\\temp\\zz')), 'C:\temp\\zz');
  });

  test('Unicode escape and unescape round trip', () => {
    const s = 'Ünïcödé ✓ 😀 \u0000 end';
    assert.equal(C.text(C.unicodeUnescape(C.unicodeEscape(s))), s);
  });

  // ------------------------------------------------------------ UTF-16LE / PowerShell

  test('UTF-16LE: PowerShell -EncodedCommand example decodes', () => {
    // powershell -EncodedCommand for: Write-Host 'hi'
    const enc = C.base64Encode(C.utf16leEncode("Write-Host 'hi'"));
    assert.equal(enc, 'VwByAGkAdABlAC0ASABvAHMAdAAgACcAaABpACcA');
    assert.equal(C.text(C.utf16leDecode(C.base64Decode(enc))), "Write-Host 'hi'");
    assert.throws(() => C.utf16leDecode(Uint8Array.from([0x41])), /even/);
  });

  // ------------------------------------------------------------ Recipes

  test('runRecipe chains steps and reports each result', () => {
    const r = C.runRecipe(u('Zm9vYmFy'), ['b64-decode', 'hex-encode']);
    assert.equal(r.length, 2);
    assert.ok(r.every((x) => x.ok));
    assert.equal(C.text(r[1].bytes), '666f6f626172');
  });

  test('runRecipe stops at the first failing step', () => {
    const r = C.runRecipe(u('not base64!'), ['b64-decode', 'hex-encode']);
    assert.equal(r.length, 1);
    assert.equal(r[0].ok, false);
    assert.ok(/Invalid Base64/.test(r[0].error));
  });

  test('every operation has a unique id and runs on empty input', () => {
    const ids = new Set();
    for (const op of C.OPS) {
      assert.ok(!ids.has(op.id), `duplicate op id ${op.id}`);
      ids.add(op.id);
      const r = C.runRecipe(new Uint8Array(0), [op.id]);
      assert.ok(r[0].ok, `${op.id} failed on empty input: ${r[0].error}`);
    }
  });

  test('encode then decode round trips for every encoder', () => {
    const pairs = [['b64-encode', 'b64-decode'], ['b64url-encode', 'b64-decode'], ['hex-encode', 'hex-decode'],
      ['url-encode', 'url-decode'], ['html-encode', 'html-decode'], ['unicode-escape', 'unicode-unescape'],
      ['binary-encode', 'binary-decode'], ['utf16le-encode', 'utf16le-decode'], ['rot13', 'rot13']];
    const sample = u('<tag attr="v">it\'s 100% café & 😀</tag>');
    for (const [a, b] of pairs) {
      const r = C.runRecipe(sample, [a, b]);
      assert.ok(r[1] && r[1].ok, `${a} → ${b} failed`);
      assert.bytes(r[1].bytes, sample, `${a} → ${b}`);
    }
  });

  // ------------------------------------------------------------ Detection

  const top = (s) => (C.detect(s)[0] || {}).ops;

  test('detect: Base64 text', () => {
    assert.equal(JSON.stringify(top('SGVsbG8sIGFuYWx5c3QhIFRoaXMgaXMgYSB0ZXN0Lg==')), '["b64-decode"]');
  });

  test('detect: Base64 of UTF-16LE suggests the PowerShell chain', () => {
    assert.equal(JSON.stringify(top('VwByAGkAdABlAC0ASABvAHMAdAAgACcAaABpACcA')), '["b64-decode","utf16le-decode"]');
  });

  test('detect: hex text', () => {
    assert.equal(JSON.stringify(top('48 65 6c 6c 6f 20 77 6f 72 6c 64')), '["hex-decode"]');
  });

  test('detect: URL, HTML entities, escapes, binary', () => {
    assert.equal(JSON.stringify(top('https%3A%2F%2Fexample.com%2Fpath%3Fq%3D1')), '["url-decode"]');
    assert.equal(JSON.stringify(top('&lt;script&gt;alert(1)&lt;/script&gt;')), '["html-decode"]');
    assert.equal(JSON.stringify(top('\\u0068\\u0065\\u006c\\u006c\\u006f')), '["unicode-unescape"]');
    assert.equal(JSON.stringify(top('01001000 01101001 00100001 00100001')), '["binary-decode"]');
  });

  test('detect: Base64 gzip is recognised by magic bytes', () => {
    const s = C.detect('H4sIAAAAAAAAA8tIzcnJBwCGphA2BQAAAA==')[0];
    assert.ok(s && /gzip/.test(s.label), 'gzip label');
  });

  test('detect: plain English gives no suggestions', () => {
    assert.equal(C.detect('The quick brown fox jumps over the lazy dog').length, 0);
    assert.equal(C.detect('abc').length, 0);
  });

  test('detect: a hex hash is not mistaken for Base64 text', () => {
    const s = C.detect('d41d8cd98f00b204e9800998ecf8427e');
    assert.ok(!s.some((x) => x.ops[0] === 'b64-decode'), 'no base64 suggestion for an MD5');
  });

  // ------------------------------------------------------------ Helpers

  test('sniff recognises common file types', () => {
    assert.equal(C.sniff(Uint8Array.from([0x4d, 0x5a, 0x90, 0])), 'Windows executable (MZ)');
    assert.equal(C.sniff(u('%PDF-1.7')), 'PDF document');
    assert.equal(C.sniff(u('hello')), null);
  });

  test('hexdump layout', () => {
    assert.equal(C.hexdump(u('ABCDEFGHIJKLMNOPQ')),
      '00000000  41 42 43 44 45 46 47 48  49 4a 4b 4c 4d 4e 4f 50  |ABCDEFGHIJKLMNOP|\n' +
      '00000010  ' + '51'.padEnd(23) + '  ' + ''.padEnd(23) + '  |Q|');
  });
})();
