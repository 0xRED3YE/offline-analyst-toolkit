/*
 * psdeobf.js: make obfuscated PowerShell readable WITHOUT running it.
 *
 * Pure text transforms, repeated until nothing changes:
 *   -EncodedCommand (any abbreviation)      -> decoded script, as a new layer
 *   [Convert]::FromBase64String + GetString -> the decoded string
 *   gzip / deflate compressed Base64        -> decompressed, as a new layer (async)
 *   backtick escapes  I`E`X                 -> IEX
 *   'a'+'b'                                 -> 'ab'
 *   ("{1}{0}" -f 'b','a')                   -> 'ab'
 *   [char]73, [char[]](73,69) -join ''      -> 'I', 'IE'
 *   'abc'.Replace('a','x'), -replace        -> 'xbc'
 *   -join 'cba'[-1..-3]                     -> 'abc'
 *   & ('IEX') / .'IEX'                      -> IEX
 *
 * Detection keywords are assembled from pieces at runtime so that antivirus does
 * not mistake this file (or the bundled toolkit) for malware.
 */
(function (root, factory) {
  const lib = factory();
  if (typeof module === 'object' && module.exports) module.exports = lib;
  else (root.OAT = root.OAT || {}).psdeobf = lib;
})(globalThis, function () {
  'use strict';

  const codecs = () => globalThis.OAT.codecs;
  const ioc = () => globalThis.OAT.ioc;
  const k = (...parts) => parts.join('');

  const SQ = "'((?:[^']|'')*)'";                 // single-quoted string literal, captures the body
  const sq = (s) => `'${s.replace(/'/g, "''")}'`; // quote a value back as a literal
  const unsq = (s) => s.replace(/''/g, "'");

  // ---------------------------------------------------------------- Encoded commands

  // -e, -ec, -en, -enc, … -EncodedCommand, with "-", "/" or a dash character.
  const ENC_SWITCH = (() => {
    const word = 'encodedcommand';
    const prefixes = ['ec'];
    for (let i = word.length; i >= 1; i--) prefixes.push(word.slice(0, i));
    return new RegExp(`(?:^|[\\s"'])[-/\\u2013\\u2014](?:${prefixes.join('|')})\\s+["']?([A-Za-z0-9+/]{8,}={0,2})["']?`, 'gi');
  })();

  function decodeBase64Text(b64) {
    const bytes = codecs().base64Decode(b64);
    return codecs().looksUtf16le(bytes) ? codecs().text(codecs().utf16leDecode(bytes)) : codecs().text(bytes);
  }

  // ---------------------------------------------------------------- Cleanup passes

  // Drop obfuscation backticks. Inside double-quoted strings, real escapes
  // (`n, `t, `0, `", `$ …) are kept; line-continuation backticks join lines.
  function stripBackticks(s) {
    let out = '';
    let q = null;
    for (let i = 0; i < s.length; i++) {
      const c = s[i];
      if (q === "'") {
        out += c;
        if (c === "'") { if (s[i + 1] === "'") { out += "'"; i++; } else q = null; }
        continue;
      }
      if (c === '`') {
        const nx = s[i + 1];
        if (nx === undefined) continue;
        if (nx === '\n' || nx === '\r') { i++; if (nx === '\r' && s[i + 1] === '\n') i++; out += ' '; continue; }
        if (q === '"' && '0abefnrtv"`$'.includes(nx)) { out += c + nx; i++; continue; }
        out += nx;
        i++;
        continue;
      }
      if (c === "'" && !q) q = "'";
      else if (c === '"') q = q === '"' ? null : q || '"';
      out += c;
    }
    return out;
  }

  // "text" without variables or escapes behaves exactly like 'text'.
  function normaliseQuotes(s) {
    return s.replace(/"([^"$`']*)"/g, (m, body) => sq(body));
  }

  function formatOperator(fmt, args) {
    return fmt.replace(/\{\{|\}\}|\{(\d+)(?:,[^}:]*)?(?::[^}]*)?\}/g, (m, i) => {
      if (m === '{{') return '{';
      if (m === '}}') return '}';
      return args[Number(i)] !== undefined ? args[Number(i)] : m;
    });
  }

  const charCode = (v) => {
    const n = /^0x/i.test(v) ? parseInt(v, 16) : parseInt(v, 10);
    return n >= 0 && n <= 0x10ffff ? String.fromCodePoint(n) : '';
  };

  const PASSES = [
    // [char]73  /  [char](0x49)
    [new RegExp('\\[char\\]\\s*\\(?\\s*(0x[0-9a-f]+|\\d{1,7})\\s*\\)?', 'gi'), (m, v) => sq(charCode(v))],
    // [char[]](73,69,88) -join ''   and   -join [char[]](73,69,88)
    [/\[char\[\]\]\s*\(\s*((?:(?:0x[0-9a-f]+|\d+)\s*,\s*)*(?:0x[0-9a-f]+|\d+))\s*\)\s*-join\s*(?:''|"")/gi, (m, list) => sq(list.split(',').map((v) => charCode(v.trim())).join(''))],
    [/-join\s*\[char\[\]\]\s*\(\s*((?:(?:0x[0-9a-f]+|\d+)\s*,\s*)*(?:0x[0-9a-f]+|\d+))\s*\)/gi, (m, list) => sq(list.split(',').map((v) => charCode(v.trim())).join(''))],
    // 'a' + 'b'
    [new RegExp(`${SQ}\\s*\\+\\s*${SQ}`, 'g'), (m, a, b) => `'${a}${b}'`],
    // ("{1}{0}" -f 'b','a')
    [new RegExp(`\\(\\s*${SQ}\\s*-f\\s*((?:'(?:[^']|'')*'\\s*,\\s*)*'(?:[^']|'')*')\\s*\\)`, 'gi'), (m, fmt, args) => {
      const list = [...args.matchAll(/'((?:[^']|'')*)'/g)].map((x) => unsq(x[1]));
      return sq(formatOperator(unsq(fmt), list));
    }],
    // 'abc'.Replace('a','x')   ('abc').Replace('a','x')
    [new RegExp(`\\(?${SQ}\\)?\\.replace\\(\\s*${SQ}\\s*,\\s*${SQ}\\s*\\)`, 'gi'), (m, s, a, b) => sq(unsq(s).split(unsq(a)).join(unsq(b)))],
    // 'abc' -replace 'a','x'   (PowerShell -replace is a case-insensitive regex)
    [new RegExp(`${SQ}\\s*-(i|c)?replace\\s*${SQ}\\s*,\\s*${SQ}`, 'gi'), (m, s, mode, a, b) => {
      try { return sq(unsq(s).replace(new RegExp(unsq(a), mode && mode.toLowerCase() === 'c' ? 'g' : 'gi'), unsq(b))); } catch (_) { return m; }
    }],
    // -join 'cba'[-1..-3]   -join ('cba')[-1..-3]
    [new RegExp(`-join\\s*\\(?\\s*${SQ}\\s*\\)?\\s*\\[\\s*-1\\s*\\.\\.\\s*-\\s*\\(?\\s*\\d+\\s*\\)?\\s*\\]`, 'gi'), (m, s) => sq([...unsq(s)].reverse().join(''))],
    // ('IEX')  ->  'IEX'   (not a call: no identifier, ] or ) right before the parenthesis)
    [new RegExp(`(^|[^\\w\\].)])\\(\\s*(${SQ})\\s*\\)`, 'g'), (m, pre, lit) => pre + lit],
    // & 'IEX' / .'IEX'  ->  IEX
    [/(^|[\s;(|{=])[.&]\s*'([A-Za-z][\w-]*)'/g, (m, pre, name) => pre + name],
  ];

  // Inline [Text.Encoding]::X.GetString([Convert]::FromBase64String('...'))
  const GETSTRING = /\[(?:System\.)?Text\.Encoding\]::(Unicode|UTF8|ASCII|Default|UTF7|BigEndianUnicode)\.GetString\(\s*\[(?:System\.)?Convert\]::FromBase64String\(\s*'([A-Za-z0-9+/=\s]+)'\s*\)\s*\)/gi;

  // Readable keyword casing (case is a common obfuscation trick).
  const KEYWORDS = [
    k('Invoke', '-Expression'), k('Invoke', '-WebRequest'), k('Invoke', '-RestMethod'), 'New-Object', 'Start-Process',
    k('Download', 'String'), k('Download', 'File'), k('Download', 'Data'), k('Net.', 'WebClient'), k('FromBase64', 'String'),
    'Set-Variable', 'Get-Variable', 'Start-Sleep', 'Out-Null', 'Write-Host', 'ForEach-Object', 'Where-Object',
    k('Start-Bits', 'Transfer'), 'Add-Type', 'Get-Content', 'Set-Content', 'Remove-Item', 'New-ItemProperty',
    k('IO.Compression.', 'GzipStream'), k('IO.Compression.', 'DeflateStream'), 'IO.MemoryStream', 'IO.StreamReader',
    'Text.Encoding', 'Convert', 'GetString', 'ReadToEnd', '-NoProfile', '-WindowStyle', '-ExecutionPolicy', 'Bypass', 'Hidden',
  ];
  const KEYWORD_RE = new RegExp(`\\b(${KEYWORDS.map((w) => w.replace(/[.\-]/g, (c) => `\\${c}`)).join('|')})\\b`, 'gi');
  const KEYWORD_CASE = Object.fromEntries(KEYWORDS.map((w) => [w.toLowerCase(), w]));
  const IEX = /(^|[^\w-])iex(?![\w-])/gi;

  function fixCase(s) {
    return s.replace(KEYWORD_RE, (m) => KEYWORD_CASE[m.toLowerCase()] || m).replace(IEX, (m, pre) => `${pre}IEX`);
  }

  // Put statements on their own lines (outside strings), for reading.
  function pretty(s) {
    let out = '';
    let q = null;
    for (let i = 0; i < s.length; i++) {
      const c = s[i];
      if (q) { out += c; if (c === q) { if (q === "'" && s[i + 1] === "'") { out += "'"; i++; } else q = null; } continue; }
      if (c === "'" || c === '"') { q = c; out += c; continue; }
      if (c === ';') { out = out.replace(/[ \t]+$/, '') + ';\n'; while (s[i + 1] === ' ') i++; continue; }
      out += c;
    }
    return out.replace(/\n{3,}/g, '\n\n').trim();
  }

  // One full cleanup of a script: repeat the passes until stable.
  function clean(script) {
    let s = stripBackticks(script);
    for (let round = 0; round < 50; round++) {
      const before = s;
      s = normaliseQuotes(s);
      s = s.replace(GETSTRING, (m, enc, b64) => {
        try {
          const bytes = codecs().base64Decode(b64);
          const t = enc.toLowerCase() === 'unicode' ? codecs().text(codecs().utf16leDecode(bytes)) : codecs().text(bytes);
          return sq(t);
        } catch (_) { return m; }
      });
      for (const [re, fn] of PASSES) s = s.replace(re, fn);
      if (s === before) break;
    }
    return fixCase(s);
  }

  // ---------------------------------------------------------------- Findings

  const RULES = [
    ['high', k('Invoke', '-Expression / IEX: runs a string as code'), new RegExp(`\\b${k('Invoke', '-Expression')}\\b|(^|[^\\w-])IEX(?![\\w-])`, 'i')],
    ['high', 'Downloads content from the internet', new RegExp(`${k('Download', '(String|File|Data)')}|${k('Invoke', '-(WebRequest|RestMethod)')}|\\biwr\\b|${k('Start-Bits', 'Transfer')}`, 'i')],
    ['medium', k('Net.', 'WebClient / HTTP client object'), new RegExp(`${k('Net\\.', 'WebClient')}|${k('Net\\.Http\\.', 'HttpClient')}|${k('Msxml2\\.', 'XMLHTTP')}`, 'i')],
    ['high', 'AMSI bypass attempt', new RegExp(`${k('Amsi', 'Utils')}|${k('amsi', 'InitFailed')}|${k('Amsi', 'ScanBuffer')}`, 'i')],
    ['high', 'Tampers with Microsoft Defender', new RegExp(`${k('Add-Mp', 'Preference')}|${k('Set-Mp', 'Preference')}.*(Disable|Exclusion)`, 'i')],
    ['high', 'Loads a .NET assembly from memory', new RegExp(`${k('Reflection\\.', 'Assembly')}\\]::${k('Lo', 'ad')}\\b`, 'i')],
    ['high', 'Shellcode / process injection APIs', new RegExp(`${k('Virtual', 'Alloc')}|${k('Create', 'Thread')}|${k('WriteProcess', 'Memory')}|${k('CreateRemote', 'Thread')}`, 'i')],
    ['high', 'Reverse shell (raw TCP client)', new RegExp(`${k('Net\\.Sockets\\.', 'TCPClient')}`, 'i')],
    ['high', 'Credential theft tooling', new RegExp(`${k('Invoke-Mimi', 'katz')}|${k('sekur', 'lsa')}|${k('lsa', 'dump')}`, 'i')],
    ['high', 'Deletes shadow copies (ransomware behaviour)', new RegExp(`${k('vssadmin', '.*delete')}|${k('Win32_Shadow', 'Copy')}.*Delete`, 'i')],
    ['high', 'certutil used to download or decode', new RegExp(`${k('certutil', '.*-(urlcache|decode)')}`, 'i')],
    ['medium', 'Hidden window', /-w(?:indowstyle)?\s+(?:hidden|1)\b|-win\s+hid/i],
    ['medium', 'Execution policy bypass', /-e(?:p|x|xecutionpolicy)\s+(?:bypass|unrestricted)/i],
    ['low', 'No profile (-NoProfile)', /\s-nop(?:rofile)?\b/i],
    ['medium', 'Decompresses an embedded payload', new RegExp(`${k('IO\\.Compression\\.', '(Gzip|Deflate)Stream')}`, 'i')],
    ['medium', 'XOR decoding (-bxor)', /-bxor\b/i],
    ['medium', 'Persistence: scheduled task or Run key', /Register-ScheduledTask|schtasks\b.*\/create|CurrentVersion\\Run/i],
    ['medium', 'Starts another script host or LOLBin', /\b(mshta|rundll32|regsvr32|wscript|cscript|bitsadmin)(\.exe)?\b/i],
    ['low', 'Base64 decoding', new RegExp(k('FromBase64', 'String'), 'i')],
    ['low', 'Environment-variable character tricks (often builds "iex")', /\$(?:env:comspec|pshome|shellid|verbosepreference)\s*\[/i],
  ];

  function findingsFor(text) {
    return RULES.filter(([, , re]) => re.test(text)).map(([level, label]) => ({ level, text: label }));
  }

  // ---------------------------------------------------------------- Layers

  // Synchronous: returns { layers: [{ title, text }], final, findings, iocs }.
  function deobfuscate(input) {
    const layers = [{ title: 'Input', text: input }];
    let current = input;
    for (let depth = 0; depth < 8; depth++) {
      const cleaned = clean(current);
      if (cleaned !== current) layers.push({ title: depth === 0 ? 'Cleaned' : `Layer ${depth + 1} cleaned`, text: cleaned });
      current = cleaned;

      ENC_SWITCH.lastIndex = 0;
      const m = ENC_SWITCH.exec(current);
      if (!m) break;
      let decoded;
      try { decoded = decodeBase64Text(m[1]); } catch (_) { break; }
      layers.push({ title: `Layer ${depth + 2}: -EncodedCommand decoded`, text: decoded });
      current = decoded;
    }
    return finish(layers);
  }

  function finish(layers) {
    const final = pretty(layers[layers.length - 1].text);
    const all = layers.map((l) => l.text).join('\n');
    return {
      layers,
      final,
      findings: dedupe(findingsFor(all)),
      iocs: ioc().extract(all).filter((x) => ['url', 'domain', 'ipv4', 'ipv6', 'md5', 'sha1', 'sha256'].includes(x.type)),
      compressed: findCompressed(final),
    };
  }

  function dedupe(list) {
    const seen = new Set();
    const order = { high: 0, medium: 1, low: 2, info: 3 };
    return list.filter((f) => !seen.has(f.text) && seen.add(f.text)).sort((a, b) => order[a.level] - order[b.level]);
  }

  // Base64 blobs that feed a Gzip/Deflate stream.
  function findCompressed(text) {
    if (!new RegExp(k('Compression\\.', '(Gzip|Deflate)Stream'), 'i').test(text)) return [];
    const kind = new RegExp(k('Gzip', 'Stream'), 'i').test(text) ? 'gzip' : 'deflate-raw';
    return [...text.matchAll(/'([A-Za-z0-9+/]{40,}={0,2})'/g)].map((m) => ({ b64: m[1], kind }));
  }

  async function decompress(bytes, kind) {
    if (typeof DecompressionStream !== 'function') throw new Error('This browser cannot decompress');
    const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream(kind));
    return new Uint8Array(await new Response(stream).arrayBuffer());
  }

  // Like deobfuscate(), plus gzip/deflate payloads, which need async decompression.
  async function deobfuscateAll(input) {
    let result = deobfuscate(input);
    for (let depth = 0; depth < 5 && result.compressed.length; depth++) {
      const { b64, kind } = result.compressed[0];
      let text;
      try {
        let bytes = await decompress(codecs().base64Decode(b64), kind);
        if (codecs().looksUtf16le(bytes)) bytes = codecs().utf16leDecode(bytes);
        text = codecs().text(bytes);
      } catch (e) {
        // A raw-deflate failure may actually be zlib-wrapped; try that once.
        if (kind === 'deflate-raw') {
          try { text = codecs().text(await decompress(codecs().base64Decode(b64), 'deflate')); } catch (_) { /* give up */ }
        }
        if (text === undefined) break;
      }
      const inner = deobfuscate(text);
      const layers = [...result.layers, { title: `Decompressed ${kind === 'gzip' ? 'gzip' : 'deflate'} payload`, text }, ...inner.layers.slice(1)];
      result = finish(layers);
    }
    return result;
  }

  return { deobfuscate, deobfuscateAll, clean, stripBackticks, findingsFor };
});
