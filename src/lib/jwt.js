/*
 * jwt.js: decode JSON Web Tokens and flag risky properties. Never sends the
 * token anywhere. HMAC signatures (HS256/384/512) can be checked locally with
 * a secret the analyst supplies; RS/ES/PS tokens need the issuer's public key,
 * which is out of scope for an offline decoder.
 */
(function (root, factory) {
  const lib = factory();
  if (typeof module === 'object' && module.exports) module.exports = lib;
  else (root.OAT = root.OAT || {}).jwt = lib;
})(globalThis, function () {
  'use strict';

  const codecs = () => globalThis.OAT.codecs;
  const hashes = () => globalThis.OAT.hashes;

  const HMAC_ALGS = { HS256: 'sha256', HS384: 'sha384', HS512: 'sha512' };
  const TIME_CLAIMS = ['exp', 'nbf', 'iat', 'auth_time', 'updated_at'];

  function clean(token) {
    return token.trim().replace(/^(?:authorization:\s*)?bearer\s+/i, '').replace(/\s+/g, '');
  }

  function decodeJson(part, what) {
    let bytes;
    try { bytes = codecs().base64Decode(part); } catch (e) { throw new Error(`${what} is not valid Base64URL: ${e.message}`); }
    const text = codecs().text(bytes);
    try { return JSON.parse(text); } catch (_) { throw new Error(`${what} is not valid JSON`); }
  }

  // Returns { header, payload, signature (Uint8Array), signingInput, findings, times }.
  // findings: [{ level: 'high'|'medium'|'low'|'info', text }]
  function decode(token, now = Date.now()) {
    const t = clean(token);
    const parts = t.split('.');
    if (parts.length === 5) {
      const header = decodeJson(parts[0], 'Header');
      return { header, payload: null, signature: new Uint8Array(0), signingInput: '', times: [],
        findings: [{ level: 'info', text: 'This is an encrypted JWT (JWE). Only the header can be read without the decryption key.' }] };
    }
    if (parts.length !== 3) throw new Error(`A JWT has 3 parts separated by dots; this has ${parts.length}`);

    const header = decodeJson(parts[0], 'Header');
    const payload = decodeJson(parts[1], 'Payload');
    let signature;
    try { signature = codecs().base64Decode(parts[2]); } catch (e) { throw new Error(`Signature is not valid Base64URL: ${e.message}`); }

    const findings = [];
    const add = (level, text) => findings.push({ level, text });
    const alg = typeof header.alg === 'string' ? header.alg : '';

    if (!alg) add('high', 'No "alg" in the header.');
    else if (alg.toLowerCase() === 'none') add('high', 'alg is "none": the token is unsigned and anyone can forge it. A server that accepts it is vulnerable.');
    else if (HMAC_ALGS[alg]) add('info', `${alg} is a shared-secret signature: anyone who knows the secret can mint tokens. Check it below if you have the secret.`);
    else if (!/^(?:RS|PS|ES)(?:256|384|512)$|^EdDSA$/.test(alg)) add('medium', `Unusual algorithm "${alg}".`);

    if (alg && alg.toLowerCase() !== 'none' && signature.length === 0) add('high', 'The signature part is empty although alg is not "none".');
    if (alg.toLowerCase() === 'none' && signature.length > 0) add('medium', 'alg is "none" but a signature is present.');

    for (const k of ['jku', 'x5u']) {
      if (header[k]) add('medium', `Header "${k}" points to a remote key (${String(header[k])}). If the server fetches keys from it, an attacker can supply their own.`);
    }
    if (header.jwk) add('medium', 'Header embeds its own key ("jwk"). A server that trusts it accepts self-signed tokens.');
    if (typeof header.kid === 'string' && /\.\.|[\/\\'";|`$]/.test(header.kid)) {
      add('medium', `"kid" contains path or injection characters: ${header.kid}`);
    }

    const times = [];
    for (const k of TIME_CLAIMS) {
      if (typeof payload[k] === 'number' && Number.isFinite(payload[k])) times.push({ claim: k, seconds: payload[k], date: new Date(payload[k] * 1000) });
    }
    const nowS = now / 1000;
    if (typeof payload.exp !== 'number') add('low', 'No expiry ("exp" claim): the token is valid until the key changes.');
    else if (payload.exp < nowS) add('medium', `Expired ${ago(nowS - payload.exp)} ago.`);
    if (typeof payload.nbf === 'number' && payload.nbf > nowS) add('medium', `Not valid yet ("nbf" is ${ago(payload.nbf - nowS)} in the future).`);
    if (typeof payload.iat === 'number' && payload.iat > nowS + 300) add('medium', 'Issued in the future ("iat"): clock skew or a forged token.');
    if (typeof payload.exp === 'number' && typeof payload.iat === 'number' && payload.exp - payload.iat > 30 * 86400) {
      add('low', `Long lifetime: ${ago(payload.exp - payload.iat)} between "iat" and "exp".`);
    }

    return { header, payload, signature, signingInput: `${parts[0]}.${parts[1]}`, times, findings };
  }

  // Check an HS256/384/512 signature with a secret given as UTF-8 text or Base64.
  // Returns true/false; throws if the algorithm is not HMAC.
  function verifyHmac(token, secret, { secretIsBase64 = false } = {}) {
    const t = clean(token);
    const parts = t.split('.');
    if (parts.length !== 3) throw new Error('Not a signed JWT');
    const alg = decodeJson(parts[0], 'Header').alg;
    const hashAlg = HMAC_ALGS[alg];
    if (!hashAlg) throw new Error(`Signature check here only supports HS256/384/512, not "${alg}"`);
    const key = secretIsBase64 ? codecs().base64Decode(secret) : codecs().utf8(secret);
    const expected = hashes().hmac(hashAlg, key, codecs().utf8(`${parts[0]}.${parts[1]}`));
    const actual = codecs().base64Decode(parts[2]);
    if (expected.length !== actual.length) return false;
    let diff = 0;
    for (let i = 0; i < expected.length; i++) diff |= expected[i] ^ actual[i];
    return diff === 0;
  }

  function ago(seconds) {
    const s = Math.abs(Math.round(seconds));
    if (s < 120) return `${s} seconds`;
    if (s < 7200) return `${Math.round(s / 60)} minutes`;
    if (s < 172800) return `${Math.round(s / 3600)} hours`;
    if (s < 63072000) return `${Math.round(s / 86400)} days`;
    return `${(s / 31557600).toFixed(1)} years`;
  }

  // Build an HS256/384/512 token. Used by the tests to create known samples.
  function signHmac(header, payload, secret) {
    const c = codecs();
    const enc = (o) => c.base64Encode(c.utf8(JSON.stringify(o)), { urlSafe: true });
    const input = `${enc(header)}.${enc(payload)}`;
    const sig = hashes().hmac(HMAC_ALGS[header.alg], c.utf8(secret), c.utf8(input));
    return `${input}.${c.base64Encode(sig, { urlSafe: true })}`;
  }

  return { decode, verifyHmac, signHmac, ago };
});
