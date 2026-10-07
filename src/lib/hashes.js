/*
 * hashes.js: incremental MD5, SHA-1, SHA-256, SHA-384, SHA-512 and HMAC.
 *
 * Why not crypto.subtle.digest: it cannot stream (the whole file must be in
 * memory), it has no MD5, and it only exists in secure contexts. These
 * implementations take data in chunks, so files of any size hash with flat memory.
 *
 * The factory is self-contained (no outside references) because the Hashing
 * module also runs it inside a Web Worker built from its source text.
 * Checked against NIST/RFC vectors and against Node's OpenSSL in the tests.
 */
(function (root, factory) {
  const lib = factory();
  lib.factorySource = '(' + factory.toString() + ')';
  if (typeof module === 'object' && module.exports) module.exports = lib;
  else (root.OAT = root.OAT || {}).hashes = lib;
})(globalThis, function () {
  'use strict';

  // ---------------------------------------------------------------- Constants
  // SHA constants are the fractional bits of square/cube roots of primes.
  // Computed exactly with BigInt integer roots instead of pasting 100+ magic numbers.

  function firstPrimes(n) {
    const out = [];
    for (let c = 2; out.length < n; c++) if (out.every((p) => c % p)) out.push(c);
    return out;
  }

  // floor(n^(1/k)) for BigInt n > 0, by Newton's method from above.
  function iroot(n, k) {
    const K = BigInt(k);
    let x = 1n << (BigInt(n.toString(2).length) / K + 1n);
    for (;;) {
      const y = ((K - 1n) * x + n / x ** (K - 1n)) / K;
      if (y >= x) return x;
      x = y;
    }
  }

  // First `bits` fractional bits of p^(1/k).
  function fracBits(p, k, bits) {
    return iroot(BigInt(p) << BigInt(k * bits), k) & ((1n << BigInt(bits)) - 1n);
  }

  const PRIMES = firstPrimes(80);

  const K256 = Int32Array.from(PRIMES.slice(0, 64), (p) => Number(fracBits(p, 3, 32)));
  const IV256 = Int32Array.from(PRIMES.slice(0, 8), (p) => Number(fracBits(p, 2, 32)));

  function split64(values) {
    const out = new Int32Array(values.length * 2);
    values.forEach((v, i) => { out[i * 2] = Number(v >> 32n); out[i * 2 + 1] = Number(v & 0xffffffffn); });
    return out;
  }
  const K512 = split64(PRIMES.map((p) => fracBits(p, 3, 64)));
  const IV512 = split64(PRIMES.slice(0, 8).map((p) => fracBits(p, 2, 64)));
  const IV384 = split64(PRIMES.slice(8, 16).map((p) => fracBits(p, 2, 64)));

  // MD5 (RFC 1321): K[i] = floor(|sin(i + 1)| * 2^32).
  const MD5_K = Int32Array.from({ length: 64 }, (_, i) => Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296));
  const MD5_R = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];

  // ---------------------------------------------------------------- Compression functions

  const M16 = new Int32Array(16);
  function md5Block(s, view, off) {
    const M = M16;
    for (let i = 0; i < 16; i++) M[i] = view.getInt32(off + i * 4, true);
    let a = s[0], b = s[1], c = s[2], d = s[3];
    for (let i = 0; i < 64; i++) {
      let f, g;
      if (i < 16) { f = (b & c) | (~b & d); g = i; }
      else if (i < 32) { f = (d & b) | (~d & c); g = (5 * i + 1) & 15; }
      else if (i < 48) { f = b ^ c ^ d; g = (3 * i + 5) & 15; }
      else { f = c ^ (b | ~d); g = (7 * i) & 15; }
      const r = MD5_R[((i >> 4) << 2) | (i & 3)];
      const x = (a + f + MD5_K[i] + M[g]) | 0;
      a = d; d = c; c = b;
      b = (b + ((x << r) | (x >>> (32 - r)))) | 0;
    }
    s[0] = (s[0] + a) | 0; s[1] = (s[1] + b) | 0; s[2] = (s[2] + c) | 0; s[3] = (s[3] + d) | 0;
  }

  const W80 = new Int32Array(80);
  function sha1Block(s, view, off) {
    const W = W80;
    for (let i = 0; i < 16; i++) W[i] = view.getInt32(off + i * 4);
    for (let i = 16; i < 80; i++) {
      const x = W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16];
      W[i] = (x << 1) | (x >>> 31);
    }
    let a = s[0], b = s[1], c = s[2], d = s[3], e = s[4];
    for (let i = 0; i < 80; i++) {
      let f, k;
      if (i < 20) { f = (b & c) | (~b & d); k = 0x5a827999; }
      else if (i < 40) { f = b ^ c ^ d; k = 0x6ed9eba1; }
      else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc; }
      else { f = b ^ c ^ d; k = 0xca62c1d6; }
      const t = (((a << 5) | (a >>> 27)) + f + e + k + W[i]) | 0;
      e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;
    }
    s[0] = (s[0] + a) | 0; s[1] = (s[1] + b) | 0; s[2] = (s[2] + c) | 0; s[3] = (s[3] + d) | 0; s[4] = (s[4] + e) | 0;
  }

  const W64 = new Int32Array(64);
  function sha256Block(s, view, off) {
    const W = W64;
    for (let i = 0; i < 16; i++) W[i] = view.getInt32(off + i * 4);
    for (let i = 16; i < 64; i++) {
      const x = W[i - 15], y = W[i - 2];
      const s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
      const s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
      W[i] = (W[i - 16] + s0 + W[i - 7] + s1) | 0;
    }
    let a = s[0], b = s[1], c = s[2], d = s[3], e = s[4], f = s[5], g = s[6], h = s[7];
    for (let i = 0; i < 64; i++) {
      const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      const choose = (e & f) ^ (~e & g);
      const t1 = (h + S1 + choose + K256[i] + W[i]) | 0;
      const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) | 0;
      h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
    }
    s[0] = (s[0] + a) | 0; s[1] = (s[1] + b) | 0; s[2] = (s[2] + c) | 0; s[3] = (s[3] + d) | 0;
    s[4] = (s[4] + e) | 0; s[5] = (s[5] + f) | 0; s[6] = (s[6] + g) | 0; s[7] = (s[7] + h) | 0;
  }

  // SHA-512 works on 64-bit words, stored as (high, low) pairs of 32-bit ints.
  // Additions carry from low to high through ordinary Number arithmetic.
  const TWO32 = 4294967296;
  const W160 = new Int32Array(160);
  function sha512Block(s, view, off) {
    const W = W160;
    for (let i = 0; i < 32; i++) W[i] = view.getInt32(off + i * 4);
    for (let i = 16; i < 80; i++) {
      let xh = W[(i - 15) * 2], xl = W[(i - 15) * 2 + 1];
      // sigma0 = rotr 1 ^ rotr 8 ^ shr 7
      const s0h = ((xh >>> 1) | (xl << 31)) ^ ((xh >>> 8) | (xl << 24)) ^ (xh >>> 7);
      const s0l = ((xl >>> 1) | (xh << 31)) ^ ((xl >>> 8) | (xh << 24)) ^ ((xl >>> 7) | (xh << 25));
      xh = W[(i - 2) * 2]; xl = W[(i - 2) * 2 + 1];
      // sigma1 = rotr 19 ^ rotr 61 ^ shr 6
      const s1h = ((xh >>> 19) | (xl << 13)) ^ ((xl >>> 29) | (xh << 3)) ^ (xh >>> 6);
      const s1l = ((xl >>> 19) | (xh << 13)) ^ ((xh >>> 29) | (xl << 3)) ^ ((xl >>> 6) | (xh << 26));
      const lo = (W[(i - 16) * 2 + 1] >>> 0) + (s0l >>> 0) + (W[(i - 7) * 2 + 1] >>> 0) + (s1l >>> 0);
      W[i * 2] = (W[(i - 16) * 2] + s0h + W[(i - 7) * 2] + s1h + Math.floor(lo / TWO32)) | 0;
      W[i * 2 + 1] = lo | 0;
    }
    let ah = s[0], al = s[1], bh = s[2], bl = s[3], ch = s[4], cl = s[5], dh = s[6], dl = s[7];
    let eh = s[8], el = s[9], fh = s[10], fl = s[11], gh = s[12], gl = s[13], hh = s[14], hl = s[15];
    for (let i = 0; i < 80; i++) {
      // Sigma1(e) = rotr 14 ^ rotr 18 ^ rotr 41
      const S1h = ((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((el >>> 9) | (eh << 23));
      const S1l = ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((eh >>> 9) | (el << 23));
      const chooseH = (eh & fh) ^ (~eh & gh), chooseL = (el & fl) ^ (~el & gl);
      let lo = (hl >>> 0) + (S1l >>> 0) + (chooseL >>> 0) + (K512[i * 2 + 1] >>> 0) + (W[i * 2 + 1] >>> 0);
      const t1h = (hh + S1h + chooseH + K512[i * 2] + W[i * 2] + Math.floor(lo / TWO32)) | 0;
      const t1l = lo | 0;
      // Sigma0(a) = rotr 28 ^ rotr 34 ^ rotr 39
      const S0h = ((ah >>> 28) | (al << 4)) ^ ((al >>> 2) | (ah << 30)) ^ ((al >>> 7) | (ah << 25));
      const S0l = ((al >>> 28) | (ah << 4)) ^ ((ah >>> 2) | (al << 30)) ^ ((ah >>> 7) | (al << 25));
      const majH = (ah & bh) ^ (ah & ch) ^ (bh & ch), majL = (al & bl) ^ (al & cl) ^ (bl & cl);
      lo = (S0l >>> 0) + (majL >>> 0);
      const t2h = (S0h + majH + Math.floor(lo / TWO32)) | 0;
      const t2l = lo | 0;
      hh = gh; hl = gl; gh = fh; gl = fl; fh = eh; fl = el;
      lo = (dl >>> 0) + (t1l >>> 0);
      eh = (dh + t1h + Math.floor(lo / TWO32)) | 0; el = lo | 0;
      dh = ch; dl = cl; ch = bh; cl = bl; bh = ah; bl = al;
      lo = (t1l >>> 0) + (t2l >>> 0);
      ah = (t1h + t2h + Math.floor(lo / TWO32)) | 0; al = lo | 0;
    }
    const v = [ah, al, bh, bl, ch, cl, dh, dl, eh, el, fh, fl, gh, gl, hh, hl];
    for (let i = 0; i < 16; i += 2) {
      const lo = (s[i + 1] >>> 0) + (v[i + 1] >>> 0);
      s[i] = (s[i] + v[i] + Math.floor(lo / TWO32)) | 0;
      s[i + 1] = lo | 0;
    }
  }

  // ---------------------------------------------------------------- Algorithms

  function wordsOut(s, nBytes, littleEndian) {
    const out = new Uint8Array(nBytes);
    const v = new DataView(out.buffer);
    for (let i = 0; i < nBytes / 4; i++) v.setInt32(i * 4, s[i], littleEndian);
    return out;
  }

  const ALGORITHMS = {
    md5: { name: 'MD5', blockSize: 64, littleEndian: true, block: md5Block, size: 16,
      init: () => Int32Array.from([0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]) },
    sha1: { name: 'SHA-1', blockSize: 64, littleEndian: false, block: sha1Block, size: 20,
      init: () => Int32Array.from([0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]) },
    sha256: { name: 'SHA-256', blockSize: 64, littleEndian: false, block: sha256Block, size: 32,
      init: () => IV256.slice() },
    sha384: { name: 'SHA-384', blockSize: 128, littleEndian: false, block: sha512Block, size: 48,
      init: () => IV384.slice() },
    sha512: { name: 'SHA-512', blockSize: 128, littleEndian: false, block: sha512Block, size: 64,
      init: () => IV512.slice() },
  };

  // createHash('sha256').update(bytes).update(more).digest() -> Uint8Array
  function createHash(alg) {
    const spec = ALGORITHMS[alg];
    if (!spec) throw new Error(`Unknown hash algorithm "${alg}"`);
    const { blockSize, littleEndian, block } = spec;
    const state = spec.init();
    const buf = new Uint8Array(blockSize);
    const bufView = new DataView(buf.buffer);
    let bufLen = 0;
    let total = 0;
    let finished = false;

    const hasher = {
      algorithm: alg,
      update(data) {
        if (finished) throw new Error('digest() was already called');
        total += data.length;
        let pos = 0;
        if (bufLen) {
          pos = Math.min(blockSize - bufLen, data.length);
          buf.set(data.subarray(0, pos), bufLen);
          bufLen += pos;
          if (bufLen < blockSize) return hasher;
          block(state, bufView, 0);
          bufLen = 0;
        }
        const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
        for (; pos + blockSize <= data.length; pos += blockSize) block(state, view, pos);
        buf.set(data.subarray(pos), 0);
        bufLen = data.length - pos;
        return hasher;
      },
      digest() {
        if (finished) throw new Error('digest() was already called');
        // Padding: 0x80, zeros, then the message length in bits (64-bit, or 128-bit for SHA-384/512).
        const lenBytes = blockSize === 128 ? 16 : 8;
        const bits = total * 8;
        const zeros = (blockSize - ((total + 1 + lenBytes) % blockSize)) % blockSize;
        const pad = new Uint8Array(1 + zeros + lenBytes);
        pad[0] = 0x80;
        const v = new DataView(pad.buffer);
        const hi = Math.floor(bits / TWO32), lo = bits >>> 0;
        if (littleEndian) { v.setUint32(pad.length - 8, lo, true); v.setUint32(pad.length - 4, hi, true); }
        else { v.setUint32(pad.length - 8, hi); v.setUint32(pad.length - 4, lo); }
        hasher.update(pad);
        finished = true;
        return wordsOut(state, spec.size, littleEndian);
      },
    };
    return hasher;
  }

  function hash(alg, bytes) {
    return createHash(alg).update(bytes).digest();
  }

  // HMAC (RFC 2104) with any of the algorithms above.
  function hmac(alg, key, message) {
    const { blockSize } = ALGORITHMS[alg];
    let k = key.length > blockSize ? hash(alg, key) : key;
    const padded = new Uint8Array(blockSize);
    padded.set(k);
    const ipad = padded.map((b) => b ^ 0x36);
    const opad = padded.map((b) => b ^ 0x5c);
    const inner = createHash(alg).update(ipad).update(message).digest();
    return createHash(alg).update(opad).update(inner).digest();
  }

  function toHex(bytes) {
    let s = '';
    for (const b of bytes) s += b.toString(16).padStart(2, '0');
    return s;
  }

  const NAMES = Object.fromEntries(Object.entries(ALGORITHMS).map(([id, a]) => [id, a.name]));

  return { createHash, hash, hmac, toHex, NAMES };
});
