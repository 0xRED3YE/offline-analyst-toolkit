/* Unit tests for src/lib/hashes.js: NIST / RFC vectors, HMAC (RFC 4231), chunking. */
(function () {
  'use strict';
  const H = globalThis.OAT.hashes;
  const u = (s) => new TextEncoder().encode(s);
  const hex = (alg, data) => H.toHex(H.hash(alg, typeof data === 'string' ? u(data) : data));

  test('MD5: RFC 1321 test suite', () => {
    const v = {
      '': 'd41d8cd98f00b204e9800998ecf8427e',
      a: '0cc175b9c0f1b6a831c399e269772661',
      abc: '900150983cd24fb0d6963f7d28e17f72',
      'message digest': 'f96b697d7cb7938d525a2f31aaf161d0',
      abcdefghijklmnopqrstuvwxyz: 'c3fcd3d76192e4007dfb496cca67e13b',
      '12345678901234567890123456789012345678901234567890123456789012345678901234567890': '57edf4a22be3c955ac49da2e2107b67a',
    };
    for (const [m, d] of Object.entries(v)) assert.equal(hex('md5', m), d, JSON.stringify(m));
  });

  const ABC448 = 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq';
  const ABC896 = 'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu';

  test('SHA-1: FIPS 180 vectors', () => {
    assert.equal(hex('sha1', ''), 'da39a3ee5e6b4b0d3255bfef95601890afd80709');
    assert.equal(hex('sha1', 'abc'), 'a9993e364706816aba3e25717850c26c9cd0d89d');
    assert.equal(hex('sha1', ABC448), '84983e441c3bd26ebaae4aa1f95129e5e54670f1');
  });

  test('SHA-256: FIPS 180 vectors', () => {
    assert.equal(hex('sha256', ''), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    assert.equal(hex('sha256', 'abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    assert.equal(hex('sha256', ABC448), '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1');
  });

  test('SHA-384: FIPS 180 vectors', () => {
    assert.equal(hex('sha384', 'abc'), 'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7');
    assert.equal(hex('sha384', ABC896), '09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039');
  });

  test('SHA-512: FIPS 180 vectors', () => {
    assert.equal(hex('sha512', ''), 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e');
    assert.equal(hex('sha512', 'abc'), 'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f');
    assert.equal(hex('sha512', ABC896), '8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909');
  });

  test('one million "a" (FIPS 180 long message), fed in odd-sized chunks', () => {
    const chunk = u('a'.repeat(997));
    const algs = { md5: '7707d6ae4e027c70eea2a935c2296f21', sha1: '34aa973cd4c4daa4f61eeb2bdbad27316534016f',
      sha256: 'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0' };
    for (const [alg, expected] of Object.entries(algs)) {
      const h = H.createHash(alg);
      let left = 1000000;
      while (left > 0) { const n = Math.min(left, chunk.length); h.update(chunk.subarray(0, n)); left -= n; }
      assert.equal(H.toHex(h.digest()), expected, alg);
    }
  });

  test('HMAC: RFC 4231 test case 2 and 6', () => {
    const tc2 = H.hmac('sha256', u('Jefe'), u('what do ya want for nothing?'));
    assert.equal(H.toHex(tc2), '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843');
    assert.equal(H.toHex(H.hmac('sha512', u('Jefe'), u('what do ya want for nothing?'))),
      '164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737');
    // Key longer than the block size is hashed first.
    const key = new Uint8Array(131).fill(0xaa);
    const tc6 = H.hmac('sha256', key, u('Test Using Larger Than Block-Size Key - Hash Key First'));
    assert.equal(H.toHex(tc6), '60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54');
  });

  test('digest() can only be called once', () => {
    const h = H.createHash('sha256');
    h.digest();
    assert.throws(() => h.digest(), /already/);
    assert.throws(() => H.createHash('sha3'), /Unknown/);
  });

  // Cross-check against OpenSSL when running under Node.
  if (typeof require === 'function') {
    test('matches Node/OpenSSL on random data of awkward lengths', () => {
      const crypto = require('crypto');
      for (const len of [0, 1, 55, 56, 63, 64, 65, 111, 112, 127, 128, 129, 4097, 65537]) {
        const data = crypto.randomBytes(len);
        for (const alg of ['md5', 'sha1', 'sha256', 'sha384', 'sha512']) {
          assert.equal(hex(alg, new Uint8Array(data)), crypto.createHash(alg).update(data).digest('hex'), `${alg} len ${len}`);
        }
      }
    });
  }
})();
