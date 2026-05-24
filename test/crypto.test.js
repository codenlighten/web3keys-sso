import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  randomBytes, bytesToBase64, base64ToBytes,
  kekFromPassword, kekFromPrf, wrap, unwrap,
} from '../public/js/crypto.js';

test('randomBytes returns the requested size and is non-zero', () => {
  const a = randomBytes(32);
  assert.equal(a.length, 32);
  const b = randomBytes(32);
  // Vanishingly unlikely to be equal; sanity check
  assert.notEqual(bytesToBase64(a), bytesToBase64(b));
});

test('base64 round-trip preserves bytes', () => {
  const a = new Uint8Array([0, 1, 2, 254, 255]);
  const round = base64ToBytes(bytesToBase64(a));
  assert.deepEqual(Array.from(round), Array.from(a));
});

test('wrap/unwrap round-trip with password-derived KEK', async () => {
  const salt = randomBytes(16);
  const kek = await kekFromPassword('correct horse battery staple', salt, 10000);
  const wrapped = await wrap(kek, 'L1WxxRzZjTwjvtjJWp...');
  const back = await unwrap(kek, wrapped);
  assert.equal(back, 'L1WxxRzZjTwjvtjJWp...');
});

test('unwrap with wrong password fails', async () => {
  const salt = randomBytes(16);
  const kek1 = await kekFromPassword('right', salt, 10000);
  const kek2 = await kekFromPassword('wrong', salt, 10000);
  const wrapped = await wrap(kek1, 'secret');
  await assert.rejects(() => unwrap(kek2, wrapped));
});

test('kekFromPrf derives different KEKs for different info strings', async () => {
  const prf = randomBytes(32);
  const kek1 = await kekFromPrf(prf, 'info-A');
  const kek2 = await kekFromPrf(prf, 'info-B');
  // We can't compare CryptoKey objects directly, but encrypting the same
  // plaintext with each should yield different ciphertexts.
  const a = await wrap(kek1, 'same');
  const b = await wrap(kek2, 'same');
  assert.notEqual(a.ct, b.ct);
});

test('wrap output base64-decodes to expected lengths', async () => {
  const salt = randomBytes(16);
  const kek = await kekFromPassword('pw', salt, 10000);
  const w = await wrap(kek, 'hello');
  const iv = base64ToBytes(w.iv);
  assert.equal(iv.length, 12);
  // AES-GCM ciphertext = plaintext + 16-byte auth tag → 5 + 16 = 21
  const ct = base64ToBytes(w.ct);
  assert.equal(ct.length, 21);
});
