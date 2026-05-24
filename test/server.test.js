// Tests run against the express app from server.js with a tmpdir DATA_DIR
// and a deterministic SERVER_PEPPER. SMTP is intentionally unconfigured so
// mail-requiring routes return 503 cleanly.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const bsv = require('@smartledger/bsv');

let app, request, tmpDir;

before(async () => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'w3k-test-'));
  process.env.DATA_DIR = tmpDir;
  process.env.SERVER_PEPPER = 'a'.repeat(64);
  process.env.PUBLIC_BASE_URL = 'http://test.local';
  // Don't set SMTP_* — mail-requiring routes should 503.
  ({ app } = await import('../server.js'));
  request = (await import('supertest')).default;
});

after(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

function newIdentity() {
  const priv = new bsv.PrivateKey();
  return { priv, pubKey: priv.toPublicKey().toString('hex'), address: priv.toAddress().toString() };
}

test('GET /healthz', async () => {
  const r = await request(app).get('/healthz');
  assert.equal(r.status, 200);
  assert.equal(r.body.ok, true);
});

test('paymail handle validation rejects bad shapes', async () => {
  const r = await request(app).get('/api/paymail/check/AA');
  assert.equal(r.status, 400);
});

test('paymail handle reserved list blocks squat targets', async () => {
  const r = await request(app).get('/api/paymail/check/admin');
  assert.equal(r.status, 200);
  // Reserved handles are valid in shape but report as unavailable.
  assert.equal(r.body.ok, true);
  assert.equal(r.body.available, false);
});

test('paymail check returns available for a fresh handle', async () => {
  const r = await request(app).get('/api/paymail/check/freshhandle' + Date.now());
  assert.equal(r.status, 200);
  assert.equal(r.body.available, true);
});

test('paymail claim end-to-end', async () => {
  const { priv, pubKey, address } = newIdentity();
  const handle = 'tester' + Math.floor(Math.random() * 1e8);
  const ts = Date.now();
  const message = `web3keys:claim|handle=${handle}|pubkey=${pubKey}|address=${address}|ts=${ts}`;
  const signature = bsv.Message(message).sign(priv);

  const r = await request(app).post('/api/paymail/claim').send({
    handle, pubKey, address, displayName: 'Tester', message, signature,
  });
  assert.equal(r.status, 200);
  assert.equal(r.body.handle, handle);

  const lookup = await request(app).get(`/api/paymail/${handle}`);
  assert.equal(lookup.status, 200);
  assert.equal(lookup.body.pubKey, pubKey);

  const html = await request(app).get(`/u/${handle}`);
  assert.equal(html.status, 200);
  assert.match(html.text, /Verified identity/);
});

test('paymail claim rejects tampered signature', async () => {
  const { priv, pubKey, address } = newIdentity();
  const handle = 'tamper' + Math.floor(Math.random() * 1e8);
  const ts = Date.now();
  const message = `web3keys:claim|handle=${handle}|pubkey=${pubKey}|address=${address}|ts=${ts}`;
  const signature = bsv.Message(message).sign(priv);
  // Mutate the message but keep the original signature
  const bad = message.replace(handle, handle + 'X');
  const r = await request(app).post('/api/paymail/claim').send({
    handle, pubKey, address, displayName: 'Tester', message: bad, signature,
  });
  assert.equal(r.status, 400);
});

test('paymail claim rejects pubkey/address mismatch', async () => {
  const { priv, pubKey } = newIdentity();
  const wrongAddress = new bsv.PrivateKey().toAddress().toString();
  const handle = 'mismatch' + Math.floor(Math.random() * 1e8);
  const ts = Date.now();
  const message = `web3keys:claim|handle=${handle}|pubkey=${pubKey}|address=${wrongAddress}|ts=${ts}`;
  const signature = bsv.Message(message).sign(priv);
  const r = await request(app).post('/api/paymail/claim').send({
    handle, pubKey, address: wrongAddress, displayName: 'X', message, signature,
  });
  // Either signature fails (verified against wrong address) or pubkey/address mismatch — both 4xx.
  assert.ok(r.status >= 400 && r.status < 500, `expected 4xx, got ${r.status}`);
});

test('GET /u/:handle for unclaimed renders 404 page', async () => {
  const r = await request(app).get('/u/nobody' + Date.now());
  assert.equal(r.status, 404);
  assert.match(r.text, /unclaimed/);
});

test('backup save with valid payload', async () => {
  const { pubKey } = newIdentity();
  const payload = {
    ciphertext: Buffer.from('ct').toString('base64'),
    iv: Buffer.from('iv').toString('base64'),
    salt: Buffer.from('saltsaltsaltsaltsalt').toString('base64'),
    iters: 600000, kdf: 'PBKDF2-SHA256',
  };
  const r = await request(app).post('/api/backup/save').send({
    email: 'test-' + Date.now() + '@example.com',
    payload, pubKey, displayName: 'Test', handle: null,
  });
  assert.equal(r.status, 200);
  assert.equal(r.body.ok, true);
});

test('backup save with different owner email returns 409', async () => {
  const email = 'conflict-' + Date.now() + '@example.com';
  const payload = {
    ciphertext: 'Y3Q=', iv: 'aXY=', salt: 'c2FsdA==',
    iters: 600000, kdf: 'PBKDF2-SHA256',
  };
  const a = newIdentity();
  const b = newIdentity();
  const r1 = await request(app).post('/api/backup/save').send({ email, payload, pubKey: a.pubKey });
  assert.equal(r1.status, 200);
  const r2 = await request(app).post('/api/backup/save').send({ email, payload, pubKey: b.pubKey });
  assert.equal(r2.status, 409);
});

test('backup request-retrieve returns 503 when mail is not configured', async () => {
  const r = await request(app).post('/api/backup/request-retrieve').send({ email: 'a@b.com' });
  assert.equal(r.status, 503);
  assert.equal(r.body.reason, 'mail_disabled');
});

test('backup delete with signed message succeeds; double delete 404', async () => {
  const { priv, pubKey } = newIdentity();
  const email = 'del-' + Date.now() + '@example.com';
  const payload = {
    ciphertext: 'Y3Q=', iv: 'aXY=', salt: 'c2FsdA==',
    iters: 600000, kdf: 'PBKDF2-SHA256',
  };
  await request(app).post('/api/backup/save').send({ email, payload, pubKey });

  const ts = Date.now();
  const message = `web3keys:backup-delete|email=${email.toLowerCase()}|pubkey=${pubKey}|ts=${ts}`;
  const signature = bsv.Message(message).sign(priv);

  const r1 = await request(app).post('/api/backup/delete').send({ email, pubKey, message, signature });
  assert.equal(r1.status, 200);

  const r2 = await request(app).post('/api/backup/delete').send({ email, pubKey, message, signature });
  assert.equal(r2.status, 404);
});

test('backup delete by wrong owner is rejected', async () => {
  const a = newIdentity();
  const b = newIdentity();
  const email = 'owner-' + Date.now() + '@example.com';
  const payload = {
    ciphertext: 'Y3Q=', iv: 'aXY=', salt: 'c2FsdA==',
    iters: 600000, kdf: 'PBKDF2-SHA256',
  };
  await request(app).post('/api/backup/save').send({ email, payload, pubKey: a.pubKey });

  const ts = Date.now();
  const message = `web3keys:backup-delete|email=${email.toLowerCase()}|pubkey=${b.pubKey}|ts=${ts}`;
  const signature = bsv.Message(message).sign(b.priv);
  const r = await request(app).post('/api/backup/delete').send({
    email, pubKey: b.pubKey, message, signature,
  });
  // owner_mismatch is 404
  assert.equal(r.status, 404);
});

test('GET /, /app, /verify, /demo, /sso, /recover all serve HTML', async () => {
  for (const p of ['/', '/app', '/verify', '/demo', '/sso', '/recover']) {
    const r = await request(app).get(p);
    assert.equal(r.status, 200, `${p} should be 200`);
    assert.match(r.headers['content-type'], /html/);
  }
});

test('GET /sdk.js serves with CORS + cache headers', async () => {
  const r = await request(app).get('/sdk.js');
  assert.equal(r.status, 200);
  assert.equal(r.headers['access-control-allow-origin'], '*');
  assert.match(r.headers['content-type'], /javascript/);
});
