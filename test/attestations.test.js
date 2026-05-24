import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

import {
  canonicalize, digestHex,
  buildAttestation, buildSdAttestation, verifyAttestation,
  buildPresentation, buildClaimPackage, detectShape,
  verifyDisclosures, commitField,
  CLAIM_TYPES, CONTEXT, SIG_ALG, DISCLOSURE,
  KIND_PACKAGE, KIND_PRESENTATION,
} from '../public/js/attestations.js';

const require = createRequire(import.meta.url);
const bsv = require('@smartledger/bsv');
const nodeCrypto = await import('node:crypto');

function signAttestation(unsigned, priv) {
  const canon = canonicalize(unsigned);
  const dig = nodeCrypto.createHash('sha256').update(canon).digest();
  const sig = bsv.crypto.ECDSA.sign(dig, priv);
  return { ...unsigned, signature: { alg: SIG_ALG, value: sig.toString() } };
}

test('canonicalize sorts keys deterministically', () => {
  const a = canonicalize({ b: 2, a: 1, c: { y: 2, x: 1 } });
  const b = canonicalize({ a: 1, c: { x: 1, y: 2 }, b: 2 });
  assert.equal(a, b);
});

test('canonicalize omits undefined fields', () => {
  const out = canonicalize({ a: 1, b: undefined, c: 'x' });
  assert.equal(out, '{"a":1,"c":"x"}');
});

test('canonicalize handles arrays and nested objects', () => {
  const out = canonicalize({ list: [{ y: 2, x: 1 }, 'z'] });
  assert.equal(out, '{"list":[{"x":1,"y":2},"z"]}');
});

test('digestHex excludes the signature field', async () => {
  const obj = { v: 1, x: 1, signature: { alg: 'foo', value: 'bar' } };
  const objNoSig = { v: 1, x: 1 };
  const h1 = await digestHex(obj);
  const h2 = await digestHex(objNoSig);
  assert.equal(h1, h2);
});

test('buildAttestation rejects missing fields', () => {
  assert.throws(() => buildAttestation({ claimType: 'name', issuer: { pubKey: 'p' }, claim: { value: 'x' } }), /subject/);
});

test('verifyAttestation passes for a well-signed claim', async () => {
  const priv = new bsv.PrivateKey();
  const pub = priv.toPublicKey().toString('hex');
  const unsigned = buildAttestation({
    claimType: 'name',
    subject: { pubKey: pub }, issuer: { pubKey: pub },
    claim: { value: 'Alice' },
  });
  const signed = signAttestation(unsigned, priv);
  const r = await verifyAttestation(signed, bsv);
  assert.equal(r.verified, true);
});

test('verifyAttestation fails when signature is mutated', async () => {
  const priv = new bsv.PrivateKey();
  const unsigned = buildAttestation({
    claimType: 'name',
    subject: { pubKey: priv.toPublicKey().toString('hex') },
    issuer: { pubKey: priv.toPublicKey().toString('hex') },
    claim: { value: 'Alice' },
  });
  const signed = signAttestation(unsigned, priv);
  // Flip one byte of the claim payload
  signed.claim.value = 'Bob';
  const r = await verifyAttestation(signed, bsv);
  assert.equal(r.verified, false);
});

test('verifyAttestation flags expired', async () => {
  const priv = new bsv.PrivateKey();
  const unsigned = buildAttestation({
    claimType: 'name',
    subject: { pubKey: priv.toPublicKey().toString('hex') },
    issuer: { pubKey: priv.toPublicKey().toString('hex') },
    claim: { value: 'Alice' },
    expiresAt: new Date(Date.now() - 60_000).toISOString(),
  });
  const signed = signAttestation(unsigned, priv);
  const r = await verifyAttestation(signed, bsv);
  assert.equal(r.verified, true);
  assert.equal(r.expired, true);
});

test('commitField is deterministic for same (salt, value)', async () => {
  const a = await commitField('abc', 'hello');
  const b = await commitField('abc', 'hello');
  assert.equal(a, b);
  assert.match(a, /^[0-9a-f]{64}$/);
});

test('commitField differs for different salts', async () => {
  const a = await commitField('s1', 'hello');
  const b = await commitField('s2', 'hello');
  assert.notEqual(a, b);
});

test('buildSdAttestation produces commitments + openings for each field', async () => {
  const priv = new bsv.PrivateKey();
  const { unsigned, openings } = await buildSdAttestation({
    claimType: 'social',
    subject: { pubKey: priv.toPublicKey().toString('hex') },
    issuer: { pubKey: priv.toPublicKey().toString('hex') },
    claim: { platform: 'github', handle: 'alice' },
  });
  assert.deepEqual(unsigned.claimSchema.sort(), ['handle', 'platform']);
  assert.equal(unsigned.disclosure, DISCLOSURE);
  assert.equal(Object.keys(openings).length, 2);
  assert.match(unsigned.claimCommitments.platform, /^[0-9a-f]{64}$/);
});

test('verifyDisclosures succeeds for the issuer-provided openings', async () => {
  const priv = new bsv.PrivateKey();
  const { unsigned, openings } = await buildSdAttestation({
    claimType: 'name',
    subject: { pubKey: priv.toPublicKey().toString('hex') },
    issuer: { pubKey: priv.toPublicKey().toString('hex') },
    claim: { value: 'Alice' },
  });
  const r = await verifyDisclosures(unsigned, openings);
  assert.equal(r.ok, true);
});

test('verifyDisclosures fails when a salt is tampered', async () => {
  const priv = new bsv.PrivateKey();
  const { unsigned, openings } = await buildSdAttestation({
    claimType: 'name',
    subject: { pubKey: priv.toPublicKey().toString('hex') },
    issuer: { pubKey: priv.toPublicKey().toString('hex') },
    claim: { value: 'Alice' },
  });
  const tampered = { value: { salt: 'deadbeef'.repeat(8), value: 'Alice' } };
  const r = await verifyDisclosures(unsigned, tampered);
  assert.equal(r.ok, false);
});

test('verifyDisclosures fails when value is tampered', async () => {
  const priv = new bsv.PrivateKey();
  const { unsigned, openings } = await buildSdAttestation({
    claimType: 'name',
    subject: { pubKey: priv.toPublicKey().toString('hex') },
    issuer: { pubKey: priv.toPublicKey().toString('hex') },
    claim: { value: 'Alice' },
  });
  const tampered = { value: { salt: openings.value.salt, value: 'Bob' } };
  const r = await verifyDisclosures(unsigned, tampered);
  assert.equal(r.ok, false);
});

test('detectShape distinguishes the three serialized forms', async () => {
  const priv = new bsv.PrivateKey();
  const unsigned = buildAttestation({
    claimType: 'name',
    subject: { pubKey: priv.toPublicKey().toString('hex') },
    issuer: { pubKey: priv.toPublicKey().toString('hex') },
    claim: { value: 'x' },
  });
  const signed = signAttestation(unsigned, priv);
  assert.equal(detectShape(signed), 'attestation');
  assert.equal(detectShape(buildClaimPackage({ attestation: signed, openings: {} })), 'package');
  assert.equal(detectShape(buildPresentation({ attestation: signed, openings: {}, fieldsToReveal: [] })), 'presentation');
  assert.equal(detectShape({ random: 'stuff' }), 'unknown');
  assert.equal(detectShape(null), 'unknown');
});

test('presentation reveals only requested fields', async () => {
  const priv = new bsv.PrivateKey();
  const { unsigned, openings } = await buildSdAttestation({
    claimType: 'social',
    subject: { pubKey: priv.toPublicKey().toString('hex') },
    issuer: { pubKey: priv.toPublicKey().toString('hex') },
    claim: { platform: 'github', handle: 'alice' },
  });
  const signed = signAttestation(unsigned, priv);
  const pres = buildPresentation({
    attestation: signed, openings,
    fieldsToReveal: ['platform'],
    audience: 'recruiter.example.com',
  });
  assert.equal(detectShape(pres), 'presentation');
  assert.deepEqual(Object.keys(pres.disclosures), ['platform']);
  assert.equal(pres.audience, 'recruiter.example.com');
});

test('CLAIM_TYPES include the documented set', () => {
  for (const k of ['name', 'email', 'domain', 'social', 'ownership', 'custom']) {
    assert.ok(CLAIM_TYPES[k], `missing type ${k}`);
    assert.ok(Array.isArray(CLAIM_TYPES[k].fields));
  }
});

test('CONTEXT and SIG_ALG are stable constants', () => {
  assert.equal(CONTEXT, 'https://web3keys.com/contexts/v1');
  assert.equal(SIG_ALG, 'ECDSA-SHA256-secp256k1');
  assert.equal(KIND_PACKAGE, 'web3keys:claim-package');
  assert.equal(KIND_PRESENTATION, 'web3keys:presentation');
});
