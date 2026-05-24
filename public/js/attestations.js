// Attestations: self-issued or third-party signed claims about an identity.
//
// Shape:
// {
//   v: 1,
//   id: "<uuid>",
//   context: "https://web3keys.com/contexts/v1",
//   type: "selfclaim" | "endorsement",
//   claimType: "name" | "email" | "domain" | "social" | "ownership" | "custom",
//   subject: { pubKey, handle?, address? },
//   issuer:  { pubKey, handle?, address? },
//   claim:   { ...typed payload },
//   issuedAt: "ISO 8601",
//   expiresAt?: "ISO 8601",
//   signature: { alg: "ECDSA-SHA256-secp256k1", value: "<DER hex>" }
// }
//
// Canonical JSON: keys sorted lexicographically at every level, undefined fields
// omitted, no whitespace, signature field excluded when hashing.

export const CONTEXT = 'https://web3keys.com/contexts/v1';
export const SIG_ALG = 'ECDSA-SHA256-secp256k1';

export function canonicalize(value) {
  if (value === null) return 'null';
  if (Array.isArray(value)) return '[' + value.map(canonicalize).join(',') + ']';
  if (typeof value === 'object') {
    const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
    return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalize(value[k])).join(',') + '}';
  }
  return JSON.stringify(value);
}

export async function digestBytes(canonicalStr) {
  const enc = new TextEncoder().encode(canonicalStr);
  const buf = await crypto.subtle.digest('SHA-256', enc);
  return new Uint8Array(buf);
}

function bytesToHex(u8) {
  return Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('');
}

export async function digestHex(attestation) {
  const { signature, ...rest } = attestation;
  const canon = canonicalize(rest);
  const d = await digestBytes(canon);
  return bytesToHex(d);
}

// Build an unsigned attestation. Caller signs it with signAttestation() once they
// have unlocked the WIF (or supplies a precomputed signature).
export function buildAttestation({ type, claimType, subject, issuer, claim, expiresAt }) {
  if (!subject?.pubKey) throw new Error('subject.pubKey is required');
  if (!issuer?.pubKey)  throw new Error('issuer.pubKey is required');
  if (!claimType)       throw new Error('claimType is required');
  if (!claim || typeof claim !== 'object') throw new Error('claim payload is required');

  return {
    v: 1,
    id: crypto.randomUUID(),
    context: CONTEXT,
    type: type || (subject.pubKey === issuer.pubKey ? 'selfclaim' : 'endorsement'),
    claimType,
    subject,
    issuer,
    claim,
    issuedAt: new Date().toISOString(),
    ...(expiresAt ? { expiresAt } : {}),
  };
}

// Verify an attestation. Returns { verified: bool, reason?: string, expired?: bool }.
export async function verifyAttestation(attestation, bsv) {
  try {
    if (!attestation || typeof attestation !== 'object') return { verified: false, reason: 'not_an_object' };
    if (attestation.v !== 1) return { verified: false, reason: 'unsupported_version' };
    if (attestation.context !== CONTEXT) return { verified: false, reason: 'unknown_context' };
    if (!attestation.signature?.value) return { verified: false, reason: 'no_signature' };
    if (attestation.signature.alg !== SIG_ALG) return { verified: false, reason: 'unknown_alg' };
    if (!attestation.issuer?.pubKey) return { verified: false, reason: 'no_issuer' };

    const hex = await digestHex(attestation);
    const Buffer = bsv.deps.Buffer;
    const digest = Buffer.from(hex, 'hex');
    const sig = bsv.crypto.Signature.fromString(attestation.signature.value);
    const pub = bsv.PublicKey.fromString(attestation.issuer.pubKey);
    const ok = bsv.crypto.ECDSA.verify(digest, sig, pub);

    let expired = false;
    if (attestation.expiresAt) {
      expired = new Date(attestation.expiresAt).getTime() < Date.now();
    }
    return { verified: !!ok, expired, reason: ok ? null : 'bad_signature' };
  } catch (e) {
    return { verified: false, reason: 'parse_error', error: e?.message };
  }
}

// Built-in claim types and how to display them. Each entry exposes its fields,
// a label, and a renderer for human-readable summary.
export const CLAIM_TYPES = {
  name: {
    label: 'My name',
    fields: [
      { key: 'value', label: 'Full name', type: 'text', required: true },
    ],
    summary: (c) => c.value,
  },
  email: {
    label: 'My email',
    fields: [
      { key: 'value', label: 'Email address', type: 'email', required: true },
    ],
    summary: (c) => c.value,
  },
  domain: {
    label: 'I control a domain',
    fields: [
      { key: 'value', label: 'Domain', type: 'text', required: true, placeholder: 'example.com' },
    ],
    summary: (c) => c.value,
  },
  social: {
    label: 'My social account',
    fields: [
      { key: 'platform', label: 'Platform', type: 'text', required: true, placeholder: 'x.com / github / instagram' },
      { key: 'handle', label: 'Handle on that platform', type: 'text', required: true, placeholder: '@username' },
    ],
    summary: (c) => `${c.handle} on ${c.platform}`,
  },
  ownership: {
    label: 'I own / authored this',
    fields: [
      { key: 'kind', label: 'What kind of thing?', type: 'text', required: true, placeholder: 'image / article / song / artwork' },
      { key: 'sha256', label: 'SHA-256 of the content (hex)', type: 'text', required: true, placeholder: '64 hex chars' },
      { key: 'title', label: 'Title (optional)', type: 'text' },
      { key: 'url', label: 'URL (optional)', type: 'url' },
    ],
    summary: (c) => `${c.kind}${c.title ? ` "${c.title}"` : ''}`,
  },
  custom: {
    label: 'Custom JSON',
    fields: [
      { key: 'json', label: 'Claim payload (JSON)', type: 'json', required: true, placeholder: '{ "anything": "you like" }' },
    ],
    summary: (c) => 'Custom claim',
  },
};
