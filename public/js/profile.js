import { canonicalize } from './attestations.js';

const HANDLE_RE = /^[a-z0-9](?:[a-z0-9_-]{1,30}[a-z0-9])?$/;

export function isValidHandle(s) {
  return typeof s === 'string' && HANDLE_RE.test(s);
}

export async function checkHandleAvailable(handle) {
  const h = String(handle || '').toLowerCase();
  if (!isValidHandle(h)) return { ok: false, reason: 'invalid' };
  const res = await fetch(`/api/paymail/check/${encodeURIComponent(h)}`);
  if (!res.ok) return { ok: false, reason: 'check_failed' };
  return res.json();
}

export function buildClaimMessage({ handle, pubKey, address, ts }) {
  return `web3keys:claim|handle=${handle.toLowerCase()}|pubkey=${pubKey}|address=${address}|ts=${ts}`;
}

export async function claimHandle({ handle, pubKey, address, displayName, signature, message }) {
  const res = await fetch('/api/paymail/claim', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ handle: handle.toLowerCase(), pubKey, address, displayName, signature, message }),
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    const reason = body?.reason || 'error';
    const messages = {
      taken: 'That handle is already taken.',
      invalid_handle: 'Invalid handle. Use 3–32 lowercase letters, digits, dashes, or underscores.',
      message_mismatch: 'Signature payload did not match the claimed handle.',
      timestamp_skew: 'Your clock is off — try again.',
      bad_signature: 'Signature did not verify.',
      bad_pubkey: 'The provided public key was not valid.',
      pubkey_address_mismatch: 'Public key and address do not match.',
    };
    throw new Error(messages[reason] || `Claim failed (${reason})`);
  }
  return body;
}

export async function fetchProfile(handle) {
  const res = await fetch(`/api/paymail/${encodeURIComponent(handle)}`);
  if (res.status === 404) return null;
  if (!res.ok) throw new Error('Profile fetch failed');
  return res.json();
}

// Resolve a subject "identifier" into a normalised { pubKey, handle?, address? }.
// Accepts:
//   - 66-char hex (compressed secp256k1 pubkey)         → assumed pubkey
//   - "alice" or "alice@web3keys.com"                   → handle lookup
export async function resolveSubject(input) {
  const raw = String(input || '').trim();
  if (!raw) throw new Error('Enter a handle or public key.');
  // Compressed pubkey hex?
  if (/^0[23][0-9a-fA-F]{64}$/.test(raw)) {
    return { pubKey: raw.toLowerCase() };
  }
  // Strip @web3keys.com suffix if present.
  const handle = raw.replace(/@web3keys\.com$/i, '').toLowerCase();
  if (!isValidHandle(handle)) throw new Error('That handle is not a valid Web3Keys handle.');
  const profile = await fetchProfile(handle);
  if (!profile) throw new Error(`No identity claimed for @${handle}.`);
  return { pubKey: profile.pubKey, handle: profile.handle, address: profile.address, displayName: profile.displayName };
}
