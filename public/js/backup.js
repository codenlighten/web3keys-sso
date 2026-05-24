import { randomBytes, bytesToBase64, base64ToBytes, kekFromPassword, wrap, unwrap } from './crypto.js';

const ITERS = 600000;
const KDF = 'PBKDF2-SHA256';

// Build the plaintext backup payload that gets AES-GCM-wrapped.
export function buildBackupPlaintext({ mnemonic, vault }) {
  if (!mnemonic) throw new Error('mnemonic is required to build a backup');
  return JSON.stringify({
    v: 1,
    createdAt: new Date().toISOString(),
    identity: {
      pubKey: vault.pubKey,
      address: vault.address,
      handle: vault.handle || null,
      displayName: vault.displayName || null,
    },
    mnemonic,
    claims: vault.claims || [],
  });
}

// Encrypt the backup with a passphrase-derived AES-GCM key.
export async function encryptBackup(plaintext, passphrase) {
  const salt = randomBytes(16);
  const kek = await kekFromPassword(passphrase, salt, ITERS);
  const wrapped = await wrap(kek, plaintext); // { iv, ct }
  return {
    ciphertext: wrapped.ct,
    iv: wrapped.iv,
    salt: bytesToBase64(salt),
    iters: ITERS,
    kdf: KDF,
  };
}

export async function decryptBackup(payload, passphrase) {
  const salt = base64ToBytes(payload.salt);
  const kek = await kekFromPassword(passphrase, salt, payload.iters || ITERS);
  const plaintext = await unwrap(kek, { iv: payload.iv, ct: payload.ciphertext });
  return JSON.parse(plaintext);
}

// ---- API wrappers ----

export async function saveBackup({ email, payload, pubKey, displayName, handle }) {
  const res = await fetch('/api/backup/save', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, payload, pubKey, displayName, handle }),
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    const reasons = {
      invalid_email: 'That email looks invalid.',
      invalid_pubkey: 'Public key did not validate.',
      invalid_payload: 'Backup payload is malformed.',
      too_large: 'Backup is too large.',
      owner_conflict: 'A different Web3Keys identity already has a backup under this email. Use a different email.',
      backup_disabled: 'Cloud backup is not enabled on this server.',
    };
    throw new Error(reasons[body.reason] || `Backup save failed (${body.reason || res.status}).`);
  }
  return body;
}

export async function requestRetrieve(email) {
  const res = await fetch('/api/backup/request-retrieve', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email }),
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    const reasons = {
      invalid_email: 'That email looks invalid.',
      mail_disabled: 'Email delivery is not configured on this server.',
      backup_disabled: 'Cloud backup is not enabled on this server.',
    };
    throw new Error(reasons[body.reason] || `Request failed (${body.reason || res.status}).`);
  }
  return body;
}

export async function inspectToken(token) {
  const res = await fetch(`/api/backup/retrieve?token=${encodeURIComponent(token)}`);
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    const reasons = {
      invalid_token: 'This link is invalid.',
      unknown_token: 'This link is not recognized.',
      used: 'This link has already been used.',
      expired: 'This link has expired.',
      no_backup: 'No backup is associated with this link.',
    };
    throw new Error(reasons[body.reason] || `Token check failed (${body.reason || res.status}).`);
  }
  return body;
}

export async function consumeToken(token) {
  const res = await fetch(`/api/backup/retrieve?token=${encodeURIComponent(token)}&confirm=1`);
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    const reasons = {
      invalid_token: 'This link is invalid.',
      unknown_token: 'This link is not recognized.',
      used: 'This link has already been used.',
      expired: 'This link has expired.',
      no_backup: 'No backup is associated with this link.',
    };
    throw new Error(reasons[body.reason] || `Retrieval failed (${body.reason || res.status}).`);
  }
  return body;
}

export async function deleteBackup({ email, pubKey, message, signature }) {
  const res = await fetch('/api/backup/delete', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, pubKey, message, signature }),
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    const reasons = {
      not_found: 'No backup found for that email.',
      owner_mismatch: 'This identity does not own that backup.',
      bad_signature: 'Signature did not verify.',
      message_mismatch: 'Signed message did not match the request.',
      timestamp_skew: 'Your clock is off — try again.',
    };
    throw new Error(reasons[body.reason] || `Delete failed (${body.reason || res.status}).`);
  }
  return body;
}

export function buildDeleteMessage({ email, pubKey, ts }) {
  return `web3keys:backup-delete|email=${email.toLowerCase()}|pubkey=${pubKey}|ts=${ts}`;
}
