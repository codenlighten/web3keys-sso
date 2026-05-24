const enc = new TextEncoder();
const dec = new TextDecoder();

export function randomBytes(n) {
  return crypto.getRandomValues(new Uint8Array(n));
}

export function bytesToBase64(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(bin);
}

export function base64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function zero(buf) {
  if (buf instanceof Uint8Array) buf.fill(0);
}

async function importKekRaw(rawBytes, usages) {
  return crypto.subtle.importKey('raw', rawBytes, { name: 'AES-GCM', length: 256 }, false, usages);
}

// PRF output (32 bytes) → AES-256-GCM key via HKDF-SHA-256 with a domain-separating info string.
export async function kekFromPrf(prfBytes, info) {
  const baseKey = await crypto.subtle.importKey('raw', prfBytes, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: enc.encode(info) },
    baseKey,
    256
  );
  return importKekRaw(new Uint8Array(bits), ['encrypt', 'decrypt']);
}

// Password → AES-256-GCM key via PBKDF2-SHA-256.
export async function kekFromPassword(password, salt, iterations = 600000) {
  const baseKey = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function wrap(kek, plaintextStr) {
  const iv = randomBytes(12);
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    kek,
    enc.encode(plaintextStr)
  );
  return { iv: bytesToBase64(iv), ct: bytesToBase64(new Uint8Array(ct)) };
}

export async function unwrap(kek, wrapped) {
  const iv = base64ToBytes(wrapped.iv);
  const ct = base64ToBytes(wrapped.ct);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, kek, ct);
  return dec.decode(pt);
}
