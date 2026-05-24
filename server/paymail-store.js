import fs from 'node:fs';
import path from 'node:path';

export const HANDLE_RE = /^[a-z0-9](?:[a-z0-9_-]{1,30}[a-z0-9])?$/;

// Reserved handles. Squat targets, internal routes, and identity-sensitive names.
const RESERVED = new Set([
  // Internal / system
  'admin', 'administrator', 'root', 'system', 'webmaster', 'support', 'help',
  'about', 'contact', 'legal', 'privacy', 'terms', 'security', 'abuse', 'noreply',
  // Product routes (mirror server.js so handles can't shadow real URLs)
  'app', 'api', 'sdk', 'sso', 'verify', 'recover', 'demo', 'u', 'healthz',
  'claim', 'docs', 'developers', 'developer', 'dev',
  // Brand / company
  'web3keys', 'w3k', 'paymail', 'smartledger',
  // Common-noun squat targets
  'wallet', 'login', 'signin', 'signup', 'register', 'account', 'accounts',
  'me', 'you', 'i', 'we', 'us', 'team', 'official', 'verified', 'identity',
  // Operations
  'noreply', 'no-reply', 'mailer', 'postmaster', 'hostmaster',
  // High-value generics
  'crypto', 'bitcoin', 'btc', 'bsv', 'eth', 'ethereum', 'nft',
  'ai', 'gpt', 'claude', 'anthropic', 'openai',
  // Single-character + ultra-short
  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
  'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
]);

export function createPaymailStore(dataDir) {
  fs.mkdirSync(dataDir, { recursive: true });
  const file = path.join(dataDir, 'paymails.json');

  function readSync() {
    try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
    catch { return { handles: {}, byPubKey: {} }; }
  }
  function writeSync(state) {
    const tmp = file + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(state, null, 2));
    fs.renameSync(tmp, file);
  }

  return {
    isShapeValid(handle) {
      return typeof handle === 'string' && HANDLE_RE.test(handle);
    },
    isReserved(handle) {
      return RESERVED.has(String(handle || '').toLowerCase());
    },
    // Kept for routes/callers that combine all three checks.
    isValid(handle) {
      return this.isShapeValid(handle) && !this.isReserved(handle);
    },
    isAvailable(handle) {
      const h = String(handle || '').toLowerCase();
      if (!this.isValid(h)) return false;
      const state = readSync();
      return !state.handles[h];
    },
    availabilityReason(handle) {
      const h = String(handle || '').toLowerCase();
      if (!this.isShapeValid(h)) return 'invalid';
      if (this.isReserved(h)) return 'reserved';
      const state = readSync();
      if (state.handles[h]) return 'taken';
      return null;
    },
    get(handle) {
      const state = readSync();
      return state.handles[String(handle || '').toLowerCase()] || null;
    },
    getByPubKey(pubKey) {
      const state = readSync();
      const handle = state.byPubKey[pubKey];
      return handle ? state.handles[handle] : null;
    },
    // Idempotent if pubKey already owns the handle.
    claim({ handle, pubKey, address, displayName, claimedAt }) {
      const h = String(handle).toLowerCase();
      if (!this.isValid(h)) throw new Error('Invalid handle.');
      const state = readSync();
      const existing = state.handles[h];
      if (existing && existing.pubKey !== pubKey) {
        throw new Error('Handle is already taken.');
      }
      // If this pubKey already owns a different handle, release that first.
      const prior = state.byPubKey[pubKey];
      if (prior && prior !== h) {
        delete state.handles[prior];
      }
      const record = {
        handle: h,
        pubKey,
        address,
        displayName: String(displayName || '').slice(0, 80),
        claimedAt: claimedAt || new Date().toISOString(),
      };
      state.handles[h] = record;
      state.byPubKey[pubKey] = h;
      writeSync(state);
      return record;
    },
  };
}
