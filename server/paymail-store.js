import fs from 'node:fs';
import path from 'node:path';

export const HANDLE_RE = /^[a-z0-9](?:[a-z0-9_-]{1,30}[a-z0-9])?$/;

// A small set of reserved handles. Real list would live in config.
const RESERVED = new Set([
  'admin', 'root', 'support', 'help', 'about', 'system', 'web3keys', 'paymail',
  'verify', 'claim', 'api', 'sdk', 'docs', 'wallet', 'login', 'signin', 'signup',
  'me', 'you', 'i', 'we', 'us', 'team', 'official',
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
    isValid(handle) {
      return typeof handle === 'string'
        && HANDLE_RE.test(handle)
        && !RESERVED.has(handle);
    },
    isAvailable(handle) {
      const h = String(handle || '').toLowerCase();
      if (!this.isValid(h)) return false;
      const state = readSync();
      return !state.handles[h];
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
