import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

export function createBackupStore(dataDir, pepper) {
  fs.mkdirSync(dataDir, { recursive: true });
  const file = path.join(dataDir, 'backups.json');

  if (!pepper || pepper.length < 32) {
    throw new Error('SERVER_PEPPER must be set to a strong random value (>=32 chars).');
  }

  function readSync() {
    try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
    catch { return { backups: {}, tokens: {} }; }
  }
  function writeSync(state) {
    const tmp = file + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(state, null, 2));
    fs.renameSync(tmp, file);
  }
  function hmac(value) {
    return crypto.createHmac('sha256', pepper).update(String(value)).digest('hex');
  }

  return {
    emailKey(email) {
      return hmac('email:' + String(email).trim().toLowerCase());
    },
    pubKeyHash(pubKey) {
      return hmac('pubkey:' + String(pubKey));
    },
    has(email) {
      const k = this.emailKey(email);
      return Boolean(readSync().backups[k]);
    },
    get(email) {
      const k = this.emailKey(email);
      const s = readSync();
      return s.backups[k] || null;
    },
    save({ email, payload, pubKey, displayName, handle }) {
      const k = this.emailKey(email);
      const s = readSync();
      const existing = s.backups[k] || {};
      // If a backup already exists, require that it was written for this same pubKey.
      // (Prevents one identity overwriting another's backup just by knowing the email.)
      if (existing.pubKeyHash && existing.pubKeyHash !== this.pubKeyHash(pubKey)) {
        throw new Error('A different identity already has a backup under this email.');
      }
      s.backups[k] = {
        v: 1,
        payload, // { ciphertext, iv, salt, iters, kdf }
        pubKeyHash: this.pubKeyHash(pubKey),
        hint: {
          handle: handle || null,
          displayName: displayName || null,
          createdAt: existing.createdAt || new Date().toISOString(),
        },
        createdAt: existing.createdAt || new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        lastRetrievedAt: existing.lastRetrievedAt || null,
        retrievals: existing.retrievals || 0,
      };
      writeSync(s);
      return { ok: true, createdAt: s.backups[k].createdAt, updatedAt: s.backups[k].updatedAt };
    },
    issueToken({ email, ip }) {
      const emailHash = this.emailKey(email);
      const s = readSync();
      if (!s.backups[emailHash]) {
        // Always succeed at issuing — we don't reveal whether the email has a backup.
        // But don't actually persist a token; caller decides not to send mail.
        return { token: null, exists: false };
      }
      const token = crypto.randomBytes(32).toString('hex');
      const now = Date.now();
      s.tokens[token] = {
        emailHash,
        issuedAt: new Date(now).toISOString(),
        expiresAt: new Date(now + 15 * 60 * 1000).toISOString(),
        used: false,
        usedAt: null,
        ip: ip || null,
      };
      this._gcTokens(s);
      writeSync(s);
      return { token, exists: true };
    },
    inspectToken(token) {
      const s = readSync();
      const t = s.tokens[token];
      if (!t) return { valid: false, reason: 'unknown_token' };
      if (t.used) return { valid: false, reason: 'used' };
      if (new Date(t.expiresAt).getTime() < Date.now()) return { valid: false, reason: 'expired' };
      const b = s.backups[t.emailHash];
      if (!b) return { valid: false, reason: 'no_backup' };
      return { valid: true, hint: b.hint, payloadCreatedAt: b.createdAt, payloadUpdatedAt: b.updatedAt };
    },
    consumeToken(token) {
      const s = readSync();
      const t = s.tokens[token];
      if (!t) return { valid: false, reason: 'unknown_token' };
      if (t.used) return { valid: false, reason: 'used' };
      if (new Date(t.expiresAt).getTime() < Date.now()) return { valid: false, reason: 'expired' };
      const b = s.backups[t.emailHash];
      if (!b) return { valid: false, reason: 'no_backup' };
      // Mark used, record retrieval.
      t.used = true;
      t.usedAt = new Date().toISOString();
      b.lastRetrievedAt = t.usedAt;
      b.retrievals = (b.retrievals || 0) + 1;
      writeSync(s);
      return { valid: true, payload: b.payload, hint: b.hint };
    },
    deleteByOwner({ email, pubKey }) {
      const k = this.emailKey(email);
      const s = readSync();
      const b = s.backups[k];
      if (!b) return { deleted: false, reason: 'not_found' };
      if (b.pubKeyHash !== this.pubKeyHash(pubKey)) {
        return { deleted: false, reason: 'owner_mismatch' };
      }
      delete s.backups[k];
      // Also invalidate any active tokens for this email.
      for (const [tok, t] of Object.entries(s.tokens)) {
        if (t.emailHash === k) delete s.tokens[tok];
      }
      writeSync(s);
      return { deleted: true };
    },
    _gcTokens(state) {
      const now = Date.now();
      let removed = 0;
      for (const [tok, t] of Object.entries(state.tokens)) {
        if (t.used || new Date(t.expiresAt).getTime() < now - 60 * 60 * 1000) {
          delete state.tokens[tok];
          removed++;
        }
      }
      return removed;
    },
  };
}
