import express from 'express';
import cors from 'cors';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import 'dotenv/config';

import { createPaymailStore, HANDLE_RE } from './server/paymail-store.js';
import { renderProfilePage, renderNotFoundPage } from './server/pages.js';
import { createBackupStore } from './server/backup-store.js';
import { isMailConfigured, sendRecoveryLink } from './server/mailer.js';
import rateLimit from 'express-rate-limit';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const bsv = require('@smartledger/bsv');

const app = express();
const PORT = process.env.PORT || 8787;
const HOST = process.env.HOST || '127.0.0.1';
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');

const paymail = createPaymailStore(DATA_DIR);
const PEPPER = process.env.SERVER_PEPPER;
const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL || 'https://web3keys.com';
let backup = null;
if (PEPPER) {
  backup = createBackupStore(DATA_DIR, PEPPER);
} else {
  console.warn('SERVER_PEPPER not set — cloud-backup routes will reject requests.');
}

const requireBackupStore = (_req, res, next) => {
  if (!backup) return res.status(503).json({ ok: false, reason: 'backup_disabled' });
  next();
};
const requireMail = (_req, res, next) => {
  if (!isMailConfigured()) return res.status(503).json({ ok: false, reason: 'mail_disabled' });
  next();
};

app.set('trust proxy', 1); // honor X-Forwarded-For from nginx
app.disable('x-powered-by');
app.use(cors());
app.use(express.json({ limit: '128kb' }));

app.use('/vendor', express.static(path.join(__dirname, 'node_modules/@smartledger/bsv'), {
  maxAge: '1h',
}));

app.get('/healthz', (_req, res) => res.json({ ok: true }));

// ---- Paymail registry ----

const limiterPaymailClaim = rateLimit({ windowMs: 60 * 60 * 1000, max: 12, standardHeaders: true });

app.get('/api/paymail/check/:handle', (req, res) => {
  const h = String(req.params.handle || '').toLowerCase();
  if (!paymail.isShapeValid(h)) {
    return res.status(400).json({ ok: false, reason: 'invalid' });
  }
  const reason = paymail.availabilityReason(h); // 'reserved' | 'taken' | null
  return res.json({ ok: true, handle: h, available: !reason, reason: reason || undefined });
});

app.get('/api/paymail/:handle', (req, res) => {
  const record = paymail.get(req.params.handle);
  if (!record) return res.status(404).json({ ok: false, reason: 'not_found' });
  return res.json({ ok: true, ...record });
});

app.post('/api/paymail/claim', limiterPaymailClaim, (req, res) => {
  try {
    const { handle, pubKey, address, displayName, message, signature } = req.body || {};

    if (typeof handle !== 'string' || typeof pubKey !== 'string' || typeof address !== 'string'
        || typeof message !== 'string' || typeof signature !== 'string') {
      return res.status(400).json({ ok: false, reason: 'bad_request' });
    }

    const h = handle.toLowerCase();
    if (!paymail.isValid(h)) {
      return res.status(400).json({ ok: false, reason: 'invalid_handle' });
    }

    // Message must commit to handle + pubKey + a recent timestamp (5 min window).
    const m = message.match(/^web3keys:claim\|handle=([^|]+)\|pubkey=([^|]+)\|address=([^|]+)\|ts=(\d+)$/);
    if (!m || m[1] !== h || m[2] !== pubKey || m[3] !== address) {
      return res.status(400).json({ ok: false, reason: 'message_mismatch' });
    }
    const ts = Number(m[4]);
    const skew = Math.abs(Date.now() - ts);
    if (!Number.isFinite(ts) || skew > 5 * 60 * 1000) {
      return res.status(400).json({ ok: false, reason: 'timestamp_skew' });
    }

    // Verify the BSV-message signature against the claimed address.
    let verified = false;
    try {
      verified = bsv.Message(message).verify(address, signature);
    } catch (e) {
      verified = false;
    }
    if (!verified) return res.status(401).json({ ok: false, reason: 'bad_signature' });

    // Verify the claimed pubKey actually maps to the address.
    let pubAddress;
    try {
      pubAddress = bsv.Address.fromPublicKey(bsv.PublicKey.fromString(pubKey)).toString();
    } catch {
      return res.status(400).json({ ok: false, reason: 'bad_pubkey' });
    }
    if (pubAddress !== address) {
      return res.status(400).json({ ok: false, reason: 'pubkey_address_mismatch' });
    }

    const record = paymail.claim({ handle: h, pubKey, address, displayName, claimedAt: new Date().toISOString() });
    return res.json({ ok: true, ...record });
  } catch (err) {
    const msg = err?.message || 'error';
    if (msg.includes('already taken')) return res.status(409).json({ ok: false, reason: 'taken' });
    if (msg.includes('Invalid handle')) return res.status(400).json({ ok: false, reason: 'invalid_handle' });
    return res.status(500).json({ ok: false, reason: 'server_error' });
  }
});

// ---- Cloud backup ----

const limiterSave = rateLimit({ windowMs: 60 * 60 * 1000, max: 30, standardHeaders: true });
const limiterRequest = rateLimit({ windowMs: 60 * 60 * 1000, max: 8, standardHeaders: true });
const limiterRetrieve = rateLimit({ windowMs: 60 * 60 * 1000, max: 40, standardHeaders: true });

function isValidEmail(s) {
  return typeof s === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s) && s.length <= 254;
}

app.post('/api/backup/save', requireBackupStore, limiterSave, (req, res) => {
  try {
    const { email, payload, pubKey, displayName, handle } = req.body || {};
    if (!isValidEmail(email)) return res.status(400).json({ ok: false, reason: 'invalid_email' });
    if (typeof pubKey !== 'string' || !/^0[23][0-9a-fA-F]{64}$/.test(pubKey)) {
      return res.status(400).json({ ok: false, reason: 'invalid_pubkey' });
    }
    if (!payload || typeof payload !== 'object') return res.status(400).json({ ok: false, reason: 'invalid_payload' });
    const required = ['ciphertext', 'iv', 'salt', 'iters', 'kdf'];
    for (const k of required) {
      if (payload[k] == null) return res.status(400).json({ ok: false, reason: 'invalid_payload', missing: k });
    }
    // Hard cap on ciphertext size to prevent abuse.
    const totalSize = JSON.stringify(payload).length;
    if (totalSize > 64 * 1024) return res.status(413).json({ ok: false, reason: 'too_large' });

    const result = backup.save({ email, payload, pubKey, displayName, handle });
    res.json({ ok: true, ...result });
  } catch (err) {
    const m = err?.message || 'error';
    if (m.includes('already has a backup')) return res.status(409).json({ ok: false, reason: 'owner_conflict' });
    console.error('backup/save:', err);
    res.status(500).json({ ok: false, reason: 'server_error' });
  }
});

app.post('/api/backup/request-retrieve', requireBackupStore, requireMail, limiterRequest, async (req, res) => {
  // Always respond identically whether or not a backup exists, so the API does not
  // confirm or deny membership for arbitrary email lookups.
  try {
    const { email } = req.body || {};
    if (!isValidEmail(email)) return res.status(400).json({ ok: false, reason: 'invalid_email' });
    const ip = req.ip;
    const { token, exists } = backup.issueToken({ email, ip });
    if (exists && token) {
      const link = `${PUBLIC_BASE_URL}/recover?token=${encodeURIComponent(token)}`;
      const rec = backup.get(email);
      const hint = rec?.hint?.handle ? `@${rec.hint.handle}` : (rec?.hint?.displayName || null);
      try {
        await sendRecoveryLink({ email, link, hint });
      } catch (mailErr) {
        console.error('backup/request-retrieve mail failed:', mailErr?.message || mailErr);
        // Don't leak whether the email failed; still respond ok.
      }
    }
    res.json({ ok: true });
  } catch (err) {
    console.error('backup/request-retrieve:', err);
    res.status(500).json({ ok: false, reason: 'server_error' });
  }
});

app.get('/api/backup/retrieve', requireBackupStore, limiterRetrieve, (req, res) => {
  const token = String(req.query.token || '');
  const confirm = req.query.confirm === '1';
  if (!/^[0-9a-f]{64}$/.test(token)) {
    return res.status(400).json({ ok: false, reason: 'invalid_token' });
  }
  if (!confirm) {
    const ins = backup.inspectToken(token);
    if (!ins.valid) return res.status(400).json({ ok: false, reason: ins.reason });
    return res.json({ ok: true, hint: ins.hint, payloadCreatedAt: ins.payloadCreatedAt, payloadUpdatedAt: ins.payloadUpdatedAt });
  }
  const out = backup.consumeToken(token);
  if (!out.valid) return res.status(400).json({ ok: false, reason: out.reason });
  res.json({ ok: true, payload: out.payload, hint: out.hint });
});

app.post('/api/backup/delete', requireBackupStore, (req, res) => {
  try {
    const { email, pubKey, message, signature } = req.body || {};
    if (!isValidEmail(email)) return res.status(400).json({ ok: false, reason: 'invalid_email' });
    if (typeof pubKey !== 'string' || typeof message !== 'string' || typeof signature !== 'string') {
      return res.status(400).json({ ok: false, reason: 'bad_request' });
    }
    const m = message.match(/^web3keys:backup-delete\|email=([^|]+)\|pubkey=([^|]+)\|ts=(\d+)$/);
    if (!m || m[1].toLowerCase() !== email.toLowerCase() || m[2] !== pubKey) {
      return res.status(400).json({ ok: false, reason: 'message_mismatch' });
    }
    const ts = Number(m[3]);
    if (!Number.isFinite(ts) || Math.abs(Date.now() - ts) > 5 * 60 * 1000) {
      return res.status(400).json({ ok: false, reason: 'timestamp_skew' });
    }
    let verified = false;
    try {
      const address = bsv.Address.fromPublicKey(bsv.PublicKey.fromString(pubKey)).toString();
      verified = bsv.Message(message).verify(address, signature);
    } catch { verified = false; }
    if (!verified) return res.status(401).json({ ok: false, reason: 'bad_signature' });

    const out = backup.deleteByOwner({ email, pubKey });
    if (!out.deleted) return res.status(404).json({ ok: false, reason: out.reason });
    res.json({ ok: true });
  } catch (err) {
    console.error('backup/delete:', err);
    res.status(500).json({ ok: false, reason: 'server_error' });
  }
});

// ---- SSR profile page ----

app.get('/u/:handle', (req, res) => {
  const h = String(req.params.handle || '').toLowerCase();
  if (!HANDLE_RE.test(h)) {
    return res.status(400).type('html').send(renderNotFoundPage(h));
  }
  const record = paymail.get(h);
  if (!record) return res.status(404).type('html').send(renderNotFoundPage(h));
  res.type('html').send(renderProfilePage(record));
});

app.get('/verify',  (_req, res) => res.sendFile(path.join(__dirname, 'public', 'verify.html')));
app.get('/sso',     (_req, res) => res.sendFile(path.join(__dirname, 'public', 'sso.html')));
app.get('/demo',    (_req, res) => res.sendFile(path.join(__dirname, 'public', 'demo.html')));
app.get('/recover', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'recover.html')));
app.get('/app',     (_req, res) => res.sendFile(path.join(__dirname, 'public', 'app.html')));
app.get('/',        (_req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// SDK gets a permissive Cache-Control for dApp embedding, plus explicit CORS so
// cross-origin <script> imports work without surprises.
app.get('/sdk.js', (_req, res) => {
  res.set('Cache-Control', 'public, max-age=300');
  res.set('Access-Control-Allow-Origin', '*');
  res.set('Content-Type', 'application/javascript; charset=utf-8');
  res.sendFile(path.join(__dirname, 'public', 'sdk.js'));
});

// ---- Static fallback last ----

app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: '5m',
  setHeaders(res, filePath) {
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-cache');
    }
  },
}));

// Only listen when run as the main module; tests import this file and drive
// the express app via supertest without binding a real port.
const isMain = import.meta.url === `file://${process.argv[1]}`;
if (isMain) {
  app.listen(PORT, HOST, () => {
    console.log(`web3keys listening on http://${HOST}:${PORT}`);
  });
}

export { app };
