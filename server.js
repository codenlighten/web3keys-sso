import express from 'express';
import cors from 'cors';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import 'dotenv/config';

import { createPaymailStore, HANDLE_RE } from './server/paymail-store.js';
import { renderProfilePage, renderNotFoundPage } from './server/pages.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const bsv = require('@smartledger/bsv');

const app = express();
const PORT = process.env.PORT || 8787;
const HOST = process.env.HOST || '127.0.0.1';
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');

const paymail = createPaymailStore(DATA_DIR);

app.disable('x-powered-by');
app.use(cors());
app.use(express.json({ limit: '64kb' }));

app.use('/vendor', express.static(path.join(__dirname, 'node_modules/@smartledger/bsv'), {
  maxAge: '1h',
}));

app.get('/healthz', (_req, res) => res.json({ ok: true }));

// ---- Paymail registry ----

app.get('/api/paymail/check/:handle', (req, res) => {
  const h = String(req.params.handle || '').toLowerCase();
  if (!paymail.isValid(h)) {
    return res.status(400).json({ ok: false, reason: 'invalid' });
  }
  return res.json({ ok: true, handle: h, available: paymail.isAvailable(h) });
});

app.get('/api/paymail/:handle', (req, res) => {
  const record = paymail.get(req.params.handle);
  if (!record) return res.status(404).json({ ok: false, reason: 'not_found' });
  return res.json({ ok: true, ...record });
});

app.post('/api/paymail/claim', (req, res) => {
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

// ---- Static fallback last ----

app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: '5m',
  setHeaders(res, filePath) {
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-cache');
    }
  },
}));

app.listen(PORT, HOST, () => {
  console.log(`web3keys listening on http://${HOST}:${PORT}`);
});
