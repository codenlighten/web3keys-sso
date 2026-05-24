// Message / Transaction / Hash / Encrypt / Decrypt tabs.

import { $, activeVault, status } from '../lib/state.js';
import { requestConsent } from '../consent.js';
import {
  signMessage, parseTransaction, summarizeTransaction, signTransaction,
  signHash, encryptForRecipient, decryptIncoming,
} from '../sign.js';
import { biometricAvailable } from '../lib/identity.js';
import { fmtSats } from '../lib/fmt.js';

export function wireMessage() {
  $('#form-message').addEventListener('submit', async (e) => {
    e.preventDefault();
    const vault = await activeVault();
    if (!vault) return;
    const message = $('#msg-text').value;
    if (!message) return;

    const consent = await requestConsent({
      kind: 'message',
      title: 'Sign a message',
      risk: 'low',
      summary: [
        { label: 'As', value: vault.handle ? `${vault.handle}@web3keys.com` : vault.address, mono: true },
        { label: 'Message', value: message.length > 200 ? message.slice(0, 200) + '…' : message },
      ],
      detail: message.length > 200 ? message : null,
      biometricAvailable: biometricAvailable(vault),
    });
    if (!consent.approved) { status('Cancelled.'); return; }

    try {
      status('Signing message…');
      const { signature, verified } = await signMessage(vault, consent, message);
      $('#msg-signature').textContent = signature;
      const verEl = $('#msg-verified');
      verEl.textContent = verified ? 'Yes' : 'No';
      verEl.dataset.kind = verified ? 'ok' : 'error';
      $('#msg-result').hidden = false;
      status('Message signed.', 'ok');
    } catch (err) {
      console.error(err); status(err.message || String(err), 'error');
    }
  });
}

function txConsentSummary(summary, ourAddress) {
  const rows = [
    { label: 'Inputs', value: `${summary.inputs.length} (${summary.ourInputCount} from this identity)` },
    { label: 'Outputs', value: String(summary.outputs.length) },
    { label: 'Total in', value: fmtSats(summary.totalIn) },
    { label: 'Total out', value: fmtSats(summary.totalOut) },
    { label: 'Fee', value: fmtSats(summary.fee) },
    { label: 'You receive', value: fmtSats(summary.toUs), highlight: summary.toUs > 0 },
    { label: 'You spend', value: fmtSats(summary.fromUs), highlight: summary.fromUs > 0 },
  ];
  summary.outputs.forEach((o) => {
    if (o.isData) rows.push({ label: `Out #${o.index}`, value: 'OP_RETURN (data)', mono: true });
    else if (o.address) {
      const tag = o.address === ourAddress ? ' (to you)' : '';
      rows.push({ label: `Out #${o.index}`, value: `${fmtSats(o.satoshis)} → ${o.address}${tag}`, mono: true, highlight: !!tag });
    } else rows.push({ label: `Out #${o.index}`, value: `${fmtSats(o.satoshis)} → ${o.scriptHex.slice(0, 40)}…`, mono: true });
  });
  return rows;
}

export function wireTransaction() {
  function parseTx() {
    const rawHex = $('#tx-raw').value.trim();
    if (!rawHex) throw new Error('Paste a raw transaction hex.');
    let utxos = [];
    const utxoText = $('#tx-utxo').value.trim();
    if (utxoText) {
      try { utxos = JSON.parse(utxoText); } catch { throw new Error('UTXO context must be valid JSON.'); }
      if (!Array.isArray(utxos)) throw new Error('UTXO context must be a JSON array.');
    }
    return parseTransaction(rawHex, utxos);
  }
  $('#btn-tx-preview').addEventListener('click', async () => {
    const vault = await activeVault(); if (!vault) return;
    try {
      const tx = parseTx();
      const summary = summarizeTransaction(tx, vault.address);
      status('See preview details below.', 'info');
      $('#tx-txid').textContent = `(unsigned preview) ${tx.id}`;
      $('#tx-rawsigned').textContent = JSON.stringify(summary, null, 2);
      $('#tx-result').hidden = false;
    } catch (e) { status(e.message, 'error'); }
  });
  $('#form-tx').addEventListener('submit', async (e) => {
    e.preventDefault();
    const vault = await activeVault(); if (!vault) return;
    try {
      const tx = parseTx();
      const summary = summarizeTransaction(tx, vault.address);
      if (summary.ourInputCount === 0 && !confirm('No inputs to this transaction belong to your address. Sign anyway?')) return;
      const risk = summary.fromUs > summary.toUs * 1.5 ? 'high' : 'normal';
      const consent = await requestConsent({
        kind: 'transaction',
        title: summary.fromUs > 0 ? `Spend ${fmtSats(summary.fromUs)}` : 'Sign transaction',
        risk,
        summary: txConsentSummary(summary, vault.address),
        detail: tx.toString(),
        warning: summary.fee != null && summary.fee < 0 ? 'Outputs exceed inputs — this transaction is invalid.' : null,
        biometricAvailable: biometricAvailable(vault),
      });
      if (!consent.approved) { status('Cancelled.'); return; }
      status('Signing transaction…');
      const { rawHex, txid } = await signTransaction(vault, consent, tx);
      $('#tx-txid').textContent = txid;
      $('#tx-rawsigned').textContent = rawHex;
      $('#tx-result').hidden = false;
      status('Transaction signed.', 'ok');
    } catch (err) {
      console.error(err); status(err.message || String(err), 'error');
    }
  });
}

export function wireHash() {
  $('#form-hash').addEventListener('submit', async (e) => {
    e.preventDefault();
    const vault = await activeVault(); if (!vault) return;
    const digest = $('#hash-digest').value.trim().toLowerCase();
    const intent = $('#hash-intent').value.trim();
    if (!/^[0-9a-f]{64}$/.test(digest)) { status('Digest must be 64 hex characters.', 'error'); return; }
    const consent = await requestConsent({
      kind: 'hash',
      title: 'Sign an opaque 32-byte hash',
      risk: 'danger',
      summary: [
        { label: 'Intent', value: intent || '(none provided)' },
        { label: 'Digest', value: digest, mono: true },
        { label: 'Signing key', value: vault.address, mono: true },
      ],
      warning: 'You are about to sign an arbitrary digest. The wallet cannot see what this hash represents. A malicious requester could trick you into signing a transaction or other data this way. Only proceed if you trust the requester.',
      approveLabel: 'I trust this request — sign hash',
      biometricAvailable: biometricAvailable(vault),
    });
    if (!consent.approved) { status('Cancelled.'); return; }
    try {
      status('Signing digest…');
      const { derHex } = await signHash(vault, consent, digest);
      $('#hash-derhex').textContent = derHex;
      $('#hash-result').hidden = false;
      status('Hash signed.', 'ok');
    } catch (err) {
      console.error(err); status(err.message || String(err), 'error');
    }
  });
}

export function wireEncrypt() {
  $('#form-encrypt').addEventListener('submit', async (e) => {
    e.preventDefault();
    const vault = await activeVault(); if (!vault) return;
    const plain = $('#enc-plain').value;
    const pub = $('#enc-pub').value.trim().toLowerCase();
    if (!plain) return;
    const consent = await requestConsent({
      kind: 'encrypt',
      title: 'Encrypt for a recipient',
      risk: 'low',
      summary: [
        { label: 'From', value: vault.handle ? `@${vault.handle}` : vault.pubKey, mono: !vault.handle },
        { label: 'To', value: pub, mono: true },
        { label: 'Bytes', value: String(new TextEncoder().encode(plain).length) },
      ],
      detail: plain.length > 200 ? null : plain,
      biometricAvailable: biometricAvailable(vault),
    });
    if (!consent.approved) { status('Cancelled.'); return; }
    try {
      status('Encrypting…');
      const { ciphertextB64 } = await encryptForRecipient(vault, consent, plain, pub);
      $('#enc-ciphertext').textContent = ciphertextB64;
      $('#enc-result').hidden = false;
      status('Encrypted.', 'ok');
    } catch (err) {
      console.error(err); status(err.message || String(err), 'error');
    }
  });
  $('#form-decrypt').addEventListener('submit', async (e) => {
    e.preventDefault();
    const vault = await activeVault(); if (!vault) return;
    const ct = $('#dec-ct').value.trim();
    if (!ct) return;
    const consent = await requestConsent({
      kind: 'decrypt',
      title: 'Decrypt with your identity key',
      risk: 'low',
      summary: [
        { label: 'Recipient', value: vault.handle ? `@${vault.handle}` : vault.pubKey, mono: !vault.handle },
        { label: 'Ciphertext bytes', value: String(Math.floor(ct.length * 0.75)) },
      ],
      biometricAvailable: biometricAvailable(vault),
    });
    if (!consent.approved) { status('Cancelled.'); return; }
    try {
      status('Decrypting…');
      const { plaintext } = await decryptIncoming(vault, consent, ct);
      $('#dec-plain').textContent = plaintext;
      $('#dec-result').hidden = false;
      status('Decrypted.', 'ok');
    } catch (err) {
      console.error(err); status(err.message || String(err), 'error');
    }
  });
}
