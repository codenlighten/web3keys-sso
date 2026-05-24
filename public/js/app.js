import {
  randomBytes, bytesToBase64, base64ToBytes,
  kekFromPrf, kekFromPassword, wrap,
} from './crypto.js';
import {
  isPlatformAuthAvailable,
  isUserVerifyingPlatformAuthenticatorAvailable,
  registerPasskey, getPrfSecret,
} from './biometric.js';
import { getVault, putVault, clearVault } from './vault.js';
import { requestConsent } from './consent.js';
import {
  signMessage, parseTransaction, summarizeTransaction, signTransaction,
  signHash, encryptForRecipient, decryptIncoming,
} from './sign.js';

const IDENTITY_PATH = "m/44'/236'/0'/0/0";
const INFO_WIF = 'web3keys/v1/wif-wrap';
const INFO_MNEMONIC = 'web3keys/v1/mnemonic-wrap';

const $ = (sel) => document.querySelector(sel);
const status = (msg, kind = 'info') => {
  const el = $('#status');
  el.textContent = msg || '';
  el.dataset.kind = kind;
};
const showView = (id) => {
  for (const s of document.querySelectorAll('main > section')) s.hidden = true;
  $(id).hidden = false;
};

function bsvLib() {
  const lib = window.bsv;
  if (!lib) throw new Error('BSV library failed to load.');
  return lib;
}
function MnemonicClass() {
  return window.bsvMnemonic || window.Mnemonic || (window.bsv && window.bsv.Mnemonic);
}

function deriveIdentity(mnemonic) {
  const bsv = bsvLib();
  const M = MnemonicClass();
  if (!M) throw new Error('Mnemonic module unavailable.');
  const seed = new M(mnemonic).toSeed();
  const root = bsv.HDPrivateKey.fromSeed(seed);
  const child = root.deriveChild(IDENTITY_PATH);
  const priv = child.privateKey;
  return {
    wif: priv.toWIF(),
    pubKey: priv.toPublicKey().toString('hex'),
    address: priv.toAddress().toString(),
  };
}

async function buildWrappings({ mnemonic, wif, passphrase, passkey }) {
  const wrappedWif = {};
  const wrappedMnemonic = {};

  const pwdSalt = randomBytes(16);
  const kekPwd = await kekFromPassword(passphrase, pwdSalt);
  wrappedWif.password = {
    salt: bytesToBase64(pwdSalt), iters: 600000, kdf: 'PBKDF2-SHA256',
    ...(await wrap(kekPwd, wif)),
  };
  const pwdSaltM = randomBytes(16);
  const kekPwdM = await kekFromPassword(passphrase, pwdSaltM);
  wrappedMnemonic.password = {
    salt: bytesToBase64(pwdSaltM), iters: 600000, kdf: 'PBKDF2-SHA256',
    ...(await wrap(kekPwdM, mnemonic)),
  };

  let bioEnabled = false;
  let prfBytes = passkey.prfFromCreate;
  if (!prfBytes) {
    try {
      prfBytes = await getPrfSecret({
        credentialIdB64: passkey.credentialId,
        prfSaltB64: passkey.prfSalt,
      });
    } catch (e) {
      console.warn('PRF unavailable on this authenticator:', e.message);
    }
  }
  if (prfBytes) {
    const kekBio = await kekFromPrf(prfBytes, INFO_WIF);
    wrappedWif.biometric = {
      credentialId: passkey.credentialId,
      prfSalt: passkey.prfSalt,
      ...(await wrap(kekBio, wif)),
    };
    const kekBioM = await kekFromPrf(prfBytes, INFO_MNEMONIC);
    wrappedMnemonic.biometric = {
      credentialId: passkey.credentialId,
      prfSalt: passkey.prfSalt,
      ...(await wrap(kekBioM, mnemonic)),
    };
    prfBytes.fill(0);
    bioEnabled = true;
  }

  return { wrappedWif, wrappedMnemonic, bioEnabled };
}

let cachedVault = null;
async function activeVault() {
  if (!cachedVault) cachedVault = await getVault();
  return cachedVault;
}
function invalidateVault() { cachedVault = null; }

async function refreshAccountView(vault) {
  $('#acct-address').textContent = vault.address;
  $('#acct-pubkey').textContent = vault.pubKey;
  const pill = $('#acct-biometric');
  if (vault.wrappedWif.biometric) {
    pill.textContent = 'Enabled'; pill.dataset.kind = 'ok';
  } else {
    pill.textContent = 'Password only'; pill.dataset.kind = 'warn';
  }
  showView('#view-account');
}

async function boot() {
  if (!isPlatformAuthAvailable()) {
    status('WebAuthn is not available in this browser. You can still use a password fallback.', 'warn');
  } else {
    const uvpa = await isUserVerifyingPlatformAuthenticatorAvailable();
    if (!uvpa) {
      status('No platform biometric detected. You can still use a password fallback.', 'warn');
    }
  }

  const vault = await activeVault();
  if (vault) await refreshAccountView(vault);
  else showView('#view-empty');

  wireCreate();
  wireRestore();
  wireTabs();
  wireMessage();
  wireTransaction();
  wireHash();
  wireEncrypt();
  wireAccountActions();
}

let pendingVault = null;

function wireCreate() {
  $('#form-create').addEventListener('submit', async (e) => {
    e.preventDefault();
    const passphrase = $('#create-passphrase').value;
    try {
      status('Generating identity…');
      const M = MnemonicClass();
      const mnemonic = M.fromRandom(256).phrase;
      const identity = deriveIdentity(mnemonic);

      status('Registering biometric passkey…');
      const passkey = await registerPasskey({
        userId: randomBytes(16),
        userName: identity.address,
        displayName: 'Web3Keys identity',
      });

      status('Encrypting identity for this device…');
      const { wrappedWif, wrappedMnemonic, bioEnabled } = await buildWrappings({
        mnemonic, wif: identity.wif, passphrase, passkey,
      });

      const vault = {
        v: 1, createdAt: new Date().toISOString(), idPath: IDENTITY_PATH,
        pubKey: identity.pubKey, address: identity.address, paymail: null,
        wrappedWif, wrappedMnemonic,
      };

      pendingVault = vault;
      $('#mnemonic-display').textContent = mnemonic;
      $('#mnemonic-confirm').checked = false;
      $('#mnemonic-continue').disabled = true;
      showView('#view-mnemonic');
      status(bioEnabled ? 'Biometric enabled.' : 'Biometric PRF not supported — password fallback only.', bioEnabled ? 'ok' : 'warn');
    } catch (err) {
      console.error(err);
      status(err.message || String(err), 'error');
    }
  });

  $('#mnemonic-confirm').addEventListener('change', (e) => {
    $('#mnemonic-continue').disabled = !e.target.checked;
  });
  $('#mnemonic-continue').addEventListener('click', async () => {
    if (!pendingVault) return;
    await putVault(pendingVault);
    invalidateVault();
    const v = pendingVault;
    pendingVault = null;
    await refreshAccountView(v);
    status('Identity saved on this device.', 'ok');
  });
}

function wireRestore() {
  $('#form-restore').addEventListener('submit', async (e) => {
    e.preventDefault();
    const mnemonic = $('#restore-mnemonic').value.trim().split(/\s+/).join(' ');
    const passphrase = $('#restore-passphrase').value;
    try {
      const M = MnemonicClass();
      try { new M(mnemonic); } catch { throw new Error('Invalid recovery phrase.'); }

      status('Deriving identity from phrase…');
      const identity = deriveIdentity(mnemonic);

      status('Registering biometric passkey on this device…');
      const passkey = await registerPasskey({
        userId: randomBytes(16),
        userName: identity.address,
        displayName: 'Web3Keys identity',
      });

      status('Encrypting identity for this device…');
      const { wrappedWif, wrappedMnemonic, bioEnabled } = await buildWrappings({
        mnemonic, wif: identity.wif, passphrase, passkey,
      });

      const vault = {
        v: 1, createdAt: new Date().toISOString(), idPath: IDENTITY_PATH,
        pubKey: identity.pubKey, address: identity.address, paymail: null,
        wrappedWif, wrappedMnemonic,
      };
      await putVault(vault);
      invalidateVault();
      await refreshAccountView(vault);
      status(bioEnabled ? 'Restored. Biometric enabled.' : 'Restored. Password-only on this device.', 'ok');
    } catch (err) {
      console.error(err);
      status(err.message || String(err), 'error');
    }
  });
}

function wireTabs() {
  const tabs = document.querySelectorAll('.tab');
  tabs.forEach((tab) => {
    tab.addEventListener('click', () => {
      tabs.forEach((t) => t.setAttribute('aria-selected', t === tab ? 'true' : 'false'));
      const name = tab.dataset.tab;
      document.querySelectorAll('.tab-panel').forEach((p) => {
        p.hidden = p.dataset.panel !== name;
      });
    });
  });
  const subtabs = document.querySelectorAll('.subtab');
  subtabs.forEach((tab) => {
    tab.addEventListener('click', () => {
      subtabs.forEach((t) => t.setAttribute('aria-selected', t === tab ? 'true' : 'false'));
      const mode = tab.dataset.mode;
      document.querySelectorAll('.subtab-panel').forEach((p) => {
        p.hidden = p.dataset.mode !== mode;
      });
    });
  });
}

function biometricAvailable(vault) { return !!vault.wrappedWif.biometric; }

function wireMessage() {
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
        { label: 'Address', value: vault.address, mono: true },
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
      console.error(err);
      status(err.message || String(err), 'error');
    }
  });
}

function fmtSats(n) {
  if (n == null) return '—';
  return `${n.toLocaleString()} sat`;
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
    if (o.isData) {
      rows.push({ label: `Out #${o.index}`, value: 'OP_RETURN (data)', mono: true });
    } else if (o.address) {
      const tag = o.address === ourAddress ? ' (to you)' : '';
      rows.push({ label: `Out #${o.index}`, value: `${fmtSats(o.satoshis)} → ${o.address}${tag}`, mono: true, highlight: !!tag });
    } else {
      rows.push({ label: `Out #${o.index}`, value: `${fmtSats(o.satoshis)} → ${o.scriptHex.slice(0, 40)}…`, mono: true });
    }
  });
  return rows;
}

function wireTransaction() {
  $('#btn-tx-preview').addEventListener('click', async () => {
    const vault = await activeVault();
    if (!vault) return;
    try {
      const tx = parseTx();
      const summary = summarizeTransaction(tx, vault.address);
      alert(JSON.stringify(summary, null, 2));
    } catch (e) {
      status(e.message, 'error');
    }
  });

  function parseTx() {
    const rawHex = $('#tx-raw').value.trim();
    if (!rawHex) throw new Error('Paste a raw transaction hex.');
    let utxos = [];
    const utxoText = $('#tx-utxo').value.trim();
    if (utxoText) {
      try { utxos = JSON.parse(utxoText); }
      catch { throw new Error('UTXO context must be valid JSON.'); }
      if (!Array.isArray(utxos)) throw new Error('UTXO context must be a JSON array.');
    }
    return parseTransaction(rawHex, utxos);
  }

  $('#form-tx').addEventListener('submit', async (e) => {
    e.preventDefault();
    const vault = await activeVault();
    if (!vault) return;
    try {
      const tx = parseTx();
      const summary = summarizeTransaction(tx, vault.address);
      if (summary.ourInputCount === 0) {
        if (!confirm('No inputs to this transaction belong to your address. Sign anyway?')) return;
      }
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
      console.error(err);
      status(err.message || String(err), 'error');
    }
  });
}

function wireHash() {
  $('#form-hash').addEventListener('submit', async (e) => {
    e.preventDefault();
    const vault = await activeVault();
    if (!vault) return;
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
      console.error(err);
      status(err.message || String(err), 'error');
    }
  });
}

function wireEncrypt() {
  $('#form-encrypt').addEventListener('submit', async (e) => {
    e.preventDefault();
    const vault = await activeVault();
    if (!vault) return;
    const plain = $('#enc-plain').value;
    const pub = $('#enc-pub').value.trim().toLowerCase();
    if (!plain) return;

    const consent = await requestConsent({
      kind: 'encrypt',
      title: 'Encrypt for a recipient',
      risk: 'low',
      summary: [
        { label: 'From', value: vault.pubKey, mono: true },
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
      console.error(err);
      status(err.message || String(err), 'error');
    }
  });

  $('#form-decrypt').addEventListener('submit', async (e) => {
    e.preventDefault();
    const vault = await activeVault();
    if (!vault) return;
    const ct = $('#dec-ct').value.trim();
    if (!ct) return;

    const consent = await requestConsent({
      kind: 'decrypt',
      title: 'Decrypt with your identity key',
      risk: 'low',
      summary: [
        { label: 'Recipient', value: vault.pubKey, mono: true },
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
      console.error(err);
      status(err.message || String(err), 'error');
    }
  });
}

function wireAccountActions() {
  $('#btn-signout').addEventListener('click', () => {
    showView('#view-empty');
    status('Signed out on this tab. Vault remains on this device.', 'info');
  });
  $('#btn-reset').addEventListener('click', async () => {
    if (!confirm('Erase the Web3Keys vault from this device? You will need your recovery phrase to restore it.')) return;
    await clearVault();
    invalidateVault();
    pendingVault = null;
    showView('#view-empty');
    status('Device erased.', 'ok');
  });
}

boot().catch((e) => {
  console.error(e);
  status(e.message || String(e), 'error');
});
