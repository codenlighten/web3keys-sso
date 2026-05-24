import {
  randomBytes, bytesToBase64, base64ToBytes,
  kekFromPrf, kekFromPassword, wrap,
} from './crypto.js';
import {
  isPlatformAuthAvailable,
  isUserVerifyingPlatformAuthenticatorAvailable,
  registerPasskey, getPrfSecret,
} from './biometric.js';
import {
  getVault, putVault, clearVault,
  listVaults, setActiveVault, removeVault,
} from './vault.js';
import { requestConsent } from './consent.js';
import {
  signMessage, parseTransaction, summarizeTransaction, signTransaction,
  signHash, encryptForRecipient, decryptIncoming,
  signAttestation, unlockMnemonic,
} from './sign.js';
import { setIdenticon, identiconSvg } from './identicon.js';
import { isValidHandle, checkHandleAvailable, buildClaimMessage, claimHandle } from './profile.js';
import { buildAttestation, CLAIM_TYPES, verifyAttestation } from './attestations.js';
import { attachChooser } from './chooser.js';

const WELCOMED_KEY = 'web3keys:welcomed';
let createMode = 'first'; // 'first' | 'add'

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
function biometricAvailable(vault) { return !!vault.wrappedWif.biometric; }

// ---- Mnemonic display ----
function renderMnemonicGrid(node, mnemonic) {
  node.innerHTML = '';
  const words = mnemonic.split(/\s+/);
  words.forEach((w, i) => {
    const cell = document.createElement('div');
    cell.className = 'word';
    const n = document.createElement('span'); n.className = 'num'; n.textContent = String(i + 1);
    const t = document.createElement('span'); t.className = 'text'; t.textContent = w;
    cell.append(n, t);
    node.append(cell);
  });
}

// ---- Account header ----
async function refreshAccountView(vault) {
  setIdenticon($('#acct-avatar'), vault.pubKey, 64);
  $('#acct-display').textContent = vault.displayName || (vault.handle ? `@${vault.handle}` : 'Unnamed identity');
  $('#acct-handle-prefix').textContent = vault.handle ? vault.handle : '—';
  $('#acct-pubkey').textContent = vault.pubKey;
  $('#acct-address').textContent = vault.address;

  const link = $('#acct-profile-link');
  if (vault.handle) {
    link.href = `/u/${encodeURIComponent(vault.handle)}`;
    link.hidden = false;
  } else {
    link.hidden = true;
  }

  const settingsLink = $('#settings-profile-link');
  if (vault.handle) {
    settingsLink.href = `/u/${encodeURIComponent(vault.handle)}`;
    settingsLink.textContent = `${vault.handle}@web3keys.com`;
  } else {
    settingsLink.removeAttribute('href');
    settingsLink.textContent = 'No handle yet';
  }

  const pill = $('#acct-biometric');
  if (vault.wrappedWif.biometric) {
    pill.textContent = 'Biometric'; pill.dataset.kind = 'ok';
  } else {
    pill.textContent = 'Password only'; pill.dataset.kind = 'warn';
  }

  $('#acct-claim-handle').hidden = !!vault.handle;
  renderClaims(vault);
  await renderIdentitiesList();
  showView('#view-account');
}

// ---- Live handle availability ----
function attachAvailabilityCheck(input, feedbackEl) {
  let timer = null;
  const update = (txt, kind) => { feedbackEl.textContent = txt; feedbackEl.dataset.kind = kind || ''; };
  input.addEventListener('input', () => {
    clearTimeout(timer);
    const v = input.value.trim().toLowerCase();
    if (!v) { update('3–32 lowercase letters, digits, dashes, underscores.', ''); return; }
    if (!isValidHandle(v)) { update('Use only a–z, 0–9, dash, underscore (3–32 chars, no leading/trailing dash).', 'error'); return; }
    update('Checking…', '');
    timer = setTimeout(async () => {
      try {
        const r = await checkHandleAvailable(v);
        if (r.ok && r.available) update(`✓ ${v}@web3keys.com is available.`, 'ok');
        else if (r.ok && !r.available) update(`That handle is taken.`, 'error');
        else update('Could not check availability.', 'warn');
      } catch { update('Could not check availability.', 'warn'); }
    }, 320);
  });
}

// ---- View routing ----
function setEmptyTitle(mode) {
  $('#empty-title').textContent = mode === 'add' ? 'Add another identity' : 'Claim your identity';
  $('#btn-empty-back').hidden = mode !== 'add';
  $('#btn-create').textContent = mode === 'add' ? 'Add identity' : 'Create identity';
}

function enterEmpty(mode) {
  createMode = mode;
  setEmptyTitle(mode);
  $('#form-create').reset();
  $('#form-restore').reset();
  $('#restore-details').open = false;
  showView('#view-empty');
}

async function routeAfterBoot() {
  const vaults = await listVaults();
  if (vaults.length > 0) {
    const v = await activeVault();
    await refreshAccountView(v);
    return;
  }
  const welcomed = localStorage.getItem(WELCOMED_KEY) === '1';
  if (welcomed) enterEmpty('first');
  else showView('#view-welcome');
}

// ---- Boot ----
async function boot() {
  if (!isPlatformAuthAvailable()) {
    status('WebAuthn is not available in this browser. You can still use a password fallback.', 'warn');
  } else {
    const uvpa = await isUserVerifyingPlatformAuthenticatorAvailable();
    if (!uvpa) status('No platform biometric detected. You can still use a password fallback.', 'warn');
  }

  attachAvailabilityCheck($('#create-handle'), $('#handle-feedback'));
  attachAvailabilityCheck($('#latehandle-input'), $('#latehandle-feedback'));

  wireWelcome();
  wireCreate();
  wireRestore();
  wireTabs();
  wireClaimHandleLate();
  wireMessage();
  wireClaims();
  wireTransaction();
  wireHash();
  wireEncrypt();
  wireSettings();
  wireChooser();

  await routeAfterBoot();
}

function wireWelcome() {
  $('#btn-welcome-create').addEventListener('click', () => {
    localStorage.setItem(WELCOMED_KEY, '1');
    enterEmpty('first');
  });
  $('#btn-welcome-restore').addEventListener('click', () => {
    localStorage.setItem(WELCOMED_KEY, '1');
    enterEmpty('first');
    setTimeout(() => { $('#restore-details').open = true; $('#restore-mnemonic').focus(); }, 50);
  });
  $('#btn-empty-back').addEventListener('click', async () => {
    const v = await activeVault();
    if (v) { await refreshAccountView(v); return; }
    showView('#view-welcome');
  });
}

// ---- Create + claim-handle pipeline ----
let pendingCreation = null; // { vault, mnemonic, passphrase, handle, displayName }

async function attemptPaymailClaim(vault, mnemonic, handle, displayName) {
  if (!handle) return null;
  const bsv = bsvLib();
  const ts = Date.now();
  const message = buildClaimMessage({ handle, pubKey: vault.pubKey, address: vault.address, ts });
  const priv = bsv.PrivateKey.fromWIF(deriveIdentity(mnemonic).wif);
  const signature = bsv.Message(message).sign(priv);
  const result = await claimHandle({
    handle, pubKey: vault.pubKey, address: vault.address,
    displayName, signature, message,
  });
  return result;
}

function wireCreate() {
  $('#form-create').addEventListener('submit', async (e) => {
    e.preventDefault();
    const handle = $('#create-handle').value.trim().toLowerCase();
    const displayName = $('#create-display').value.trim();
    const passphrase = $('#create-passphrase').value;
    if (!isValidHandle(handle)) { status('Handle is invalid.', 'error'); return; }
    if (!displayName) { status('Display name is required.', 'error'); return; }

    try {
      status('Checking handle availability…');
      const avail = await checkHandleAvailable(handle);
      if (!avail.ok || !avail.available) { status('That handle is no longer available — pick another.', 'error'); return; }

      status('Generating identity…');
      const M = MnemonicClass();
      const mnemonic = M.fromRandom(256).phrase;
      const identity = deriveIdentity(mnemonic);

      status('Registering biometric passkey…');
      const passkey = await registerPasskey({
        userId: randomBytes(16),
        userName: `${handle}@web3keys.com`,
        displayName,
      });

      status('Encrypting identity for this device…');
      const { wrappedWif, wrappedMnemonic, bioEnabled } = await buildWrappings({
        mnemonic, wif: identity.wif, passphrase, passkey,
      });

      const vault = {
        v: 1, createdAt: new Date().toISOString(), idPath: IDENTITY_PATH,
        pubKey: identity.pubKey, address: identity.address,
        handle: null, displayName,
        wrappedWif, wrappedMnemonic,
        claims: [],
      };

      pendingCreation = { vault, mnemonic, handle, displayName };
      renderMnemonicGrid($('#mnemonic-grid'), mnemonic);
      $('#mnemonic-confirm').checked = false;
      $('#mnemonic-continue').disabled = true;
      showView('#view-mnemonic');
      status(bioEnabled ? 'Biometric enabled.' : 'Biometric PRF not supported — password fallback only.', bioEnabled ? 'ok' : 'warn');
    } catch (err) {
      console.error(err); status(err.message || String(err), 'error');
    }
  });

  $('#mnemonic-confirm').addEventListener('change', (e) => {
    $('#mnemonic-continue').disabled = !e.target.checked;
  });
  $('#btn-mnemonic-copy').addEventListener('click', async () => {
    if (!pendingCreation) return;
    await navigator.clipboard.writeText(pendingCreation.mnemonic);
    status('Recovery phrase copied. Paste it somewhere offline, then erase from clipboard.', 'warn');
  });

  $('#mnemonic-continue').addEventListener('click', async () => {
    if (!pendingCreation) return;
    const { vault, mnemonic, handle, displayName } = pendingCreation;
    try {
      status('Claiming your handle…');
      const claimed = await attemptPaymailClaim(vault, mnemonic, handle, displayName);
      if (claimed) {
        vault.handle = claimed.handle;
        vault.profileClaimedAt = claimed.claimedAt;
      }
      await putVault(vault);
      invalidateVault();
      pendingCreation = null;
      await refreshAccountView(vault);
      status(claimed ? `Welcome, @${claimed.handle}.` : 'Identity saved locally. Claim a handle below to get a public profile.', 'ok');
    } catch (err) {
      console.error(err);
      // Vault not yet saved. Save without handle so the user keeps their identity.
      await putVault(vault);
      invalidateVault();
      pendingCreation = null;
      await refreshAccountView(vault);
      status(err.message || String(err), 'error');
    }
  });
}

function wireRestore() {
  $('#form-restore').addEventListener('submit', async (e) => {
    e.preventDefault();
    const mnemonic = $('#restore-mnemonic').value.trim().split(/\s+/).join(' ');
    const passphrase = $('#restore-passphrase').value;
    const handle = $('#restore-handle').value.trim().toLowerCase();
    const displayName = $('#restore-display').value.trim();
    try {
      const M = MnemonicClass();
      try { new M(mnemonic); } catch { throw new Error('Invalid recovery phrase.'); }

      status('Deriving identity from phrase…');
      const identity = deriveIdentity(mnemonic);

      status('Registering biometric passkey on this device…');
      const passkey = await registerPasskey({
        userId: randomBytes(16),
        userName: handle ? `${handle}@web3keys.com` : identity.address,
        displayName: displayName || 'Web3Keys identity',
      });

      status('Encrypting identity for this device…');
      const { wrappedWif, wrappedMnemonic, bioEnabled } = await buildWrappings({
        mnemonic, wif: identity.wif, passphrase, passkey,
      });

      const vault = {
        v: 1, createdAt: new Date().toISOString(), idPath: IDENTITY_PATH,
        pubKey: identity.pubKey, address: identity.address,
        handle: null, displayName: displayName || '',
        wrappedWif, wrappedMnemonic,
        claims: [],
      };

      if (handle) {
        try {
          const claimed = await attemptPaymailClaim(vault, mnemonic, handle, displayName || handle);
          vault.handle = claimed.handle;
          vault.profileClaimedAt = claimed.claimedAt;
        } catch (err) {
          // If claim fails, still save the vault.
          status(err.message + ' (Identity saved without a handle — you can claim one in Settings.)', 'warn');
        }
      }

      await putVault(vault);
      invalidateVault();
      await refreshAccountView(vault);
      status(vault.handle ? `Restored as @${vault.handle}.` : 'Restored. Biometric ' + (bioEnabled ? 'enabled.' : 'not available — password fallback only.'), 'ok');
    } catch (err) {
      console.error(err); status(err.message || String(err), 'error');
    }
  });
}

function wireClaimHandleLate() {
  $('#form-claim-handle').addEventListener('submit', async (e) => {
    e.preventDefault();
    const handle = $('#latehandle-input').value.trim().toLowerCase();
    const displayName = $('#latehandle-display').value.trim();
    if (!isValidHandle(handle)) { status('Invalid handle.', 'error'); return; }

    const vault = await activeVault();
    if (!vault) return;

    // Need a signature; ask for consent.
    const consent = await requestConsent({
      kind: 'claim',
      title: `Claim @${handle}`,
      risk: 'low',
      summary: [
        { label: 'Handle', value: `${handle}@web3keys.com`, mono: true },
        { label: 'Display name', value: displayName || '(none)' },
        { label: 'Public key', value: vault.pubKey, mono: true },
      ],
      biometricAvailable: biometricAvailable(vault),
    });
    if (!consent.approved) { status('Cancelled.'); return; }

    try {
      status('Signing claim…');
      const bsv = bsvLib();
      const ts = Date.now();
      const message = buildClaimMessage({ handle, pubKey: vault.pubKey, address: vault.address, ts });
      const { signature } = await signMessage(vault, consent, message);
      status('Submitting…');
      const claimed = await claimHandle({
        handle, pubKey: vault.pubKey, address: vault.address,
        displayName, signature, message,
      });
      vault.handle = claimed.handle;
      vault.displayName = displayName || vault.displayName;
      vault.profileClaimedAt = claimed.claimedAt;
      await putVault(vault);
      invalidateVault();
      await refreshAccountView(vault);
      status(`Welcome, @${claimed.handle}.`, 'ok');
    } catch (err) {
      console.error(err); status(err.message || String(err), 'error');
    }
  });
}

// ---- Tabs ----
function wireTabs() {
  const tabs = document.querySelectorAll('.tab');
  tabs.forEach((tab) => {
    tab.addEventListener('click', () => {
      tabs.forEach((t) => t.setAttribute('aria-selected', t === tab ? 'true' : 'false'));
      const name = tab.dataset.tab;
      document.querySelectorAll('.tab-panel').forEach((p) => p.hidden = p.dataset.panel !== name);
    });
  });
  const subtabs = document.querySelectorAll('.subtab');
  subtabs.forEach((tab) => {
    tab.addEventListener('click', () => {
      subtabs.forEach((t) => t.setAttribute('aria-selected', t === tab ? 'true' : 'false'));
      const mode = tab.dataset.mode;
      document.querySelectorAll('.subtab-panel').forEach((p) => p.hidden = p.dataset.mode !== mode);
    });
  });
}

// ---- Message ----
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

// ---- Claims ----
function renderClaimFields(type) {
  const wrap = $('#claim-fields');
  wrap.innerHTML = '';
  const def = CLAIM_TYPES[type];
  if (!def) return;
  for (const f of def.fields) {
    const label = document.createElement('label');
    const span = document.createElement('span');
    span.textContent = f.label;
    label.append(span);
    let input;
    if (f.type === 'json') {
      input = document.createElement('textarea');
      input.rows = 4;
    } else {
      input = document.createElement('input');
      input.type = f.type === 'email' ? 'email' : (f.type === 'url' ? 'url' : 'text');
    }
    input.id = `claim-field-${f.key}`;
    input.dataset.fieldKey = f.key;
    input.dataset.fieldType = f.type;
    if (f.required) input.required = true;
    if (f.placeholder) input.placeholder = f.placeholder;
    label.append(input);
    wrap.append(label);
  }
}

function collectClaim(type) {
  const def = CLAIM_TYPES[type];
  if (!def) throw new Error('Pick a claim type.');
  const out = {};
  for (const f of def.fields) {
    const el = $(`#claim-field-${f.key}`);
    if (!el) continue;
    const v = el.value.trim();
    if (!v && f.required) throw new Error(`Missing field: ${f.label}`);
    if (f.type === 'json') {
      if (!v) continue;
      try { Object.assign(out, JSON.parse(v)); }
      catch { throw new Error('Custom JSON did not parse.'); }
    } else if (v) {
      out[f.key] = v;
    }
  }
  return out;
}

function renderClaims(vault) {
  const list = $('#claims-list');
  list.innerHTML = '';
  const claims = vault.claims || [];
  if (claims.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'muted small';
    empty.textContent = 'No claims yet. Sign one above.';
    list.append(empty);
    return;
  }
  claims.forEach((c, idx) => {
    const def = CLAIM_TYPES[c.claimType];
    const card = document.createElement('div');
    card.className = 'claim-card';
    const label = def?.label || c.claimType;
    let summary = '';
    try { summary = def?.summary(c.claim) || ''; } catch {}
    card.innerHTML = `
      <div class="claim-card-head">
        <span class="claim-card-type">${label}</span>
        <span class="claim-card-id">${c.id.slice(0, 8)}…</span>
      </div>
      <div class="claim-card-summary">${summary || '<span class="muted">(no preview)</span>'}</div>
      <div class="claim-card-actions">
        <button class="ghost" data-act="copy" data-idx="${idx}">Copy JSON</button>
        <button class="ghost" data-act="verify" data-idx="${idx}">Verify</button>
        <button class="ghost danger" data-act="delete" data-idx="${idx}">Delete</button>
      </div>
    `;
    list.append(card);
  });
}

function wireClaims() {
  $('#claim-type').addEventListener('change', (e) => renderClaimFields(e.target.value));

  $('#form-claim').addEventListener('submit', async (e) => {
    e.preventDefault();
    const vault = await activeVault();
    if (!vault) return;
    const type = $('#claim-type').value;
    const expires = $('#claim-expires').value;
    let claim;
    try { claim = collectClaim(type); }
    catch (err) { status(err.message, 'error'); return; }

    const expiresAt = expires ? new Date(expires + 'T23:59:59Z').toISOString() : undefined;
    const unsigned = buildAttestation({
      claimType: type,
      subject: { pubKey: vault.pubKey, address: vault.address, ...(vault.handle ? { handle: vault.handle } : {}) },
      issuer:  { pubKey: vault.pubKey, address: vault.address, ...(vault.handle ? { handle: vault.handle } : {}) },
      claim,
      expiresAt,
    });

    const def = CLAIM_TYPES[type];
    let summary = '';
    try { summary = def.summary(claim); } catch {}

    const consent = await requestConsent({
      kind: 'attestation',
      title: `Sign claim: ${def.label}`,
      risk: 'low',
      summary: [
        { label: 'About', value: vault.handle ? `@${vault.handle}` : vault.pubKey, mono: !vault.handle },
        { label: 'Claim', value: summary || '(custom payload)' },
        { label: 'Issued by', value: vault.handle ? `@${vault.handle} (you)` : 'you' },
        ...(expiresAt ? [{ label: 'Expires', value: expiresAt.slice(0, 10) }] : []),
      ],
      detail: JSON.stringify({ ...unsigned }, null, 2),
      biometricAvailable: biometricAvailable(vault),
    });
    if (!consent.approved) { status('Cancelled.'); return; }

    try {
      status('Signing claim…');
      const signed = await signAttestation(vault, consent, unsigned);
      vault.claims = vault.claims || [];
      vault.claims.unshift(signed);
      await putVault(vault);
      invalidateVault();
      const fresh = await activeVault();
      renderClaims(fresh);
      $('#form-claim').reset();
      $('#claim-fields').innerHTML = '';
      status('Claim signed.', 'ok');
    } catch (err) {
      console.error(err); status(err.message || String(err), 'error');
    }
  });

  $('#claims-list').addEventListener('click', async (e) => {
    const btn = e.target.closest('button[data-act]');
    if (!btn) return;
    const idx = Number(btn.dataset.idx);
    const vault = await activeVault();
    if (!vault?.claims?.[idx]) return;
    const c = vault.claims[idx];

    if (btn.dataset.act === 'copy') {
      await navigator.clipboard.writeText(JSON.stringify(c, null, 2));
      status('Claim JSON copied.', 'ok');
    } else if (btn.dataset.act === 'verify') {
      const r = await verifyAttestation(c, bsvLib());
      status(r.verified ? `Verified ✓${r.expired ? ' (expired)' : ''}` : `Failed: ${r.reason}`, r.verified ? 'ok' : 'error');
    } else if (btn.dataset.act === 'delete') {
      if (!confirm('Delete this claim from this device?')) return;
      vault.claims.splice(idx, 1);
      await putVault(vault);
      invalidateVault();
      const fresh = await activeVault();
      renderClaims(fresh);
      status('Claim deleted.', 'ok');
    }
  });
}

// ---- Transaction ----
function fmtSats(n) { if (n == null) return '—'; return `${n.toLocaleString()} sat`; }
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
function wireTransaction() {
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

// ---- Hash ----
function wireHash() {
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

// ---- Encrypt / Decrypt ----
function wireEncrypt() {
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

// ---- Chooser ----
async function switchToVault(vault) {
  await setActiveVault(vault.pubKey);
  invalidateVault();
  const fresh = await activeVault();
  await refreshAccountView(fresh);
  status(`Switched to ${fresh.handle ? `@${fresh.handle}` : 'unnamed identity'}.`, 'ok');
}

async function startAddIdentity() {
  enterEmpty('add');
  status('Add an identity. Your current identity stays on this device.', 'info');
}

function wireChooser() {
  attachChooser({
    trigger: $('#acct-switcher'),
    container: $('#chooser'),
    getVaults: listVaults,
    getActiveId: async () => (await activeVault())?.pubKey || null,
    onPick: switchToVault,
    onAddIdentity: startAddIdentity,
  });
}

// ---- Settings: identities list ----
async function renderIdentitiesList() {
  const wrap = $('#identities-list');
  wrap.innerHTML = '';
  const vaults = await listVaults();
  const active = await activeVault();
  if (vaults.length === 0) {
    wrap.append(Object.assign(document.createElement('div'), { className: 'muted small', textContent: 'No identities on this device.' }));
    return;
  }
  vaults.forEach((v) => {
    const isActive = active?.pubKey === v.pubKey;
    const row = document.createElement('div');
    row.className = 'identity-row' + (isActive ? ' active' : '');
    row.innerHTML = `
      <div class="identity-row-avatar">${identiconSvg(v.pubKey, 36)}</div>
      <div class="identity-row-text">
        <div class="identity-row-name">${escapeText(v.displayName || (v.handle ? `@${v.handle}` : 'Unnamed'))}${isActive ? ' <span class="pill" data-kind="ok">active</span>' : ''}</div>
        <div class="identity-row-handle">${v.handle ? v.handle + '@web3keys.com' : 'No handle'}</div>
      </div>
      <div class="identity-row-actions">
        ${isActive ? '' : `<button class="ghost" data-act="switch" data-id="${v.pubKey}">Switch</button>`}
        <button class="ghost danger" data-act="remove" data-id="${v.pubKey}">Remove</button>
      </div>
    `;
    wrap.append(row);
  });
}

function escapeText(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// ---- Settings (show phrase + reset) ----
function wireSettings() {
  $('#btn-show-mnemonic').addEventListener('click', async () => {
    const vault = await activeVault(); if (!vault) return;
    const consent = await requestConsent({
      kind: 'recovery',
      title: 'Reveal recovery phrase',
      risk: 'high',
      summary: [
        { label: 'Identity', value: vault.handle ? `@${vault.handle}` : vault.pubKey, mono: !vault.handle },
      ],
      warning: 'Anyone who reads your recovery phrase can recreate this identity on any device. Make sure no one is looking.',
      approveLabel: 'Reveal phrase',
      biometricAvailable: biometricAvailable(vault),
    });
    if (!consent.approved) { status('Cancelled.'); return; }
    try {
      const mnemonic = await unlockMnemonic(vault, consent);
      renderMnemonicGrid($('#mnemonic-revealed-grid'), mnemonic);
      $('#mnemonic-revealed').hidden = false;
      status('Phrase shown. Hide it when you\'re done.', 'warn');
    } catch (err) {
      console.error(err); status(err.message || String(err), 'error');
    }
  });
  $('#btn-hide-mnemonic').addEventListener('click', () => {
    $('#mnemonic-revealed-grid').innerHTML = '';
    $('#mnemonic-revealed').hidden = true;
    status('Phrase hidden.');
  });
  $('#btn-reset').addEventListener('click', async () => {
    if (!confirm('Erase ALL Web3Keys identities from this device? You will need each recovery phrase to restore them.')) return;
    await clearVault();
    invalidateVault();
    pendingCreation = null;
    localStorage.removeItem(WELCOMED_KEY);
    showView('#view-welcome');
    status('Device erased.', 'ok');
  });
  $('#btn-settings-add').addEventListener('click', startAddIdentity);

  $('#identities-list').addEventListener('click', async (e) => {
    const btn = e.target.closest('button[data-act]');
    if (!btn) return;
    const id = btn.dataset.id;
    if (btn.dataset.act === 'switch') {
      const v = (await listVaults()).find((x) => x.pubKey === id);
      if (v) await switchToVault(v);
    } else if (btn.dataset.act === 'remove') {
      const all = await listVaults();
      const target = all.find((x) => x.pubKey === id);
      if (!target) return;
      const label = target.handle ? `@${target.handle}` : 'this identity';
      if (!confirm(`Remove ${label} from this device? You'll need its recovery phrase to restore it elsewhere.`)) return;
      await removeVault(id);
      invalidateVault();
      const remaining = await listVaults();
      if (remaining.length === 0) {
        localStorage.removeItem(WELCOMED_KEY);
        showView('#view-welcome');
        status('Last identity removed.', 'ok');
      } else {
        const next = await activeVault();
        await refreshAccountView(next);
        status(`${label} removed.`, 'ok');
      }
    }
  });
}

boot().catch((e) => { console.error(e); status(e.message || String(e), 'error'); });
