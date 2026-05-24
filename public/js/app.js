import {
  randomBytes, bytesToBase64, base64ToBytes,
  kekFromPrf, kekFromPassword, wrap, unwrap,
} from './crypto.js';
import {
  isPlatformAuthAvailable,
  isUserVerifyingPlatformAuthenticatorAvailable,
  registerPasskey, getPrfSecret,
} from './biometric.js';
import { getVault, putVault, clearVault } from './vault.js';

const IDENTITY_PATH = "m/44'/236'/0'/0/0";
const INFO_WIF = 'web3keys/v1/wif-wrap';
const INFO_MNEMONIC = 'web3keys/v1/mnemonic-wrap';

const $ = (sel) => document.querySelector(sel);
const status = (msg, kind = 'info') => {
  const el = $('#status');
  el.textContent = msg || '';
  el.dataset.kind = kind;
};
const show = (id) => {
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

  // Password wrapping (always present as fallback).
  const pwdSalt = randomBytes(16);
  const kekPwd = await kekFromPassword(passphrase, pwdSalt);
  wrappedWif.password = {
    salt: bytesToBase64(pwdSalt),
    iters: 600000,
    kdf: 'PBKDF2-SHA256',
    ...(await wrap(kekPwd, wif)),
  };
  const pwdSaltM = randomBytes(16);
  const kekPwdM = await kekFromPassword(passphrase, pwdSaltM);
  wrappedMnemonic.password = {
    salt: bytesToBase64(pwdSaltM),
    iters: 600000,
    kdf: 'PBKDF2-SHA256',
    ...(await wrap(kekPwdM, mnemonic)),
  };

  // Biometric wrapping (optional, requires PRF).
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

async function unlockWifPassword(vault, passphrase) {
  const w = vault.wrappedWif.password;
  const salt = base64ToBytes(w.salt);
  const kek = await kekFromPassword(passphrase, salt, w.iters);
  try {
    return await unwrap(kek, w);
  } catch (e) {
    throw new Error('Wrong password.');
  }
}

async function unlockWifBiometric(vault) {
  const w = vault.wrappedWif.biometric;
  if (!w) throw new Error('Biometric not configured for this account.');
  const prfBytes = await getPrfSecret({
    credentialIdB64: w.credentialId,
    prfSaltB64: w.prfSalt,
  });
  const kek = await kekFromPrf(prfBytes, INFO_WIF);
  prfBytes.fill(0);
  return unwrap(kek, w);
}

async function signMessageWithWif(wif, message) {
  const bsv = bsvLib();
  const priv = bsv.PrivateKey.fromWIF(wif);
  const sig = bsv.Message(message).sign(priv);
  const address = bsv.Address.fromPrivateKey(priv).toString();
  const verified = bsv.Message(message).verify(address, sig);
  return { signature: sig, address, verified };
}

async function refreshAccountView(vault) {
  $('#acct-address').textContent = vault.address;
  $('#acct-pubkey').textContent = vault.pubKey;
  const pill = $('#acct-biometric');
  if (vault.wrappedWif.biometric) {
    pill.textContent = 'Enabled';
    pill.dataset.kind = 'ok';
  } else {
    pill.textContent = 'Password only';
    pill.dataset.kind = 'warn';
  }
  show('#view-account');
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

  const vault = await getVault();
  if (vault) {
    await refreshAccountView(vault);
  } else {
    show('#view-empty');
  }

  wireCreate();
  wireRestore();
  wireSign();
  wireAccountActions();
}

let pendingMnemonic = null;
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
        v: 1,
        createdAt: new Date().toISOString(),
        idPath: IDENTITY_PATH,
        pubKey: identity.pubKey,
        address: identity.address,
        paymail: null,
        wrappedWif,
        wrappedMnemonic,
      };

      pendingMnemonic = mnemonic;
      pendingVault = vault;

      $('#mnemonic-display').textContent = mnemonic;
      $('#mnemonic-confirm').checked = false;
      $('#mnemonic-continue').disabled = true;
      show('#view-mnemonic');
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
    pendingMnemonic = null;
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
        v: 1,
        createdAt: new Date().toISOString(),
        idPath: IDENTITY_PATH,
        pubKey: identity.pubKey,
        address: identity.address,
        paymail: null,
        wrappedWif,
        wrappedMnemonic,
      };
      await putVault(vault);
      await refreshAccountView(vault);
      status(bioEnabled ? 'Restored. Biometric enabled.' : 'Restored. Password-only on this device.', 'ok');
    } catch (err) {
      console.error(err);
      status(err.message || String(err), 'error');
    }
  });
}

function wireSign() {
  $('#form-sign').addEventListener('submit', async (e) => {
    e.preventDefault();
    const message = $('#sign-message').value;
    if (!message) return;
    const vault = await getVault();
    if (!vault) return;

    const usePassword = $('#use-password').checked;
    let wif;
    try {
      if (usePassword) {
        const pwd = prompt('Recovery passphrase');
        if (!pwd) { status('Cancelled.'); return; }
        status('Decrypting with password…');
        wif = await unlockWifPassword(vault, pwd);
      } else {
        if (!vault.wrappedWif.biometric) {
          status('Biometric is not configured. Use the password option.', 'warn');
          return;
        }
        status('Awaiting biometric…');
        wif = await unlockWifBiometric(vault);
      }
      status('Signing…');
      const { signature, verified } = await signMessageWithWif(wif, message);
      wif = '';
      $('#sign-signature').textContent = signature;
      const verEl = $('#sign-verified');
      verEl.textContent = verified ? 'Yes' : 'No';
      verEl.dataset.kind = verified ? 'ok' : 'error';
      $('#sign-result').hidden = false;
      status('Signed.', 'ok');
    } catch (err) {
      console.error(err);
      status(err.message || String(err), 'error');
    }
  });
}

function wireAccountActions() {
  $('#btn-signout').addEventListener('click', () => {
    // Phase 1: just hide the account view. Vault stays on device.
    show('#view-empty');
    status('Signed out on this tab. Vault remains on this device.', 'info');
  });
  $('#btn-reset').addEventListener('click', async () => {
    if (!confirm('Erase the Web3Keys vault from this device? You will need your recovery phrase to restore it.')) return;
    await clearVault();
    pendingMnemonic = null;
    pendingVault = null;
    show('#view-empty');
    status('Device erased.', 'ok');
  });
}

boot().catch((e) => {
  console.error(e);
  status(e.message || String(e), 'error');
});
