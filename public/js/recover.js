import { randomBytes, bytesToBase64, kekFromPrf, kekFromPassword, wrap } from './crypto.js';
import {
  isPlatformAuthAvailable, isUserVerifyingPlatformAuthenticatorAvailable,
  registerPasskey, getPrfSecret,
} from './biometric.js';
import { putVault } from './vault.js';
import { inspectToken, consumeToken, decryptBackup } from './backup.js';

const IDENTITY_PATH = "m/44'/236'/0'/0/0";
const INFO_WIF = 'web3keys/v1/wif-wrap';
const INFO_MNEMONIC = 'web3keys/v1/mnemonic-wrap';

const $ = (s) => document.querySelector(s);
const status = (m, k = 'info') => { const e = $('#status'); e.textContent = m || ''; e.dataset.kind = k; };

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

function showOnly(id) {
  for (const s of document.querySelectorAll('main > section')) s.hidden = true;
  $(id).hidden = false;
}

const params = new URLSearchParams(location.search);
const TOKEN = params.get('token');

async function init() {
  if (!TOKEN) {
    $('#rec-invalid-reason').textContent = 'No token provided.';
    showOnly('#rec-invalid');
    return;
  }
  try {
    const ins = await inspectToken(TOKEN);
    const hint = ins.hint || {};
    const label = hint.handle ? `@${hint.handle}` : (hint.displayName || 'Web3Keys identity');
    $('#rec-hint-name').textContent = label;
    const when = hint.createdAt ? new Date(hint.createdAt).toLocaleString() : '—';
    $('#rec-hint-when').textContent = when;
    showOnly('#rec-ready');
  } catch (err) {
    $('#rec-invalid-reason').textContent = err.message || String(err);
    showOnly('#rec-invalid');
  }
}

async function buildWrappingsForDevice({ mnemonic, wif, passphrase, passkey }) {
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

  let prfBytes = passkey.prfFromCreate;
  if (!prfBytes) {
    try {
      prfBytes = await getPrfSecret({
        credentialIdB64: passkey.credentialId,
        prfSaltB64: passkey.prfSalt,
      });
    } catch (e) { console.warn('PRF unavailable:', e.message); }
  }
  let bioEnabled = false;
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

$('#form-recover').addEventListener('submit', async (e) => {
  e.preventDefault();
  const passphrase = $('#rec-passphrase').value;
  const devicePassphrase = $('#rec-device-passphrase').value;
  if (!passphrase || !devicePassphrase) return;

  try {
    status('Fetching encrypted backup…');
    const fetched = await consumeToken(TOKEN);
    const payload = fetched.payload;

    status('Decrypting…');
    let plain;
    try {
      plain = await decryptBackup(payload, passphrase);
    } catch {
      throw new Error('Could not decrypt — wrong passphrase, or backup is corrupted.');
    }

    const mnemonic = plain.mnemonic;
    const identity = deriveIdentity(mnemonic);
    const hint = fetched.hint || {};
    const displayName = plain.identity?.displayName || hint.displayName || '';
    const handle = plain.identity?.handle || hint.handle || null;

    status('Registering biometric on this device…');
    if (!isPlatformAuthAvailable()) throw new Error('WebAuthn not available in this browser.');
    const passkey = await registerPasskey({
      userId: randomBytes(16),
      userName: handle ? `${handle}@web3keys.com` : identity.address,
      displayName: displayName || 'Web3Keys identity',
    });

    status('Encrypting for this device…');
    const { wrappedWif, wrappedMnemonic } = await buildWrappingsForDevice({
      mnemonic, wif: identity.wif, passphrase: devicePassphrase, passkey,
    });

    const vault = {
      v: 1,
      createdAt: new Date().toISOString(),
      idPath: IDENTITY_PATH,
      pubKey: identity.pubKey,
      address: identity.address,
      handle,
      displayName,
      wrappedWif,
      wrappedMnemonic,
      claims: Array.isArray(plain.claims) ? plain.claims : [],
      cloudBackup: { enabled: true, email: null, lastBackupAt: payload?.updatedAt || null },
    };

    await putVault(vault);

    $('#rec-success-name').textContent = displayName || (handle ? `@${handle}` : 'friend');
    showOnly('#rec-success');
    status('Restored. Welcome back.', 'ok');
  } catch (err) {
    console.error(err);
    status(err.message || String(err), 'error');
  }
});

init().catch((e) => {
  console.error(e);
  $('#rec-invalid-reason').textContent = e.message || String(e);
  showOnly('#rec-invalid');
});
