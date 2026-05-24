// BSV / mnemonic / wrap helpers. Pure functions — no DOM.

import { randomBytes, bytesToBase64, kekFromPassword, kekFromPrf, wrap } from '../crypto.js';
import { getPrfSecret } from '../biometric.js';

export const IDENTITY_PATH = "m/44'/236'/0'/0/0";
export const INFO_WIF = 'web3keys/v1/wif-wrap';
export const INFO_MNEMONIC = 'web3keys/v1/mnemonic-wrap';

export function bsvLib() {
  const lib = window.bsv;
  if (!lib) throw new Error('BSV library failed to load.');
  return lib;
}
export function MnemonicClass() {
  return window.bsvMnemonic || window.Mnemonic || (window.bsv && window.bsv.Mnemonic);
}

export function deriveIdentity(mnemonic) {
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

export function biometricAvailable(vault) { return !!vault.wrappedWif?.biometric; }

export async function buildWrappings({ mnemonic, wif, passphrase, passkey }) {
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

// Used by both create and restore to write the paymail registry record.
export async function attemptPaymailClaim({ vault, mnemonic, handle, displayName }) {
  if (!handle) return null;
  const bsv = bsvLib();
  const { buildClaimMessage, claimHandle } = await import('../profile.js');
  const ts = Date.now();
  const message = buildClaimMessage({ handle, pubKey: vault.pubKey, address: vault.address, ts });
  const priv = bsv.PrivateKey.fromWIF(deriveIdentity(mnemonic).wif);
  const signature = bsv.Message(message).sign(priv);
  return claimHandle({
    handle, pubKey: vault.pubKey, address: vault.address,
    displayName, signature, message,
  });
}

export function renderMnemonicGrid(node, mnemonic) {
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
