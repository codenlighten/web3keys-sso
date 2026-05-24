import { base64ToBytes, kekFromPassword, kekFromPrf, unwrap } from './crypto.js';
import { getPrfSecret } from './biometric.js';

const INFO_WIF = 'web3keys/v1/wif-wrap';

function bsvLib() {
  const lib = window.bsv;
  if (!lib) throw new Error('BSV library failed to load.');
  return lib;
}

async function unlockWif(vault, consent) {
  if (consent.method === 'biometric') {
    const w = vault.wrappedWif.biometric;
    if (!w) throw new Error('Biometric is not configured for this account.');
    const prfBytes = await getPrfSecret({
      credentialIdB64: w.credentialId,
      prfSaltB64: w.prfSalt,
    });
    const kek = await kekFromPrf(prfBytes, INFO_WIF);
    prfBytes.fill(0);
    return unwrap(kek, w);
  }
  if (consent.method === 'password') {
    if (!consent.password) throw new Error('Password required.');
    const w = vault.wrappedWif.password;
    const kek = await kekFromPassword(consent.password, base64ToBytes(w.salt), w.iters);
    try {
      return await unwrap(kek, w);
    } catch {
      throw new Error('Wrong password.');
    }
  }
  throw new Error('Unknown unlock method.');
}

async function withPrivateKey(vault, consent, fn) {
  const wif = await unlockWif(vault, consent);
  const bsv = bsvLib();
  const priv = bsv.PrivateKey.fromWIF(wif);
  try {
    return await fn(priv, bsv);
  } finally {
    // JS strings are immutable so we cannot reliably zero `wif`.
    // The unlocked WIF lifetime is bounded to this stack frame.
  }
}

// ---- Message ----
export async function signMessage(vault, consent, message) {
  return withPrivateKey(vault, consent, (priv, bsv) => {
    const sig = bsv.Message(message).sign(priv);
    const address = bsv.Address.fromPrivateKey(priv).toString();
    const verified = bsv.Message(message).verify(address, sig);
    return { signature: sig, verified, address };
  });
}

// ---- Transaction ----
export function parseTransaction(rawHex, utxoContext = []) {
  const bsv = bsvLib();
  const tx = new bsv.Transaction(rawHex);
  for (const ctx of utxoContext) {
    if (typeof ctx.index !== 'number') continue;
    const input = tx.inputs[ctx.index];
    if (!input) continue;
    input.output = new bsv.Transaction.Output({
      script: bsv.Script.fromHex(ctx.scriptPubKey),
      satoshis: ctx.satoshis,
    });
  }
  return tx;
}

export function summarizeTransaction(tx, ourAddress) {
  const inputs = tx.inputs.map((inp, i) => {
    const prev = inp.output;
    let address = null;
    if (prev?.script) {
      try { address = prev.script.toAddress().toString(); } catch {}
    }
    return {
      index: i,
      prevTxId: inp.prevTxId.toString('hex'),
      prevIndex: inp.outputIndex,
      satoshis: prev?.satoshis ?? null,
      address,
    };
  });
  const outputs = tx.outputs.map((out, i) => {
    let address = null;
    let isData = false;
    try {
      if (out.script.isPublicKeyHashOut()) address = out.script.toAddress().toString();
      else if (out.script.isDataOut()) isData = true;
    } catch {}
    return { index: i, satoshis: out.satoshis, address, isData, scriptHex: out.script.toHex() };
  });
  const allInputsValued = inputs.every((i) => i.satoshis != null);
  const totalIn = allInputsValued ? inputs.reduce((a, b) => a + b.satoshis, 0) : null;
  const totalOut = outputs.reduce((a, b) => a + b.satoshis, 0);
  const fee = totalIn != null ? totalIn - totalOut : null;
  const toUs = outputs
    .filter((o) => o.address === ourAddress)
    .reduce((a, b) => a + b.satoshis, 0);
  const fromUs = inputs
    .filter((i) => i.address === ourAddress)
    .reduce((a, b) => a + (b.satoshis || 0), 0);
  const ourInputCount = inputs.filter((i) => i.address === ourAddress).length;
  return { inputs, outputs, totalIn, totalOut, fee, toUs, fromUs, ourInputCount };
}

export async function signTransaction(vault, consent, tx) {
  return withPrivateKey(vault, consent, (priv, bsv) => {
    tx.sign(priv);
    return { rawHex: tx.toString(), txid: tx.id };
  });
}

// ---- BRC-77 raw-hash signing ----
export async function signHash(vault, consent, digestHex) {
  if (!/^[0-9a-fA-F]{64}$/.test(digestHex)) {
    throw new Error('Hash must be exactly 32 bytes (64 hex chars).');
  }
  return withPrivateKey(vault, consent, (priv, bsv) => {
    const Buffer = bsv.deps.Buffer;
    const digest = Buffer.from(digestHex, 'hex');
    const sig = bsv.crypto.ECDSA.sign(digest, priv);
    return {
      derHex: sig.toString(),
      pubKey: priv.toPublicKey().toString('hex'),
    };
  });
}

// ---- ECIES encrypt / decrypt ----
function eciesInstance(bsv, priv, otherPub) {
  if (!bsv.ECIES) throw new Error('ECIES module not loaded.');
  const ecies = new bsv.ECIES();
  ecies.privateKey(priv);
  if (otherPub) ecies.publicKey(otherPub);
  return ecies;
}

export async function encryptForRecipient(vault, consent, plaintext, recipientPubKeyHex) {
  return withPrivateKey(vault, consent, (priv, bsv) => {
    const pub = bsv.PublicKey.fromString(recipientPubKeyHex);
    const ecies = eciesInstance(bsv, priv, pub);
    const Buffer = bsv.deps.Buffer;
    const ct = ecies.encrypt(Buffer.from(plaintext, 'utf8'));
    return { ciphertextB64: ct.toString('base64') };
  });
}

export async function decryptIncoming(vault, consent, ciphertextB64) {
  return withPrivateKey(vault, consent, (priv, bsv) => {
    const ecies = eciesInstance(bsv, priv);
    const Buffer = bsv.deps.Buffer;
    const ct = Buffer.from(ciphertextB64, 'base64');
    try {
      const pt = ecies.decrypt(ct);
      return { plaintext: pt.toString('utf8') };
    } catch (e) {
      throw new Error('Could not decrypt — not intended for this key, or corrupt ciphertext.');
    }
  });
}

// ---- Public-key utilities ----
export function pubKeyFromMnemonicMatchesVault(_) { /* placeholder for future tools */ }
