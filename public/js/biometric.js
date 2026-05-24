import { randomBytes, bytesToBase64, base64ToBytes } from './crypto.js';

const RP_NAME = 'Web3Keys';

function rpId() {
  // WebAuthn rpId must match the effective domain. localhost is allowed by browsers for dev.
  return location.hostname;
}

export function isPlatformAuthAvailable() {
  return !!(window.PublicKeyCredential && navigator.credentials);
}

export async function isUserVerifyingPlatformAuthenticatorAvailable() {
  if (!window.PublicKeyCredential?.isUserVerifyingPlatformAuthenticatorAvailable) return false;
  try {
    return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch {
    return false;
  }
}

export async function registerPasskey({ userId, userName, displayName }) {
  if (!isPlatformAuthAvailable()) {
    throw new Error('This browser does not support WebAuthn.');
  }

  const challenge = randomBytes(32);
  const prfSalt = randomBytes(32);

  const credential = await navigator.credentials.create({
    publicKey: {
      challenge,
      rp: { id: rpId(), name: RP_NAME },
      user: {
        id: userId,
        name: userName,
        displayName,
      },
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },    // ES256
        { type: 'public-key', alg: -257 },  // RS256 (fallback)
      ],
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'required',
        authenticatorAttachment: 'platform',
      },
      timeout: 60000,
      attestation: 'none',
      extensions: {
        prf: { eval: { first: prfSalt } },
      },
    },
  });

  if (!credential) throw new Error('Passkey creation was cancelled.');

  const credentialId = new Uint8Array(credential.rawId);
  const ext = credential.getClientExtensionResults?.() || {};
  const prfEnabled = !!ext.prf?.enabled || !!ext.prf?.results?.first;
  const prfFromCreate = ext.prf?.results?.first ? new Uint8Array(ext.prf.results.first) : null;

  return {
    credentialId: bytesToBase64(credentialId),
    prfSalt: bytesToBase64(prfSalt),
    prfEnabled,
    prfFromCreate,
  };
}

export async function getPrfSecret({ credentialIdB64, prfSaltB64 }) {
  const credentialId = base64ToBytes(credentialIdB64);
  const prfSalt = base64ToBytes(prfSaltB64);
  const challenge = randomBytes(32);

  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge,
      rpId: rpId(),
      allowCredentials: [{ id: credentialId, type: 'public-key' }],
      userVerification: 'required',
      timeout: 60000,
      extensions: {
        prf: { eval: { first: prfSalt } },
      },
    },
  });

  if (!assertion) throw new Error('Biometric was cancelled.');

  const ext = assertion.getClientExtensionResults?.() || {};
  const out = ext.prf?.results?.first;
  if (!out) {
    throw new Error('Biometric PRF is not supported by this browser/authenticator. Use the password fallback.');
  }
  return new Uint8Array(out);
}
