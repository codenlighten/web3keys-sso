import { listVaults } from './vault.js';
import { requestConsent } from './consent.js';
import { signHash } from './sign.js';
import { identiconSvg } from './identicon.js';
import { status } from './status.js';

const params = new URLSearchParams(location.search);
const CLIENT_ID = params.get('client_id') || 'unknown';
const NONCE = params.get('nonce') || '';
const SCOPE = params.get('scope') || 'profile';
// The origin of the page that opened this popup. Used as targetOrigin for postMessage.
// Falls back to '*' if absent; the idToken's `aud` binding is what actually keeps tokens safe.
const OPENER_ORIGIN = params.get('origin') || '*';

const ALG = 'ECDSA-SHA256-secp256k1';
const ISSUER = 'web3keys.com';
const TOKEN_TTL_SEC = 300;
const TOKEN_TYP = 'WEB3KEYS';
const TOKEN_VERSION = 1;

const $ = (s) => document.querySelector(s);

function bytesToBase64Url(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(bin).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function jsonToBase64Url(obj) {
  return bytesToBase64Url(new TextEncoder().encode(JSON.stringify(obj)));
}

async function sha256Hex(text) {
  const bytes = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
}

async function buildIdToken(vault, consent) {
  const header = { typ: TOKEN_TYP, alg: ALG, v: TOKEN_VERSION };
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: ISSUER,
    sub: vault.pubKey,
    aud: CLIENT_ID,
    iat: now,
    exp: now + TOKEN_TTL_SEC,
    nonce: NONCE,
    handle: vault.handle || null,
    displayName: vault.displayName || null,
    address: vault.address,
    scope: SCOPE,
  };
  const headerB64 = jsonToBase64Url(header);
  const payloadB64 = jsonToBase64Url(payload);
  const digestHex = await sha256Hex(`${headerB64}.${payloadB64}`);
  const { derHex } = await signHash(vault, consent, digestHex);
  return `${headerB64}.${payloadB64}.${derHex}`;
}

function postBack(message) {
  if (!window.opener) return;
  // Try the specific origin first; if it's '*' (unknown), broadcast.
  // The token's `aud` binding makes broadcast safe.
  try {
    window.opener.postMessage(message, OPENER_ORIGIN);
  } catch {
    window.opener.postMessage(message, '*');
  }
}

function postResult(payload) {
  postBack({ kind: 'web3keys:signin-result', payload });
}
function postError(error) {
  postBack({ kind: 'web3keys:signin-result', error });
}

async function signInWith(vault) {
  const consent = await requestConsent({
    kind: 'signin',
    title: `Sign in to ${CLIENT_ID}`,
    risk: 'normal',
    summary: [
      { label: 'As', value: vault.handle ? `${vault.handle}@web3keys.com` : 'unnamed identity', mono: !vault.handle },
      { label: 'Display name', value: vault.displayName || '(none)' },
      { label: 'You share', value: 'handle, display name, public key, address' },
      { label: 'Stays private', value: 'private key, recovery phrase, claims' },
      { label: 'Audience', value: CLIENT_ID, mono: true },
      { label: 'Valid for', value: '5 minutes' },
      ...(NONCE ? [{ label: 'Nonce', value: NONCE.slice(0, 12) + (NONCE.length > 12 ? '…' : ''), mono: true }] : []),
    ],
    biometricAvailable: !!vault.wrappedWif.biometric,
  });
  if (!consent.approved) {
    status('Cancelled.');
    return;
  }
  try {
    status('Signing identity assertion…');
    const idToken = await buildIdToken(vault, consent);
    postResult({
      pubKey: vault.pubKey,
      address: vault.address,
      handle: vault.handle || null,
      displayName: vault.displayName || null,
      idToken,
    });
    status('Signed in. You can close this window.', 'ok');
    setTimeout(() => window.close(), 300);
  } catch (err) {
    console.error(err);
    status(err.message || String(err), 'error');
    postError(err.message || String(err));
  }
}

async function renderChooser() {
  $('#sso-app-name').textContent = CLIENT_ID;
  document.title = `Sign in to ${CLIENT_ID} — Web3Keys`;

  const vaults = await listVaults();
  if (vaults.length === 0) {
    $('#sso-noidentity').hidden = false;
    return;
  }

  const wrap = $('#sso-identities');
  wrap.innerHTML = '';
  vaults.forEach((v) => {
    const row = document.createElement('button');
    row.type = 'button';
    row.className = 'identity-row';
    row.style.cursor = 'pointer';
    row.style.textAlign = 'left';
    row.style.width = '100%';
    row.style.fontWeight = '400';
    row.innerHTML = `
      <div class="identity-row-avatar">${identiconSvg(v.pubKey, 36)}</div>
      <div class="identity-row-text">
        <div class="identity-row-name">${escapeText(v.displayName || (v.handle ? '@' + v.handle : 'Unnamed'))}</div>
        <div class="identity-row-handle">${v.handle ? v.handle + '@web3keys.com' : v.address}</div>
      </div>
      <div class="identity-row-actions"><span class="muted">→</span></div>
    `;
    row.addEventListener('click', () => signInWith(v));
    wrap.append(row);
  });
  $('#sso-chooser').hidden = false;
}

function escapeText(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

$('#sso-noidentity-refresh').addEventListener('click', () => location.reload());
$('#sso-cancel').addEventListener('click', () => {
  postError('User cancelled');
  window.close();
});

window.addEventListener('beforeunload', () => {
  // If the user closes the popup without signing in, opener gets a "closed" signal via SDK's polling.
});

renderChooser().catch((e) => {
  console.error(e);
  status(e.message || String(e), 'error');
  postError(e.message || String(e));
});
