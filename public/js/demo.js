// Demo dApp: receives the idToken from Web3Keys SSO and verifies it.
// In a real dApp, verification should also happen server-side. This page
// runs the same logic client-side using the bsv library for illustration.

const CLIENT_ID = 'demo.web3keys.com';
const $ = (s) => document.querySelector(s);
const status = (m, k = 'info') => { const e = $('#status'); e.textContent = m || ''; e.dataset.kind = k; };

function fmtTime(unix) {
  const d = new Date(unix * 1000);
  return d.toLocaleString();
}

async function sha256Hex(text) {
  const bytes = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
}

async function verifyIdToken(idToken, expectedAud) {
  const parsed = Web3Keys.parseIdToken(idToken);
  const bsv = window.bsv;

  // 1. Digest
  const hex = await sha256Hex(parsed.signingInput);
  const Buffer = bsv.deps.Buffer;
  const digest = Buffer.from(hex, 'hex');

  // 2. Signature object
  const sig = bsv.crypto.Signature.fromString(parsed.signatureHex);

  // 3. Public key from payload.sub
  const pub = bsv.PublicKey.fromString(parsed.payload.sub);

  // 4. ECDSA verify
  let sigOk = false;
  try { sigOk = bsv.crypto.ECDSA.verify(digest, sig, pub); } catch { sigOk = false; }

  // 5. Audience / expiration / issuer
  const now = Math.floor(Date.now() / 1000);
  const audOk = parsed.payload.aud === expectedAud;
  const expOk = typeof parsed.payload.exp === 'number' && parsed.payload.exp > now;
  const issOk = parsed.payload.iss === 'web3keys.com';
  const algOk = parsed.header.alg === 'ECDSA-SHA256-secp256k1';

  return {
    valid: sigOk && audOk && expOk && issOk && algOk,
    sigOk, audOk, expOk, issOk, algOk,
    parsed,
  };
}

async function show(result) {
  const verification = await verifyIdToken(result.idToken, CLIENT_ID);
  $('#result-handle').textContent = result.handle ? `@${result.handle}` : '(none)';
  $('#result-name').textContent = result.displayName || '(none)';
  $('#result-pubkey').textContent = result.pubKey;
  $('#result-address').textContent = result.address;
  $('#result-aud').textContent = verification.parsed.payload.aud;
  $('#result-exp').textContent = fmtTime(verification.parsed.payload.exp);

  const pill = $('#result-verified');
  if (verification.valid) {
    pill.textContent = 'Verified ✓';
    pill.dataset.kind = 'ok';
  } else {
    const fails = ['sig', 'aud', 'exp', 'iss', 'alg'].filter((k) => !verification[`${k}Ok`]);
    pill.textContent = 'Failed: ' + fails.join(', ');
    pill.dataset.kind = 'error';
  }

  $('#result-token').textContent = result.idToken;
  $('#result-decoded').textContent = JSON.stringify({
    header: verification.parsed.header,
    payload: verification.parsed.payload,
  }, null, 2);
  $('#result').hidden = false;
}

document.addEventListener('web3keys-signin', async (e) => {
  status('Verifying token…');
  try {
    await show(e.detail);
    status('Signed in and verified.', 'ok');
  } catch (err) {
    console.error(err);
    status(err.message || String(err), 'error');
  }
});

document.addEventListener('web3keys-signin-error', (e) => {
  status(e.detail?.message || 'Sign-in failed.', 'error');
});

$('#btn-clear').addEventListener('click', () => {
  $('#result').hidden = true;
  status('');
});
