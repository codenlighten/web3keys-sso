import { verifyAttestation, digestHex, CLAIM_TYPES } from './attestations.js';

const $ = (s) => document.querySelector(s);
const status = (m, k = 'info') => { const el = $('#status'); el.textContent = m || ''; el.dataset.kind = k; };

function row(label, value, mono = false) {
  const r = document.createElement('div');
  r.className = 'row';
  const l = document.createElement('span'); l.className = 'label'; l.textContent = label;
  const v = document.createElement(mono ? 'code' : 'span'); v.textContent = value;
  r.append(l, v);
  return r;
}

function b64urlEncode(s) {
  return btoa(s).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}

async function fetchHandleHint(pubKey) {
  try {
    const res = await fetch(`/api/paymail/${encodeURIComponent(pubKey)}`);
    if (!res.ok) return null;
    return res.json();
  } catch { return null; }
}

$('#form-verify').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('#verify-result').hidden = true;
  $('#v-details').innerHTML = '';
  let parsed;
  try {
    parsed = JSON.parse($('#att-json').value);
  } catch (err) {
    status('Not valid JSON.', 'error');
    return;
  }
  const bsv = window.bsv;
  const result = await verifyAttestation(parsed, bsv);

  const pill = $('#v-pill');
  if (result.verified && !result.expired) {
    pill.textContent = 'Verified';
    pill.dataset.kind = 'ok';
  } else if (result.verified && result.expired) {
    pill.textContent = 'Verified but expired';
    pill.dataset.kind = 'warn';
  } else {
    pill.textContent = `Failed: ${result.reason || 'invalid'}`;
    pill.dataset.kind = 'error';
  }

  const details = $('#v-details');
  details.innerHTML = '';

  const sub = parsed.subject || {};
  const iss = parsed.issuer || {};
  const samePerson = sub.pubKey && iss.pubKey && sub.pubKey === iss.pubKey;

  // Headline summary banner explaining what kind of claim this is.
  const banner = document.createElement('div');
  banner.className = 'claim-banner';
  const subLabel = sub.handle ? `@${sub.handle}` : (sub.pubKey ? sub.pubKey.slice(0, 12) + '…' : 'unknown');
  const issLabel = iss.handle ? `@${iss.handle}` : (iss.pubKey ? iss.pubKey.slice(0, 12) + '…' : 'unknown');
  if (samePerson) {
    banner.innerHTML = `<strong>${subLabel}</strong> made this self-claim.`;
  } else {
    banner.innerHTML = `<strong>${issLabel}</strong> attests this about <strong>${subLabel}</strong>.`;
  }
  details.append(banner);

  const claimDef = CLAIM_TYPES[parsed.claimType];
  if (claimDef && parsed.claim) {
    let summary;
    try { summary = claimDef.summary(parsed.claim); } catch {}
    if (summary) details.append(row(claimDef.label, summary));
  }

  details.append(row('Type', parsed.claimType ? `${parsed.type} / ${parsed.claimType}` : (parsed.type || '—')));
  details.append(row('Issued', parsed.issuedAt ? new Date(parsed.issuedAt).toLocaleString() : '—'));
  if (parsed.expiresAt) details.append(row('Expires', new Date(parsed.expiresAt).toLocaleString()));

  if (sub.handle || sub.pubKey) {
    details.append(row('Subject', sub.handle ? `@${sub.handle}` : sub.pubKey, !sub.handle));
    if (sub.handle && sub.pubKey) details.append(row('Subject pubkey', sub.pubKey, true));
  }
  if (iss.handle || iss.pubKey) {
    details.append(row('Issuer', iss.handle ? `@${iss.handle}` : iss.pubKey, !iss.handle));
    if (iss.handle && iss.pubKey) details.append(row('Issuer pubkey', iss.pubKey, true));
  }
  details.append(row('ID', parsed.id || '—', true));
  if (parsed.signature?.value) {
    details.append(row('Signature', parsed.signature.value.slice(0, 64) + '…', true));
  }
  const hex = await digestHex(parsed);
  details.append(row('Canonical digest', hex, true));

  // CTA to import into the wallet — passes the attestation via URL hash so it
  // doesn't end up in server logs.
  if (result.verified) {
    const importBox = document.createElement('div');
    importBox.className = 'welcome-cta';
    importBox.style.marginTop = '1rem';
    const importBtn = document.createElement('a');
    importBtn.className = 'primary button-link';
    importBtn.href = `/?import=${b64urlEncode(JSON.stringify(parsed))}`;
    importBtn.textContent = sub.pubKey ? 'Add to my Web3Keys wallet →' : 'Open Web3Keys →';
    importBox.append(importBtn);
    details.append(importBox);
  }

  $('#verify-result').hidden = false;
  status('');
});
