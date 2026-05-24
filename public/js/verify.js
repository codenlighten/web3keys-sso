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

  details.append(row('ID', parsed.id || '—', true));
  details.append(row('Type', parsed.claimType ? `${parsed.type} / ${parsed.claimType}` : (parsed.type || '—')));

  const claimDef = CLAIM_TYPES[parsed.claimType];
  if (claimDef && parsed.claim) {
    let summary;
    try { summary = claimDef.summary(parsed.claim); } catch {}
    if (summary) details.append(row(claimDef.label, summary));
  }

  details.append(row('Issued at', parsed.issuedAt || '—'));
  if (parsed.expiresAt) details.append(row('Expires at', parsed.expiresAt));

  const sub = parsed.subject || {};
  if (sub.handle) details.append(row('Subject', `@${sub.handle}`));
  if (sub.pubKey) details.append(row('Subject pubkey', sub.pubKey, true));

  const iss = parsed.issuer || {};
  if (iss.handle) details.append(row('Issuer', `@${iss.handle}`));
  if (iss.pubKey) details.append(row('Issuer pubkey', iss.pubKey, true));

  if (parsed.signature?.value) {
    details.append(row('Signature', parsed.signature.value.slice(0, 64) + '…', true));
  }

  const hex = await digestHex(parsed);
  details.append(row('Canonical digest', hex, true));

  $('#verify-result').hidden = false;
  status('');
});
