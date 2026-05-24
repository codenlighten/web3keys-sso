import {
  verifyAttestation, digestHex, CLAIM_TYPES,
  detectShape, verifyDisclosures, DISCLOSURE,
} from './attestations.js';

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

function fieldRow(label, value, opts = {}) {
  const r = document.createElement('div');
  r.className = 'row' + (opts.highlight ? ' highlight' : '');
  const l = document.createElement('span'); l.className = 'label'; l.textContent = label;
  const v = document.createElement(opts.mono ? 'code' : 'span');
  v.textContent = value;
  if (opts.muted) v.style.color = 'var(--text-muted)';
  if (opts.italic) v.style.fontStyle = 'italic';
  r.append(l, v);
  return r;
}

function b64urlEncode(s) {
  return btoa(s).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function labelFor(party) {
  if (!party) return 'unknown';
  if (party.handle) return `@${party.handle}`;
  if (party.pubKey) return party.pubKey.slice(0, 12) + '…';
  return 'unknown';
}

function renderBanner(parts) {
  const banner = document.createElement('div');
  banner.className = 'claim-banner';
  banner.innerHTML = parts.join(' ');
  return banner;
}

function setPill(verified, expired, extra) {
  const pill = $('#v-pill');
  if (verified && !expired) {
    pill.textContent = extra ? `Verified — ${extra}` : 'Verified';
    pill.dataset.kind = 'ok';
  } else if (verified && expired) {
    pill.textContent = 'Verified but expired';
    pill.dataset.kind = 'warn';
  } else {
    pill.textContent = typeof verified === 'string' ? verified : `Failed: ${verified?.reason || extra || 'invalid'}`;
    pill.dataset.kind = 'error';
  }
}

async function renderAttestation(details, attestation, bsv) {
  const result = await verifyAttestation(attestation, bsv);
  const sub = attestation.subject || {};
  const iss = attestation.issuer || {};
  const samePerson = sub.pubKey && iss.pubKey && sub.pubKey === iss.pubKey;
  details.append(renderBanner([
    samePerson
      ? `<strong>${labelFor(sub)}</strong> made this self-claim.`
      : `<strong>${labelFor(iss)}</strong> attests this about <strong>${labelFor(sub)}</strong>.`,
  ]));

  const claimDef = CLAIM_TYPES[attestation.claimType];
  if (claimDef && attestation.claim) {
    let summary;
    try { summary = claimDef.summary(attestation.claim); } catch {}
    if (summary) details.append(row(claimDef.label, summary));
  } else if (claimDef && attestation.claimCommitments) {
    details.append(row(claimDef.label, '(committed — hidden until disclosure)'));
  }

  details.append(row('Type', attestation.claimType ? `${attestation.type} / ${attestation.claimType}` : (attestation.type || '—')));
  details.append(row('Mode', attestation.disclosure === DISCLOSURE ? 'Selective disclosure (salt+SHA-256)' : 'Full disclosure'));
  details.append(row('Issued', attestation.issuedAt ? new Date(attestation.issuedAt).toLocaleString() : '—'));
  if (attestation.expiresAt) details.append(row('Expires', new Date(attestation.expiresAt).toLocaleString()));

  if (sub.handle || sub.pubKey) {
    details.append(row('Subject', sub.handle ? `@${sub.handle}` : sub.pubKey, !sub.handle));
    if (sub.handle && sub.pubKey) details.append(row('Subject pubkey', sub.pubKey, true));
  }
  if (iss.handle || iss.pubKey) {
    details.append(row('Issuer', iss.handle ? `@${iss.handle}` : iss.pubKey, !iss.handle));
    if (iss.handle && iss.pubKey) details.append(row('Issuer pubkey', iss.pubKey, true));
  }
  details.append(row('ID', attestation.id || '—', true));
  if (attestation.signature?.value) {
    details.append(row('Signature', attestation.signature.value.slice(0, 64) + '…', true));
  }
  const hex = await digestHex(attestation);
  details.append(row('Canonical digest', hex, true));
  return result;
}

async function renderPresentation(details, presentation, bsv) {
  const attestation = presentation.attestation || {};
  const result = await verifyAttestation(attestation, bsv);
  if (!result.verified) {
    return { verified: false, reason: 'attestation_signature_invalid', inner: result };
  }
  if (attestation.disclosure !== DISCLOSURE) {
    return { verified: false, reason: 'attestation_not_selectively_disclosable', inner: result };
  }
  const check = await verifyDisclosures(attestation, presentation.disclosures || {});

  const sub = attestation.subject || {};
  const iss = attestation.issuer || {};
  const presenter = presentation.presenter || sub;
  const samePerson = sub.pubKey && iss.pubKey && sub.pubKey === iss.pubKey;
  const presenterIsSubject = presenter.pubKey && sub.pubKey && presenter.pubKey === sub.pubKey;

  details.append(renderBanner([
    samePerson
      ? `<strong>${labelFor(sub)}</strong> presents a self-claim.`
      : `<strong>${labelFor(presenter)}</strong> presents <strong>${labelFor(iss)}</strong>'s claim about <strong>${labelFor(sub)}</strong>.`,
    presentation.audience ? `Audience: <strong>${escapeText(presentation.audience)}</strong>.` : '',
    presenterIsSubject ? '' : '<span style="color:var(--warn)"> ⚠ Presenter is not the subject.</span>',
  ].filter(Boolean)));

  // Field-by-field disclosure summary
  const fields = attestation.claimSchema || Object.keys(attestation.claimCommitments || {});
  const fieldsBox = document.createElement('div');
  fieldsBox.className = 'consent-summary';
  fieldsBox.style.padding = '0';
  fields.forEach((k) => {
    const disclosed = (presentation.disclosures || {})[k];
    const r = document.createElement('div');
    r.className = 'consent-row' + (disclosed ? ' highlight' : '');
    const l = document.createElement('span'); l.className = 'label'; l.textContent = k;
    const v = document.createElement('span'); v.className = 'value';
    if (disclosed) {
      const fieldOk = check.results?.[k]?.ok;
      v.textContent = (fieldOk ? '' : '⚠ ') + formatVal(disclosed.value);
      if (!fieldOk) v.style.color = 'var(--danger)';
    } else {
      v.textContent = '(undisclosed)';
      v.style.color = 'var(--text-muted)';
      v.style.fontStyle = 'italic';
    }
    r.append(l, v);
    fieldsBox.append(r);
  });
  details.append(fieldsBox);

  // Common metadata
  details.append(row('Type', attestation.claimType ? `${attestation.type} / ${attestation.claimType}` : (attestation.type || '—')));
  details.append(row('Issued', attestation.issuedAt ? new Date(attestation.issuedAt).toLocaleString() : '—'));
  if (attestation.expiresAt) details.append(row('Expires', new Date(attestation.expiresAt).toLocaleString()));
  details.append(row('Presented', presentation.presentedAt ? new Date(presentation.presentedAt).toLocaleString() : '—'));
  details.append(row('Subject', labelFor(sub), !sub.handle));
  details.append(row('Issuer', labelFor(iss), !iss.handle));
  details.append(row('Presenter', labelFor(presenter), !presenter.handle));

  return {
    verified: check.ok,
    expired: result.expired,
    disclosed: Object.keys(presentation.disclosures || {}).length,
    fieldCount: fields.length,
    failingFields: Object.entries(check.results || {}).filter(([, r]) => !r.ok).map(([k]) => k),
  };
}

function escapeText(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
function formatVal(v) {
  if (v == null) return '—';
  if (typeof v === 'string') return v.length > 80 ? v.slice(0, 80) + '…' : v;
  try { return JSON.stringify(v); } catch { return String(v); }
}

$('#form-verify').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('#verify-result').hidden = true;
  $('#v-details').innerHTML = '';
  let parsed;
  try { parsed = JSON.parse($('#att-json').value); }
  catch { status('Not valid JSON.', 'error'); return; }

  const bsv = window.bsv;
  const shape = detectShape(parsed);
  const details = $('#v-details');

  if (shape === 'unknown') {
    setPill('Failed: unrecognized JSON shape');
    $('#verify-result').hidden = false;
    return;
  }

  if (shape === 'attestation') {
    const r = await renderAttestation(details, parsed, bsv);
    setPill(r.verified, r.expired, r.verified ? null : r.reason);
    addImportButton(details, parsed, r.verified);
  } else if (shape === 'package') {
    // A package is "here's a signed attestation plus its openings". Verify the
    // attestation signature, then verify every opening matches its commitment.
    const r = await renderAttestation(details, parsed.attestation, bsv);
    if (r.verified) {
      const check = await verifyDisclosures(parsed.attestation, parsed.openings || {});
      if (!check.ok) {
        setPill('Failed: openings do not match commitments');
      } else {
        setPill(r.verified, r.expired, 'full package, openings match');
      }
    } else {
      setPill(r);
    }
    addImportButton(details, parsed, r.verified);
  } else if (shape === 'presentation') {
    const r = await renderPresentation(details, parsed, bsv);
    if (r.verified === false) {
      setPill(`Failed: ${r.reason || 'invalid'}`);
    } else if (r.failingFields && r.failingFields.length > 0) {
      setPill(`Failed: bad opening for ${r.failingFields.join(', ')}`);
    } else {
      setPill(true, r.expired, `${r.disclosed} of ${r.fieldCount} fields revealed`);
    }
  }

  $('#verify-result').hidden = false;
  status('');
});

function addImportButton(details, parsed, verified) {
  if (!verified) return;
  const importBox = document.createElement('div');
  importBox.className = 'welcome-cta';
  importBox.style.marginTop = '1rem';
  const importBtn = document.createElement('a');
  importBtn.className = 'primary button-link';
  importBtn.href = `/app?import=${b64urlEncode(JSON.stringify(parsed))}`;
  importBtn.textContent = 'Add to my Web3Keys wallet →';
  importBox.append(importBtn);
  details.append(importBox);
}
