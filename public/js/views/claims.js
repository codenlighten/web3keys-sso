// Claims tab: issue self / about-other / import / present / verify / copy /
// delete. Also the SD present modal.

import { $, activeVault, invalidateVault, status, emitVaultChanged } from '../lib/state.js';
import { putVault } from '../vault.js';
import { requestConsent } from '../consent.js';
import { signAttestation } from '../sign.js';
import { resolveSubject } from '../profile.js';
import {
  buildAttestation, CLAIM_TYPES, verifyAttestation,
  buildSdAttestation, buildClaimPackage, buildPresentation,
  detectShape, verifyDisclosures, DISCLOSURE,
} from '../attestations.js';
import { biometricAvailable, bsvLib } from '../lib/identity.js';
import { escapeText, formatPresetValue } from '../lib/fmt.js';

let claimMode = 'self';
let resolvedSubject = null;

export function setClaimMode(mode) {
  claimMode = mode;
  document.querySelectorAll('[data-claim-mode]').forEach((el) => {
    if (el.tagName === 'BUTTON' && el.dataset.claimMode) {
      el.setAttribute('aria-selected', el.dataset.claimMode === mode ? 'true' : 'false');
    }
  });
  $('#form-claim').hidden = mode === 'import';
  $('#form-claim-import').hidden = mode !== 'import';
  $('#claim-subject-label').hidden = mode !== 'other';
  $('#claim-subject').required = mode === 'other';
  $('#claim-submit').textContent = mode === 'other' ? 'Sign claim about subject' : 'Sign claim';
  if (mode !== 'other') resolvedSubject = null;
}

function renderClaimFields(type) {
  const wrap = $('#claim-fields');
  wrap.innerHTML = '';
  const def = CLAIM_TYPES[type];
  if (!def) return;
  for (const f of def.fields) {
    const label = document.createElement('label');
    const span = document.createElement('span');
    span.textContent = f.label;
    label.append(span);
    const input = f.type === 'json' ? document.createElement('textarea') : document.createElement('input');
    if (f.type === 'json') input.rows = 4;
    else input.type = f.type === 'email' ? 'email' : (f.type === 'url' ? 'url' : 'text');
    input.id = `claim-field-${f.key}`;
    input.dataset.fieldKey = f.key;
    input.dataset.fieldType = f.type;
    if (f.required) input.required = true;
    if (f.placeholder) input.placeholder = f.placeholder;
    label.append(input);
    wrap.append(label);
  }
}

function collectClaim(type) {
  const def = CLAIM_TYPES[type];
  if (!def) throw new Error('Pick a claim type.');
  const out = {};
  for (const f of def.fields) {
    const el = $(`#claim-field-${f.key}`);
    if (!el) continue;
    const v = el.value.trim();
    if (!v && f.required) throw new Error(`Missing field: ${f.label}`);
    if (f.type === 'json') {
      if (!v) continue;
      try { Object.assign(out, JSON.parse(v)); }
      catch { throw new Error('Custom JSON did not parse.'); }
    } else if (v) {
      out[f.key] = v;
    }
  }
  return out;
}

function claimDirection(vault, claim) {
  if (claim.direction) return claim.direction;
  const me = vault.pubKey;
  if (claim.issuer?.pubKey === me && claim.subject?.pubKey === me) return 'selfclaim';
  if (claim.issuer?.pubKey === me) return 'issued';
  return 'received';
}

function renderClaimCard(c, idx, direction, vault) {
  const def = CLAIM_TYPES[c.claimType];
  const card = document.createElement('div');
  card.className = 'claim-card';
  const label = def?.label || c.claimType;
  let summary = '';
  try { summary = def?.summary(c.claim) || ''; } catch {}

  const subjectLabel = c.subject?.handle ? `@${c.subject.handle}` : (c.subject?.pubKey?.slice(0, 12) + '…');
  const issuerLabel = c.issuer?.handle ? `@${c.issuer.handle}` : (c.issuer?.pubKey?.slice(0, 12) + '…');

  let directionBadge = '';
  if (direction === 'issued') directionBadge = `<span class="claim-card-direction">→ about ${escapeText(subjectLabel)}</span>`;
  else if (direction === 'received') directionBadge = `<span class="claim-card-direction">← from ${escapeText(issuerLabel)}</span>`;

  const hasOpenings = c._openings && Object.keys(c._openings).length > 0;
  const sdBadge = c.disclosure ? '<span class="claim-card-direction" style="margin-left:6px">SD</span>' : '';

  card.innerHTML = `
    <div class="claim-card-head">
      <span class="claim-card-type">${escapeText(label)}${sdBadge}</span>
      <span class="claim-card-id">${c.id.slice(0, 8)}…</span>
    </div>
    <div class="claim-card-summary">${summary ? escapeText(summary) : (c.claimCommitments ? '<span class="muted">(hidden — selectively disclosable)</span>' : '<span class="muted">(no preview)</span>')}</div>
    ${directionBadge ? `<div class="claim-card-meta">${directionBadge}</div>` : ''}
    <div class="claim-card-actions">
      ${hasOpenings ? `<button class="primary" data-act="present" data-idx="${idx}">Present…</button>` : ''}
      <button class="ghost" data-act="copy" data-idx="${idx}">Copy JSON</button>
      <button class="ghost" data-act="verify" data-idx="${idx}">Verify</button>
      <button class="ghost danger" data-act="delete" data-idx="${idx}">Delete</button>
    </div>
  `;
  return card;
}

export function renderClaims(vault) {
  const list = $('#claims-list');
  list.innerHTML = '';
  const claims = vault.claims || [];
  if (claims.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'muted small';
    empty.textContent = 'No claims yet. Sign one above, or import one someone sent you.';
    list.append(empty);
    return;
  }
  const groups = { selfclaim: [], issued: [], received: [] };
  claims.forEach((c, idx) => groups[claimDirection(vault, c)].push({ c, idx }));

  function renderGroup(title, items) {
    if (items.length === 0) return;
    const h = document.createElement('h3');
    h.className = 'claims-group-title';
    h.textContent = title;
    list.append(h);
    items.forEach(({ c, idx }) => list.append(renderClaimCard(c, idx, claimDirection(vault, c), vault)));
  }
  renderGroup('Self-claims', groups.selfclaim);
  renderGroup('Issued (you signed about others)', groups.issued);
  renderGroup('Received (signed about you by others)', groups.received);
}

function attachSubjectResolution() {
  const input = $('#claim-subject');
  const feedback = $('#claim-subject-feedback');
  let timer = null;
  const upd = (msg, kind) => { feedback.textContent = msg; feedback.dataset.kind = kind || ''; };
  input.addEventListener('input', () => {
    resolvedSubject = null;
    clearTimeout(timer);
    const v = input.value.trim();
    if (!v) { upd('Enter a Web3Keys handle or a compressed secp256k1 public key.', ''); return; }
    if (/^0[23][0-9a-fA-F]{64}$/.test(v)) {
      resolvedSubject = { pubKey: v.toLowerCase() };
      upd('✓ Public key accepted.', 'ok');
      return;
    }
    upd('Looking up handle…', '');
    timer = setTimeout(async () => {
      try {
        const subj = await resolveSubject(v);
        resolvedSubject = subj;
        upd(`✓ ${subj.handle ? '@' + subj.handle : 'pubkey'} → ${subj.pubKey.slice(0, 12)}…`, 'ok');
      } catch (e) {
        resolvedSubject = null;
        upd(e.message || 'Lookup failed.', 'error');
      }
    }, 320);
  });
}

async function signAndStoreClaim({ vault, claim, type, subject, direction, expiresAt, selectiveDisclosure }) {
  const issuer = {
    pubKey: vault.pubKey, address: vault.address,
    ...(vault.handle ? { handle: vault.handle } : {}),
  };
  let unsigned, openings = null;
  if (selectiveDisclosure) {
    const built = await buildSdAttestation({ claimType: type, subject, issuer, claim, expiresAt });
    unsigned = built.unsigned;
    openings = built.openings;
  } else {
    unsigned = buildAttestation({ claimType: type, subject, issuer, claim, expiresAt });
  }
  const def = CLAIM_TYPES[type];
  let summary = '';
  try { summary = def.summary(claim); } catch {}
  const aboutLabel = subject.handle ? `@${subject.handle}` :
    (subject.pubKey === vault.pubKey ? (vault.handle ? `@${vault.handle} (you)` : 'you') : subject.pubKey);

  const consent = await requestConsent({
    kind: selectiveDisclosure ? 'attestation-sd' : 'attestation',
    title: direction === 'issued'
      ? `Issue ${selectiveDisclosure ? 'SD ' : ''}claim about ${aboutLabel}`
      : `Sign ${selectiveDisclosure ? 'SD ' : ''}self-claim: ${def.label}`,
    risk: direction === 'issued' ? 'normal' : 'low',
    summary: [
      { label: 'About', value: aboutLabel, mono: !subject.handle && subject.pubKey !== vault.pubKey },
      { label: 'Claim type', value: def.label },
      { label: 'Detail', value: summary || '(custom payload)' },
      { label: 'Issued by', value: vault.handle ? `@${vault.handle} (you)` : 'you' },
      { label: 'Mode', value: selectiveDisclosure ? 'Selective disclosure' : 'Full disclosure' },
      ...(expiresAt ? [{ label: 'Expires', value: expiresAt.slice(0, 10) }] : []),
    ],
    detail: JSON.stringify({ ...unsigned }, null, 2),
    warning: direction === 'issued'
      ? 'This claim says something about someone else over your signature. Make sure it is true and that you want the subject to be able to present it.'
      : (selectiveDisclosure ? 'Signed attestation will contain only hash commitments of each field. The holder can reveal any subset later.' : null),
    biometricAvailable: biometricAvailable(vault),
  });
  if (!consent.approved) return null;

  const signed = await signAttestation(vault, consent, unsigned);
  signed.direction = direction;
  if (openings) signed._openings = openings;
  vault.claims = vault.claims || [];
  vault.claims.unshift(signed);
  await putVault(vault);
  return signed;
}

function openPresentModal(claim, vault) {
  return new Promise((resolve) => {
    const backdrop = document.createElement('div');
    backdrop.className = 'consent-backdrop';
    const fields = (claim.claimSchema || Object.keys(claim._openings || {})).slice();
    const openings = claim._openings || {};

    function close(result) {
      backdrop.remove();
      document.removeEventListener('keydown', onKey);
      resolve(result);
    }
    function onKey(e) { if (e.key === 'Escape') close(null); }
    document.addEventListener('keydown', onKey);

    const fieldsHtml = fields.map((k) => `
      <label class="inline" style="justify-content:space-between;gap:0.5rem">
        <span style="display:flex;align-items:center;gap:0.5rem">
          <input type="checkbox" data-field="${escapeText(k)}" checked />
          <strong>${escapeText(k)}</strong>
        </span>
        <code style="font-size:0.75rem;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escapeText(formatPresetValue(openings[k]?.value))}</code>
      </label>
    `).join('');

    const def = CLAIM_TYPES[claim.claimType];
    backdrop.innerHTML = `
      <div class="consent-card" role="dialog" aria-modal="true">
        <header class="consent-header">
          <div class="consent-kind">presentation</div>
          <span class="pill" data-kind="info">Selective</span>
        </header>
        <h2 class="consent-title">Present ${escapeText(def?.label || claim.claimType)}</h2>
        <div class="consent-requester">
          <span class="label">Issuer</span>
          <span>${claim.issuer?.handle ? '@' + escapeText(claim.issuer.handle) : escapeText(claim.issuer?.pubKey?.slice(0, 12) + '…')}</span>
        </div>
        <p class="muted small">Choose which fields to reveal. Hidden fields stay as commitments only — the verifier can confirm the claim was signed, but can't see what they say.</p>
        <div class="consent-summary" style="padding:0.5rem 0.75rem;display:flex;flex-direction:column;gap:0.5rem">${fieldsHtml}</div>
        <label>
          <span>Audience (optional)</span>
          <input type="text" id="present-audience" placeholder="e.g. recruiter.example.com" autocomplete="off" />
        </label>
        <div class="consent-actions">
          <button class="ghost" type="button" data-pa="cancel">Cancel</button>
          <button class="primary" type="button" data-pa="ok">Generate presentation</button>
        </div>
      </div>
    `;
    document.body.append(backdrop);
    backdrop.querySelector('[data-pa="cancel"]').addEventListener('click', () => close(null));
    backdrop.querySelector('[data-pa="ok"]').addEventListener('click', () => {
      const checks = backdrop.querySelectorAll('input[type=checkbox][data-field]');
      const fieldsToReveal = Array.from(checks).filter((c) => c.checked).map((c) => c.dataset.field);
      const audience = backdrop.querySelector('#present-audience').value.trim() || null;
      const publicAttestation = { ...claim };
      delete publicAttestation._openings;
      delete publicAttestation.direction;
      const presentation = buildPresentation({
        attestation: publicAttestation,
        openings,
        fieldsToReveal,
        audience,
        presenter: { pubKey: vault.pubKey, ...(vault.handle ? { handle: vault.handle } : {}) },
      });
      $('#claim-output-title').textContent = 'Presentation';
      $('#claim-output-desc').textContent = audience
        ? `Send this to ${audience}. They paste it into /verify; revealed fields show as values, hidden fields show as "(undisclosed)".`
        : 'Send this to your verifier. They paste it into /verify; revealed fields show as values, hidden fields show as "(undisclosed)".';
      $('#claim-output-json').textContent = JSON.stringify(presentation, null, 2);
      $('#claim-output').hidden = false;
      $('#claim-output').scrollIntoView({ behavior: 'smooth', block: 'center' });
      close(presentation);
      status(`Generated presentation revealing ${fieldsToReveal.length} of ${fields.length} fields.`, 'ok');
    });
  });
}

export function wireClaims() {
  $('#claim-type').addEventListener('change', (e) => renderClaimFields(e.target.value));

  document.querySelectorAll('[data-claim-mode]').forEach((tab) => {
    if (tab.tagName !== 'BUTTON' || !tab.dataset.claimMode) return;
    tab.addEventListener('click', () => setClaimMode(tab.dataset.claimMode));
  });
  attachSubjectResolution();
  setClaimMode('self');

  $('#form-claim').addEventListener('submit', async (e) => {
    e.preventDefault();
    const vault = await activeVault();
    if (!vault) return;
    const type = $('#claim-type').value;
    const expires = $('#claim-expires').value;
    const selectiveDisclosure = $('#claim-sd').checked;

    let subject, direction;
    if (claimMode === 'other') {
      if (!resolvedSubject) { status('Resolve a valid subject first.', 'error'); return; }
      subject = { ...resolvedSubject };
      direction = subject.pubKey === vault.pubKey ? 'selfclaim' : 'issued';
    } else {
      subject = { pubKey: vault.pubKey, address: vault.address, ...(vault.handle ? { handle: vault.handle } : {}) };
      direction = 'selfclaim';
    }

    let claim;
    try { claim = collectClaim(type); }
    catch (err) { status(err.message, 'error'); return; }
    const expiresAt = expires ? new Date(expires + 'T23:59:59Z').toISOString() : undefined;

    try {
      status('Signing claim…');
      const signed = await signAndStoreClaim({ vault, claim, type, subject, direction, expiresAt, selectiveDisclosure });
      if (!signed) { status('Cancelled.'); return; }
      invalidateVault();
      const fresh = await activeVault();
      renderClaims(fresh);
      $('#form-claim').reset();
      $('#claim-fields').innerHTML = '';

      if (direction === 'issued') {
        const publicAttestation = { ...signed };
        delete publicAttestation._openings;
        delete publicAttestation.direction;
        const output = selectiveDisclosure
          ? buildClaimPackage({ attestation: publicAttestation, openings: signed._openings || {} })
          : publicAttestation;
        $('#claim-output-title').textContent = selectiveDisclosure ? 'Signed claim package' : 'Signed claim';
        $('#claim-output-desc').textContent = selectiveDisclosure
          ? 'This package contains the signed commitments + the openings the subject needs to present any field later. Send the whole JSON to the subject privately.'
          : 'Copy this JSON and send it to the subject. They can paste it into "Import a claim" to save it.';
        $('#claim-output-json').textContent = JSON.stringify(output, null, 2);
        $('#claim-output').hidden = false;
        if (selectiveDisclosure) {
          // Don't retain someone else's openings locally.
          delete signed._openings;
          await putVault(fresh);
          invalidateVault();
        }
        status(`Claim signed. Copy and send it to ${subject.handle ? '@' + subject.handle : 'them'}.`, 'ok');
      } else {
        status(selectiveDisclosure ? 'Self-claim signed with selective disclosure.' : 'Self-claim signed.', 'ok');
      }
      $('#claim-sd').checked = false;
    } catch (err) {
      console.error(err); status(err.message || String(err), 'error');
    }
  });

  $('#claim-output-copy').addEventListener('click', async () => {
    await navigator.clipboard.writeText($('#claim-output-json').textContent);
    status('Claim JSON copied.', 'ok');
  });
  $('#claim-output-done').addEventListener('click', () => {
    $('#claim-output').hidden = true;
    status('');
  });

  $('#form-claim-import').addEventListener('submit', async (e) => {
    e.preventDefault();
    const text = $('#claim-import-json').value.trim();
    if (!text) return;
    let parsed;
    try { parsed = JSON.parse(text); }
    catch { status('Not valid JSON.', 'error'); return; }

    const shape = detectShape(parsed);
    if (shape === 'unknown') { status('Unrecognized JSON shape — expected an attestation or claim-package.', 'error'); return; }
    if (shape === 'presentation') { status('That is a presentation. Use /verify to inspect presentations.', 'warn'); return; }

    const attestation = shape === 'package' ? parsed.attestation : parsed;
    const openings = shape === 'package' ? parsed.openings : null;

    const bsv = bsvLib();
    const result = await verifyAttestation(attestation, bsv);
    if (!result.verified) { status(`Signature did not verify: ${result.reason}`, 'error'); return; }

    const vault = await activeVault();
    if (!vault) return;
    if (attestation.subject?.pubKey !== vault.pubKey) {
      const accept = confirm(`This claim's subject is not the active identity (${vault.handle ? '@' + vault.handle : vault.pubKey.slice(0, 12) + '…'}). Save it anyway?`);
      if (!accept) return;
    }

    if (openings && attestation.disclosure === DISCLOSURE) {
      const check = await verifyDisclosures(attestation, openings);
      if (!check.ok) {
        const bad = Object.entries(check.results).filter(([, r]) => !r.ok).map(([k]) => k).join(', ');
        status(`Package was tampered with — openings do not match commitments (${bad}).`, 'error');
        return;
      }
    }

    attestation.direction = attestation.issuer?.pubKey === vault.pubKey
      ? (attestation.subject?.pubKey === vault.pubKey ? 'selfclaim' : 'issued')
      : 'received';
    if (openings) attestation._openings = openings;

    vault.claims = vault.claims || [];
    if (vault.claims.find((c) => c.id === attestation.id)) {
      status('This claim is already in your wallet.', 'warn');
      return;
    }
    vault.claims.unshift(attestation);
    await putVault(vault);
    invalidateVault();
    const fresh = await activeVault();
    renderClaims(fresh);
    $('#claim-import-json').value = '';
    setClaimMode('self');
    const sdSuffix = openings ? ' (selective disclosure ready)' : '';
    status(result.expired ? `Claim saved${sdSuffix} (already expired).` : `Claim verified and saved${sdSuffix}.`, result.expired ? 'warn' : 'ok');
  });

  $('#claim-import-clear').addEventListener('click', () => { $('#claim-import-json').value = ''; });

  $('#claims-list').addEventListener('click', async (e) => {
    const btn = e.target.closest('button[data-act]');
    if (!btn) return;
    const idx = Number(btn.dataset.idx);
    const vault = await activeVault();
    if (!vault?.claims?.[idx]) return;
    const c = vault.claims[idx];

    if (btn.dataset.act === 'copy') {
      const out = { ...c };
      delete out._openings;
      delete out.direction;
      await navigator.clipboard.writeText(JSON.stringify(out, null, 2));
      status('Claim JSON copied.', 'ok');
    } else if (btn.dataset.act === 'verify') {
      const r = await verifyAttestation(c, bsvLib());
      status(r.verified ? `Verified ✓${r.expired ? ' (expired)' : ''}` : `Failed: ${r.reason}`, r.verified ? 'ok' : 'error');
    } else if (btn.dataset.act === 'delete') {
      if (!confirm('Delete this claim from this device?')) return;
      vault.claims.splice(idx, 1);
      await putVault(vault);
      invalidateVault();
      const fresh = await activeVault();
      renderClaims(fresh);
      status('Claim deleted.', 'ok');
    } else if (btn.dataset.act === 'present') {
      await openPresentModal(c, vault);
    }
  });
}
