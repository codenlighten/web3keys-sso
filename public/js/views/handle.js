// Handle availability check (used by create, restore, late-claim forms) and
// the "claim a handle later" form for identities that don't have one yet.

import { $, activeVault, invalidateVault, status, emitVaultChanged } from '../lib/state.js';
import { putVault } from '../vault.js';
import { isValidHandle, checkHandleAvailable, buildClaimMessage, claimHandle } from '../profile.js';
import { requestConsent } from '../consent.js';
import { signMessage } from '../sign.js';
import { biometricAvailable } from '../lib/identity.js';

export function attachAvailabilityCheck(input, feedbackEl) {
  let timer = null;
  const upd = (txt, kind) => { feedbackEl.textContent = txt; feedbackEl.dataset.kind = kind || ''; };
  input.addEventListener('input', () => {
    clearTimeout(timer);
    const v = input.value.trim().toLowerCase();
    if (!v) { upd('3–32 lowercase letters, digits, dashes, underscores.', ''); return; }
    if (!isValidHandle(v)) { upd('Use only a–z, 0–9, dash, underscore (3–32 chars, no leading/trailing dash).', 'error'); return; }
    upd('Checking…', '');
    timer = setTimeout(async () => {
      try {
        const r = await checkHandleAvailable(v);
        if (r.ok && r.available) upd(`✓ ${v}@web3keys.com is available.`, 'ok');
        else if (r.ok && r.reason === 'reserved') upd('That handle is reserved.', 'error');
        else if (r.ok && r.reason === 'taken') upd('That handle is taken.', 'error');
        else if (r.ok && !r.available) upd('That handle is unavailable.', 'error');
        else upd('Could not check availability.', 'warn');
      } catch { upd('Could not check availability.', 'warn'); }
    }, 320);
  });
}

export function wireClaimHandleLate() {
  $('#form-claim-handle').addEventListener('submit', async (e) => {
    e.preventDefault();
    const handle = $('#latehandle-input').value.trim().toLowerCase();
    const displayName = $('#latehandle-display').value.trim();
    if (!isValidHandle(handle)) { status('Invalid handle.', 'error'); return; }

    const vault = await activeVault();
    if (!vault) return;

    const consent = await requestConsent({
      kind: 'claim',
      title: `Claim @${handle}`,
      risk: 'low',
      summary: [
        { label: 'Handle', value: `${handle}@web3keys.com`, mono: true },
        { label: 'Display name', value: displayName || '(none)' },
        { label: 'Public key', value: vault.pubKey, mono: true },
      ],
      biometricAvailable: biometricAvailable(vault),
    });
    if (!consent.approved) { status('Cancelled.'); return; }

    try {
      status('Signing claim…');
      const ts = Date.now();
      const message = buildClaimMessage({ handle, pubKey: vault.pubKey, address: vault.address, ts });
      const { signature } = await signMessage(vault, consent, message);
      status('Submitting…');
      const claimed = await claimHandle({
        handle, pubKey: vault.pubKey, address: vault.address,
        displayName, signature, message,
      });
      vault.handle = claimed.handle;
      vault.displayName = displayName || vault.displayName;
      vault.profileClaimedAt = claimed.claimedAt;
      await putVault(vault);
      invalidateVault();
      emitVaultChanged();
      status(`Welcome, @${claimed.handle}.`, 'ok');
    } catch (err) {
      console.error(err);
      status(err.message || String(err), 'error');
    }
  });
}
