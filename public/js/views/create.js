// Create flow: generate mnemonic → register passkey → wrap → mnemonic confirm
// → claim paymail handle → save vault → return to account view.

import { $, status, showView, invalidateVault, emitVaultChanged } from '../lib/state.js';
import { randomBytes } from '../crypto.js';
import { registerPasskey } from '../biometric.js';
import { putVault } from '../vault.js';
import { isValidHandle, checkHandleAvailable } from '../profile.js';
import {
  IDENTITY_PATH, MnemonicClass, deriveIdentity, buildWrappings,
  attemptPaymailClaim, renderMnemonicGrid,
} from '../lib/identity.js';

let pendingCreation = null;

export function clearPendingCreation() { pendingCreation = null; }

export function wireCreate() {
  $('#form-create').addEventListener('submit', async (e) => {
    e.preventDefault();
    const handle = $('#create-handle').value.trim().toLowerCase();
    const displayName = $('#create-display').value.trim();
    const passphrase = $('#create-passphrase').value;
    if (!isValidHandle(handle)) { status('Handle is invalid.', 'error'); return; }
    if (!displayName) { status('Display name is required.', 'error'); return; }

    try {
      status('Checking handle availability…');
      const avail = await checkHandleAvailable(handle);
      if (!avail.ok || !avail.available) { status('That handle is no longer available — pick another.', 'error'); return; }

      status('Generating identity…');
      const M = MnemonicClass();
      const mnemonic = M.fromRandom(256).phrase;
      const identity = deriveIdentity(mnemonic);

      status('Registering biometric passkey…');
      const passkey = await registerPasskey({
        userId: randomBytes(16),
        userName: `${handle}@web3keys.com`,
        displayName,
      });

      status('Encrypting identity for this device…');
      const { wrappedWif, wrappedMnemonic, bioEnabled } = await buildWrappings({
        mnemonic, wif: identity.wif, passphrase, passkey,
      });

      const vault = {
        v: 1, createdAt: new Date().toISOString(), idPath: IDENTITY_PATH,
        pubKey: identity.pubKey, address: identity.address,
        handle: null, displayName,
        wrappedWif, wrappedMnemonic,
        claims: [],
      };

      pendingCreation = { vault, mnemonic, handle, displayName };
      renderMnemonicGrid($('#mnemonic-grid'), mnemonic);
      $('#mnemonic-confirm').checked = false;
      $('#mnemonic-continue').disabled = true;
      showView('#view-mnemonic');
      status(bioEnabled ? 'Biometric enabled.' : 'Biometric PRF not supported — password fallback only.', bioEnabled ? 'ok' : 'warn');
    } catch (err) {
      console.error(err); status(err.message || String(err), 'error');
    }
  });

  $('#mnemonic-confirm').addEventListener('change', (e) => {
    $('#mnemonic-continue').disabled = !e.target.checked;
  });
  $('#btn-mnemonic-copy').addEventListener('click', async () => {
    if (!pendingCreation) return;
    await navigator.clipboard.writeText(pendingCreation.mnemonic);
    status('Recovery phrase copied. Paste it somewhere offline, then erase from clipboard.', 'warn');
  });

  $('#mnemonic-continue').addEventListener('click', async () => {
    if (!pendingCreation) return;
    const { vault, mnemonic, handle, displayName } = pendingCreation;
    try {
      status('Claiming your handle…');
      const claimed = await attemptPaymailClaim({ vault, mnemonic, handle, displayName });
      if (claimed) {
        vault.handle = claimed.handle;
        vault.profileClaimedAt = claimed.claimedAt;
      }
      await putVault(vault);
      invalidateVault();
      pendingCreation = null;
      emitVaultChanged();
      status(claimed
        ? `Welcome, @${claimed.handle}.`
        : 'Identity saved locally. Claim a handle below to get a public profile.', 'ok');
    } catch (err) {
      console.error(err);
      // Save the vault anyway so the user keeps their identity even on claim failure.
      await putVault(vault);
      invalidateVault();
      pendingCreation = null;
      emitVaultChanged();
      status(err.message || String(err), 'error');
    }
  });
}
