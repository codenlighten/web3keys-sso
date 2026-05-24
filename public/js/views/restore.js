// Restore flow: import a mnemonic, optionally claim a handle here too.

import { $, status, invalidateVault, emitVaultChanged } from '../lib/state.js';
import { randomBytes } from '../crypto.js';
import { registerPasskey } from '../biometric.js';
import { putVault } from '../vault.js';
import {
  IDENTITY_PATH, MnemonicClass, deriveIdentity, buildWrappings, attemptPaymailClaim,
} from '../lib/identity.js';

export function wireRestore() {
  $('#form-restore').addEventListener('submit', async (e) => {
    e.preventDefault();
    const mnemonic = $('#restore-mnemonic').value.trim().split(/\s+/).join(' ');
    const passphrase = $('#restore-passphrase').value;
    const handle = $('#restore-handle').value.trim().toLowerCase();
    const displayName = $('#restore-display').value.trim();
    try {
      const M = MnemonicClass();
      try { new M(mnemonic); } catch { throw new Error('Invalid recovery phrase.'); }

      status('Deriving identity from phrase…');
      const identity = deriveIdentity(mnemonic);

      status('Registering biometric passkey on this device…');
      const passkey = await registerPasskey({
        userId: randomBytes(16),
        userName: handle ? `${handle}@web3keys.com` : identity.address,
        displayName: displayName || 'Web3Keys identity',
      });

      status('Encrypting identity for this device…');
      const { wrappedWif, wrappedMnemonic, bioEnabled } = await buildWrappings({
        mnemonic, wif: identity.wif, passphrase, passkey,
      });

      const vault = {
        v: 1, createdAt: new Date().toISOString(), idPath: IDENTITY_PATH,
        pubKey: identity.pubKey, address: identity.address,
        handle: null, displayName: displayName || '',
        wrappedWif, wrappedMnemonic,
        claims: [],
      };

      if (handle) {
        try {
          const claimed = await attemptPaymailClaim({ vault, mnemonic, handle, displayName: displayName || handle });
          vault.handle = claimed.handle;
          vault.profileClaimedAt = claimed.claimedAt;
        } catch (err) {
          status(err.message + ' (Identity saved without a handle — you can claim one in Settings.)', 'warn');
        }
      }

      await putVault(vault);
      invalidateVault();
      emitVaultChanged();
      status(vault.handle
        ? `Restored as @${vault.handle}.`
        : 'Restored. Biometric ' + (bioEnabled ? 'enabled.' : 'not available — password fallback only.'), 'ok');
    } catch (err) {
      console.error(err); status(err.message || String(err), 'error');
    }
  });
}
