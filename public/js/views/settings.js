// Settings tab: show recovery phrase, hide, erase device.

import { $, activeVault, invalidateVault, status, showView, clearWelcomed, emitVaultErased } from '../lib/state.js';
import { clearVault } from '../vault.js';
import { requestConsent } from '../consent.js';
import { unlockMnemonic } from '../sign.js';
import { biometricAvailable, renderMnemonicGrid } from '../lib/identity.js';
import { clearPendingCreation } from './create.js';

export function wireSettings() {
  $('#btn-show-mnemonic').addEventListener('click', async () => {
    const vault = await activeVault(); if (!vault) return;
    const consent = await requestConsent({
      kind: 'recovery',
      title: 'Reveal recovery phrase',
      risk: 'high',
      summary: [
        { label: 'Identity', value: vault.handle ? `@${vault.handle}` : vault.pubKey, mono: !vault.handle },
      ],
      warning: 'Anyone who reads your recovery phrase can recreate this identity on any device. Make sure no one is looking.',
      approveLabel: 'Reveal phrase',
      biometricAvailable: biometricAvailable(vault),
    });
    if (!consent.approved) { status('Cancelled.'); return; }
    try {
      const mnemonic = await unlockMnemonic(vault, consent);
      renderMnemonicGrid($('#mnemonic-revealed-grid'), mnemonic);
      $('#mnemonic-revealed').hidden = false;
      status('Phrase shown. Hide it when you\'re done.', 'warn');
    } catch (err) {
      console.error(err); status(err.message || String(err), 'error');
    }
  });
  $('#btn-hide-mnemonic').addEventListener('click', () => {
    $('#mnemonic-revealed-grid').innerHTML = '';
    $('#mnemonic-revealed').hidden = true;
    status('Phrase hidden.');
  });
  $('#btn-reset').addEventListener('click', async () => {
    if (!confirm('Erase ALL Web3Keys identities from this device? You will need each recovery phrase to restore them.')) return;
    await clearVault();
    invalidateVault();
    clearPendingCreation();
    clearWelcomed();
    emitVaultErased();
    showView('#view-welcome');
    status('Device erased.', 'ok');
  });
}
