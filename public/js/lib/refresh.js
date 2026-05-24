// Full account-view re-render orchestrator. Called whenever the active vault
// changes meaningfully (create / restore / switch / claim-handle / claim
// added/removed / backup change).
//
// Lives in lib/ so views can import it without forming a cycle with each
// other. Imports the section renderers from each view module.

import { $, showView, activeVault } from './state.js';
import { setIdenticon } from '../identicon.js';
import { renderClaims, setClaimMode } from '../views/claims.js';
import { renderIdentitiesList } from '../views/identities.js';
import { renderBackupSection } from '../views/backup.js';
import { popImport } from './url-import.js';

export async function refreshAccountView(vault) {
  if (!vault) {
    vault = await activeVault();
    if (!vault) return;
  }
  setIdenticon($('#acct-avatar'), vault.pubKey, 64);
  $('#acct-display').textContent = vault.displayName || (vault.handle ? `@${vault.handle}` : 'Unnamed identity');
  $('#acct-handle-prefix').textContent = vault.handle ? vault.handle : '—';
  $('#acct-pubkey').textContent = vault.pubKey;
  $('#acct-address').textContent = vault.address;

  const link = $('#acct-profile-link');
  if (vault.handle) {
    link.href = `/u/${encodeURIComponent(vault.handle)}`;
    link.hidden = false;
  } else {
    link.hidden = true;
  }

  const settingsLink = $('#settings-profile-link');
  if (vault.handle) {
    settingsLink.href = `/u/${encodeURIComponent(vault.handle)}`;
    settingsLink.textContent = `${vault.handle}@web3keys.com`;
  } else {
    settingsLink.removeAttribute('href');
    settingsLink.textContent = 'No handle yet';
  }

  const pill = $('#acct-biometric');
  if (vault.wrappedWif?.biometric) {
    pill.textContent = 'Biometric'; pill.dataset.kind = 'ok';
  } else {
    pill.textContent = 'Password only'; pill.dataset.kind = 'warn';
  }

  $('#acct-claim-handle').hidden = !!vault.handle;
  renderClaims(vault);
  await renderIdentitiesList();
  renderBackupSection(vault);
  showView('#view-account');

  // Honor a deep-link ?import= stashed earlier in sessionStorage.
  const stashed = popImport();
  if (stashed) {
    const tab = document.querySelector('.tab[data-tab="claims"]');
    if (tab) tab.click();
    setClaimMode('import');
    const ta = $('#claim-import-json');
    if (ta) ta.value = stashed;
  }
}
