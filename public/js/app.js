// Wallet bootstrap. Wires every view's event handlers, sets up tab switching,
// listens for vault-changed events, and decides the initial view.

import {
  $, activeVault, showView, welcomed, status,
  onVaultChanged, onVaultErased,
} from './lib/state.js';
import { isPlatformAuthAvailable, isUserVerifyingPlatformAuthenticatorAvailable } from './biometric.js';
import { listVaults } from './vault.js';
import { pendingImportFromUrl, consumeImportParam, stashImport } from './lib/url-import.js';
import { refreshAccountView } from './lib/refresh.js';

import { wireWelcome, showWelcomeOrEmpty } from './views/empty.js';
import { wireCreate } from './views/create.js';
import { wireRestore } from './views/restore.js';
import { attachAvailabilityCheck, wireClaimHandleLate } from './views/handle.js';
import { wireClaims, setClaimMode } from './views/claims.js';
import { wireMessage, wireTransaction, wireHash, wireEncrypt } from './views/signing.js';
import { wireChooser, wireIdentitiesList } from './views/identities.js';
import { wireBackup } from './views/backup.js';
import { wireSettings } from './views/settings.js';
import { wireCloudRequest } from './views/cloud-request.js';

function wireTabs() {
  const tabs = document.querySelectorAll('.tab');
  tabs.forEach((tab) => {
    tab.addEventListener('click', () => {
      tabs.forEach((t) => t.setAttribute('aria-selected', t === tab ? 'true' : 'false'));
      const name = tab.dataset.tab;
      document.querySelectorAll('.tab-panel').forEach((p) => p.hidden = p.dataset.panel !== name);
    });
  });
  const subtabs = document.querySelectorAll('.subtab');
  subtabs.forEach((tab) => {
    tab.addEventListener('click', () => {
      subtabs.forEach((t) => t.setAttribute('aria-selected', t === tab ? 'true' : 'false'));
      const mode = tab.dataset.mode;
      document.querySelectorAll('.subtab-panel').forEach((p) => p.hidden = p.dataset.mode !== mode);
    });
  });
}

async function routeAfterBoot() {
  const vaults = await listVaults();
  const imported = pendingImportFromUrl();

  if (vaults.length > 0) {
    const v = await activeVault();
    await refreshAccountView(v);
    if (imported) {
      // Switch to Claims tab → import section, pre-fill textarea.
      $('.tab[data-tab="claims"]')?.click();
      setClaimMode('import');
      $('#claim-import-json').value = imported;
      $('#claim-import-json').scrollIntoView({ behavior: 'smooth', block: 'center' });
      status('Review the incoming claim and click "Verify & save".', 'info');
      consumeImportParam();
    }
    return;
  }
  showWelcomeOrEmpty();
  if (imported) {
    status('Sign in to import this claim.', 'info');
    stashImport(imported);
    consumeImportParam();
  }
}

async function boot() {
  if (!isPlatformAuthAvailable()) {
    status('WebAuthn is not available in this browser. You can still use a password fallback.', 'warn');
  } else {
    const uvpa = await isUserVerifyingPlatformAuthenticatorAvailable();
    if (!uvpa) status('No platform biometric detected. You can still use a password fallback.', 'warn');
  }

  attachAvailabilityCheck($('#create-handle'), $('#handle-feedback'));
  attachAvailabilityCheck($('#latehandle-input'), $('#latehandle-feedback'));

  wireWelcome();
  wireCreate();
  wireRestore();
  wireTabs();
  wireClaimHandleLate();
  wireMessage();
  wireClaims();
  wireTransaction();
  wireHash();
  wireEncrypt();
  wireSettings();
  wireChooser();
  wireIdentitiesList();
  wireCloudRequest();
  wireBackup();

  // Whenever a view mutates the vault, refresh the whole account view.
  onVaultChanged(async () => {
    const v = await activeVault();
    if (v) await refreshAccountView(v);
  });
  // After erase, the active vault is gone; welcome screen is the destination.
  onVaultErased(() => {
    showView('#view-welcome');
  });

  await routeAfterBoot();
}

boot().catch((e) => { console.error(e); status(e.message || String(e), 'error'); });
