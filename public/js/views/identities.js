// Chooser dropdown wiring + identities list in Settings + switch/add/remove.

import {
  $, activeVault, invalidateVault, status, showView, clearWelcomed, emitVaultChanged, emitVaultErased,
} from '../lib/state.js';
import { listVaults, setActiveVault, removeVault } from '../vault.js';
import { attachChooser } from '../chooser.js';
import { identiconSvg } from '../identicon.js';
import { escapeText } from '../lib/fmt.js';
import { enterEmpty } from './empty.js';

export async function switchToVault(vault) {
  await setActiveVault(vault.pubKey);
  invalidateVault();
  const fresh = await activeVault();
  emitVaultChanged();
  status(`Switched to ${fresh.handle ? `@${fresh.handle}` : 'unnamed identity'}.`, 'ok');
}

export function startAddIdentity() {
  enterEmpty('add');
  status('Add an identity. Your current identity stays on this device.', 'info');
}

export function wireChooser() {
  attachChooser({
    trigger: $('#acct-switcher'),
    container: $('#chooser'),
    getVaults: listVaults,
    getActiveId: async () => (await activeVault())?.pubKey || null,
    onPick: switchToVault,
    onAddIdentity: startAddIdentity,
  });
}

export async function renderIdentitiesList() {
  const wrap = $('#identities-list');
  wrap.innerHTML = '';
  const vaults = await listVaults();
  const active = await activeVault();
  if (vaults.length === 0) {
    wrap.append(Object.assign(document.createElement('div'), {
      className: 'muted small', textContent: 'No identities on this device.',
    }));
    return;
  }
  vaults.forEach((v) => {
    const isActive = active?.pubKey === v.pubKey;
    const row = document.createElement('div');
    row.className = 'identity-row' + (isActive ? ' active' : '');
    row.innerHTML = `
      <div class="identity-row-avatar">${identiconSvg(v.pubKey, 36)}</div>
      <div class="identity-row-text">
        <div class="identity-row-name">${escapeText(v.displayName || (v.handle ? `@${v.handle}` : 'Unnamed'))}${isActive ? ' <span class="pill" data-kind="ok">active</span>' : ''}</div>
        <div class="identity-row-handle">${v.handle ? v.handle + '@web3keys.com' : 'No handle'}</div>
      </div>
      <div class="identity-row-actions">
        ${isActive ? '' : `<button class="ghost" data-act="switch" data-id="${v.pubKey}">Switch</button>`}
        <button class="ghost danger" data-act="remove" data-id="${v.pubKey}">Remove</button>
      </div>
    `;
    wrap.append(row);
  });
}

export function wireIdentitiesList() {
  $('#identities-list').addEventListener('click', async (e) => {
    const btn = e.target.closest('button[data-act]');
    if (!btn) return;
    const id = btn.dataset.id;
    if (btn.dataset.act === 'switch') {
      const v = (await listVaults()).find((x) => x.pubKey === id);
      if (v) await switchToVault(v);
    } else if (btn.dataset.act === 'remove') {
      const all = await listVaults();
      const target = all.find((x) => x.pubKey === id);
      if (!target) return;
      const label = target.handle ? `@${target.handle}` : 'this identity';
      if (!confirm(`Remove ${label} from this device? You'll need its recovery phrase to restore it elsewhere.`)) return;
      await removeVault(id);
      invalidateVault();
      const remaining = await listVaults();
      if (remaining.length === 0) {
        clearWelcomed();
        emitVaultErased();
        showView('#view-welcome');
        status('Last identity removed.', 'ok');
      } else {
        emitVaultChanged();
        status(`${label} removed.`, 'ok');
      }
    }
  });
  $('#btn-settings-add').addEventListener('click', startAddIdentity);
}
