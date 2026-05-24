// view-welcome + view-empty (the create / restore form).
//
// Owns: the "Welcome" hero, "Empty" form mode, and the back/cancel button
// that returns to the active identity or back to welcome.

import { $, showView, activeVault, welcomed, setWelcomed } from '../lib/state.js';
import { enterCloudRequest } from './cloud-request.js';
import { refreshAccountView } from '../lib/refresh.js';

let createMode = 'first'; // 'first' | 'add'

export function getCreateMode() { return createMode; }

export function setEmptyTitle(mode) {
  $('#empty-title').textContent = mode === 'add' ? 'Add another identity' : 'Claim your identity';
  $('#btn-empty-back').hidden = mode !== 'add';
  $('#btn-create').textContent = mode === 'add' ? 'Add identity' : 'Create identity';
}

export function enterEmpty(mode) {
  createMode = mode;
  setEmptyTitle(mode);
  $('#form-create').reset();
  $('#form-restore').reset();
  $('#restore-details').open = false;
  showView('#view-empty');
}

export function showWelcomeOrEmpty() {
  if (welcomed()) enterEmpty('first');
  else showView('#view-welcome');
}

export function wireWelcome() {
  $('#btn-welcome-create').addEventListener('click', () => {
    setWelcomed();
    enterEmpty('first');
  });
  $('#btn-welcome-restore').addEventListener('click', () => {
    setWelcomed();
    enterEmpty('first');
    setTimeout(() => { $('#restore-details').open = true; $('#restore-mnemonic').focus(); }, 50);
  });
  $('#btn-empty-back').addEventListener('click', async () => {
    const v = await activeVault();
    if (v) { await refreshAccountView(v); return; }
    showView('#view-welcome');
  });
  $('#link-welcome-cloud').addEventListener('click', (e) => {
    e.preventDefault();
    setWelcomed();
    enterCloudRequest();
  });
  $('#btn-empty-cloud').addEventListener('click', enterCloudRequest);
}
