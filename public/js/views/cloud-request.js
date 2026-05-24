// view-cloud-request: enter an email to trigger a magic-link recovery.

import { $, showView, activeVault, status, welcomed } from '../lib/state.js';
import { requestRetrieve } from '../backup.js';
import { refreshAccountView } from '../lib/refresh.js';
import { enterEmpty } from './empty.js';

export function enterCloudRequest() {
  $('#cloud-request-email').value = '';
  $('#cloud-request-sent').hidden = true;
  $('#form-cloud-request').hidden = false;
  showView('#view-cloud-request');
}

export function wireCloudRequest() {
  $('#form-cloud-request').addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = $('#cloud-request-email').value.trim();
    try {
      status('Sending recovery link…');
      await requestRetrieve(email);
      $('#form-cloud-request').hidden = true;
      $('#cloud-request-sent').hidden = false;
      status('If a backup exists for that email, the link is on its way.', 'ok');
    } catch (err) {
      console.error(err);
      status(err.message || String(err), 'error');
    }
  });
  $('#cloud-request-back').addEventListener('click', async () => {
    const v = await activeVault();
    if (v) await refreshAccountView(v);
    else if (welcomed()) enterEmpty('first');
    else showView('#view-welcome');
  });
  $('#cloud-request-done').addEventListener('click', async () => {
    const v = await activeVault();
    if (v) await refreshAccountView(v);
    else showView('#view-welcome');
  });
}
