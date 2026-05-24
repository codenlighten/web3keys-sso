// Cloud backup section in Settings: setup / update / remove.

import { $, activeVault, invalidateVault, status, emitVaultChanged } from '../lib/state.js';
import { putVault } from '../vault.js';
import { requestConsent } from '../consent.js';
import { signMessage, unlockMnemonic } from '../sign.js';
import {
  buildBackupPlaintext, encryptBackup,
  saveBackup, deleteBackup, buildDeleteMessage,
} from '../backup.js';
import { biometricAvailable } from '../lib/identity.js';

export function renderBackupSection(vault) {
  const cb = vault.cloudBackup || { enabled: false };
  const enableBtn = $('#btn-backup-enable');
  const setupForm = $('#form-backup-setup');
  const statusBox = $('#backup-status');
  if (cb.enabled) {
    enableBtn.hidden = true;
    setupForm.hidden = true;
    statusBox.hidden = false;
    $('#backup-state').textContent = 'Enabled';
    $('#backup-state').dataset.kind = 'ok';
    $('#backup-email').textContent = cb.email || '—';
    $('#backup-updated').textContent = cb.lastBackupAt ? new Date(cb.lastBackupAt).toLocaleString() : '—';
  } else {
    enableBtn.hidden = false;
    setupForm.hidden = true;
    statusBox.hidden = true;
  }
}

async function encryptAndUploadBackup({ vault, email, passphrase }) {
  const consent = await requestConsent({
    kind: 'cloud-backup',
    title: 'Encrypt and upload your backup',
    risk: 'high',
    summary: [
      { label: 'Email (HMAC only)', value: email },
      { label: 'Includes', value: 'mnemonic, identity profile, signed claims' },
      { label: 'Encryption', value: 'AES-256-GCM, PBKDF2-SHA256 600k iters' },
    ],
    warning: 'A new attack surface: anyone who has both your email AND your backup passphrase can recover your identity. Use a strong, unique passphrase.',
    biometricAvailable: biometricAvailable(vault),
  });
  if (!consent.approved) throw new Error('Cancelled.');

  const mnemonic = await unlockMnemonic(vault, consent);
  const plaintext = buildBackupPlaintext({ mnemonic, vault });
  const payload = await encryptBackup(plaintext, passphrase);
  const result = await saveBackup({
    email, payload, pubKey: vault.pubKey,
    displayName: vault.displayName || null,
    handle: vault.handle || null,
  });
  vault.cloudBackup = { enabled: true, email, lastBackupAt: result.updatedAt || new Date().toISOString() };
  await putVault(vault);
  return vault;
}

export function wireBackup() {
  $('#btn-backup-enable').addEventListener('click', () => {
    $('#btn-backup-enable').hidden = true;
    $('#form-backup-setup').hidden = false;
    $('#backup-email-input').value = '';
    $('#backup-pass-input').value = '';
    $('#backup-pass-confirm').value = '';
    $('#backup-email-input').focus();
  });
  $('#btn-backup-cancel').addEventListener('click', () => {
    $('#form-backup-setup').hidden = true;
    $('#btn-backup-enable').hidden = false;
  });
  $('#form-backup-setup').addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = $('#backup-email-input').value.trim();
    const passphrase = $('#backup-pass-input').value;
    const confirmPass = $('#backup-pass-confirm').value;
    if (passphrase !== confirmPass) { status('Passphrases do not match.', 'error'); return; }
    const vault = await activeVault();
    if (!vault) return;
    try {
      status('Encrypting and uploading…');
      await encryptAndUploadBackup({ vault, email, passphrase });
      invalidateVault();
      emitVaultChanged();
      status('Cloud backup enabled.', 'ok');
    } catch (err) {
      console.error(err); status(err.message || String(err), 'error');
    }
  });

  $('#btn-backup-update').addEventListener('click', async () => {
    const vault = await activeVault();
    if (!vault?.cloudBackup?.email) return;
    const passphrase = prompt('Re-enter your backup passphrase to refresh the cloud backup. Must match what you used at setup; if it differs, the next recovery will require this new passphrase.');
    if (!passphrase) return;
    try {
      status('Refreshing cloud backup…');
      await encryptAndUploadBackup({ vault, email: vault.cloudBackup.email, passphrase });
      invalidateVault();
      emitVaultChanged();
      status('Cloud backup updated.', 'ok');
    } catch (err) {
      console.error(err); status(err.message || String(err), 'error');
    }
  });

  $('#btn-backup-remove').addEventListener('click', async () => {
    const vault = await activeVault();
    if (!vault?.cloudBackup?.email) return;
    if (!confirm('Remove your cloud backup? You will lose the ability to recover this identity by email — only your 24-word phrase will work after this.')) return;
    const consent = await requestConsent({
      kind: 'backup-delete',
      title: 'Remove cloud backup',
      risk: 'high',
      summary: [
        { label: 'Email', value: vault.cloudBackup.email },
        { label: 'Identity', value: vault.handle ? `@${vault.handle}` : vault.pubKey, mono: !vault.handle },
      ],
      warning: 'After this, your 24-word phrase is the only way to recover this identity.',
      approveLabel: 'Sign deletion request',
      biometricAvailable: biometricAvailable(vault),
    });
    if (!consent.approved) { status('Cancelled.'); return; }
    try {
      const ts = Date.now();
      const message = buildDeleteMessage({ email: vault.cloudBackup.email, pubKey: vault.pubKey, ts });
      const { signature } = await signMessage(vault, consent, message);
      status('Submitting deletion…');
      await deleteBackup({ email: vault.cloudBackup.email, pubKey: vault.pubKey, message, signature });
      vault.cloudBackup = { enabled: false, email: null, lastBackupAt: null };
      await putVault(vault);
      invalidateVault();
      emitVaultChanged();
      status('Cloud backup removed.', 'ok');
    } catch (err) {
      console.error(err); status(err.message || String(err), 'error');
    }
  });
}
