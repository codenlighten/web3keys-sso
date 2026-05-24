// Shared client state, DOM helpers, and a tiny event bus for vault-changed
// notifications. Imports nothing from view modules.

import { getVault } from '../vault.js';
export { status } from '../status.js';

let cachedVault = null;

export const $ = (sel) => document.querySelector(sel);

export async function activeVault() {
  if (!cachedVault) cachedVault = await getVault();
  return cachedVault;
}
export function invalidateVault() { cachedVault = null; }

export function showView(id) {
  for (const s of document.querySelectorAll('main > section')) s.hidden = true;
  const node = $(id);
  if (node) node.hidden = false;
}

export const WELCOMED_KEY = 'web3keys:welcomed';
export const welcomed = () => localStorage.getItem(WELCOMED_KEY) === '1';
export const setWelcomed = () => localStorage.setItem(WELCOMED_KEY, '1');
export const clearWelcomed = () => localStorage.removeItem(WELCOMED_KEY);

// Event bus — used by views to ask app.js for a full account-view refresh
// without taking a hard dependency on the orchestrator.
const VAULT_CHANGED = 'w3k:vault-changed';
const VAULT_ERASED = 'w3k:vault-erased';
export function emitVaultChanged() {
  document.dispatchEvent(new CustomEvent(VAULT_CHANGED));
}
export function onVaultChanged(fn) {
  document.addEventListener(VAULT_CHANGED, fn);
}
export function emitVaultErased() {
  document.dispatchEvent(new CustomEvent(VAULT_ERASED));
}
export function onVaultErased(fn) {
  document.addEventListener(VAULT_ERASED, fn);
}
