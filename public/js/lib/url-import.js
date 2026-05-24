// Handle ?import=<b64url-of-claim-json> deep links from /verify.

const STASH_KEY = 'web3keys:pendingImport';

export function pendingImportFromUrl() {
  const p = new URLSearchParams(location.search);
  const raw = p.get('import');
  if (!raw) return null;
  try {
    const pad = '='.repeat((4 - raw.length % 4) % 4);
    return atob(raw.replace(/-/g, '+').replace(/_/g, '/') + pad);
  } catch { return null; }
}

export function consumeImportParam() {
  if (location.search.includes('import=')) {
    const url = new URL(location.href);
    url.searchParams.delete('import');
    history.replaceState({}, '', url.toString());
  }
}

export function stashImport(text) { sessionStorage.setItem(STASH_KEY, text); }
export function popImport() {
  const v = sessionStorage.getItem(STASH_KEY);
  if (v) sessionStorage.removeItem(STASH_KEY);
  return v;
}
