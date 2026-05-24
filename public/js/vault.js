// Multi-vault storage. One device can hold many identities.
//
// Persisted shape (v2):
//   { v: 2, activeId: <pubKey|null>, vaults: { [pubKey]: vaultObject } }
//
// v1 (single-vault) data is migrated transparently on first read.

const DB_NAME = 'web3keys';
const DB_VERSION = 1;
const STORE = 'vault';
const KEY = 'default';

function openDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function rawGet() {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, 'readonly');
    const req = tx.objectStore(STORE).get(KEY);
    req.onsuccess = () => resolve(req.result || null);
    req.onerror = () => reject(req.error);
  });
}

async function rawPut(value) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, 'readwrite');
    tx.objectStore(STORE).put(value, KEY);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

async function rawDelete() {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, 'readwrite');
    tx.objectStore(STORE).delete(KEY);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

function emptyStore() { return { v: 2, activeId: null, vaults: {} }; }

async function getStore() {
  const raw = await rawGet();
  if (!raw) return emptyStore();
  if (raw.v === 2 && raw.vaults) return raw;
  // v1: a single vault object stored directly.
  if (raw.wrappedWif && raw.pubKey) {
    const migrated = { v: 2, activeId: raw.pubKey, vaults: { [raw.pubKey]: raw } };
    await rawPut(migrated);
    return migrated;
  }
  return emptyStore();
}

async function putStore(store) {
  await rawPut(store);
}

export async function listVaults() {
  const s = await getStore();
  return Object.values(s.vaults);
}

export async function getActiveId() {
  const s = await getStore();
  return s.activeId;
}

export async function getVault() {
  const s = await getStore();
  if (!s.activeId) return null;
  return s.vaults[s.activeId] || null;
}

export async function getVaultById(id) {
  const s = await getStore();
  return s.vaults[id] || null;
}

// Upsert by pubKey, set as active. Used for both creation and update.
export async function putVault(vault) {
  if (!vault || !vault.pubKey) throw new Error('Vault must have a pubKey.');
  const s = await getStore();
  s.vaults[vault.pubKey] = vault;
  s.activeId = vault.pubKey;
  await putStore(s);
}

export async function setActiveVault(id) {
  const s = await getStore();
  if (!s.vaults[id]) throw new Error('No such vault.');
  s.activeId = id;
  await putStore(s);
}

export async function removeVault(id) {
  const s = await getStore();
  if (!s.vaults[id]) return;
  delete s.vaults[id];
  if (s.activeId === id) {
    const remaining = Object.keys(s.vaults);
    s.activeId = remaining[0] || null;
  }
  await putStore(s);
}

// Wipe everything for this device.
export async function clearVault() {
  await rawDelete();
}
