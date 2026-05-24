// Shared status toast. Auto-dismisses; tap-to-dismiss for impatient users.
//
// Display durations:
//   error → 6000ms
//   warn  → 4500ms
//   ok/info/default → 3500ms
// A new status() call always replaces the previous message and resets the timer.

const DURATION = { error: 6000, warn: 4500, ok: 3500, info: 3500, '': 3500 };

let timer = null;
let bound = false;
let currentToken = 0;

function findToast() {
  return document.getElementById('status');
}

function bindOnce() {
  if (bound) return;
  bound = true;
  document.addEventListener('click', (e) => {
    const el = findToast();
    if (el && e.target === el) clear();
  }, { passive: true });
}

function clear() {
  const el = findToast();
  if (!el) return;
  el.textContent = '';
  el.dataset.kind = '';
  clearTimeout(timer);
  timer = null;
}

export function status(msg, kind = '') {
  bindOnce();
  const el = findToast();
  if (!el) return;
  clearTimeout(timer);
  const token = ++currentToken;
  const text = msg || '';
  el.textContent = text;
  el.dataset.kind = kind || '';
  el.style.cursor = text ? 'pointer' : 'default';
  if (!text) return;
  const ms = DURATION[kind] ?? DURATION[''];
  timer = setTimeout(() => {
    // Only clear if this status hasn't been replaced in the meantime.
    if (token === currentToken) clear();
  }, ms);
}

export function clearStatus() { clear(); }
