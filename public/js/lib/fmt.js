export function fmtSats(n) {
  if (n == null) return '—';
  return `${n.toLocaleString()} sat`;
}

export function formatPresetValue(v) {
  if (v == null) return '—';
  if (typeof v === 'string') return v.length > 32 ? v.slice(0, 32) + '…' : v;
  try { return JSON.stringify(v).slice(0, 32); } catch { return String(v); }
}

export function escapeText(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}
