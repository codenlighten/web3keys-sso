// Reusable consent modal. Every signing/encrypting action is gated by this UI.
// Phase 3 will hand it requests originating from dApps; until then the
// requester is "This device" and the flow is fully in-app.

const RISK = {
  low:    { label: 'Low risk',    kind: 'ok' },
  normal: { label: 'Review',      kind: 'info' },
  high:   { label: 'High risk',   kind: 'warn' },
  danger: { label: 'Dangerous',   kind: 'error' },
};

function el(tag, attrs = {}, ...kids) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') node.className = v;
    else if (k === 'dataset') Object.assign(node.dataset, v);
    else if (k === 'on') for (const [ev, fn] of Object.entries(v)) node.addEventListener(ev, fn);
    else if (v === true) node.setAttribute(k, '');
    else if (v !== false && v != null) node.setAttribute(k, v);
  }
  for (const kid of kids) {
    if (kid == null || kid === false) continue;
    node.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return node;
}

function ensureRoot() {
  let root = document.getElementById('consent-root');
  if (!root) {
    root = el('div', { id: 'consent-root' });
    document.body.append(root);
  }
  return root;
}

/**
 * Open the consent modal.
 *
 * request = {
 *   kind,          // 'message' | 'transaction' | 'hash' | 'encrypt' | 'decrypt'
 *   title,         // short title
 *   requester,     // 'This device' | dApp origin
 *   risk,          // 'low' | 'normal' | 'high' | 'danger'
 *   summary,       // [{ label, value, mono?: bool, highlight?: bool }]
 *   detail,        // optional long-form raw data (rendered in <details>)
 *   warning,       // optional string shown prominently
 *   approveLabel,  // default "Approve & sign"
 *   biometricAvailable, // bool — if false, only password is shown
 * }
 *
 * Returns: { approved: boolean, method?: 'biometric' | 'password', password?: string }
 */
export function requestConsent(request) {
  const root = ensureRoot();
  root.innerHTML = '';

  let resolveOuter;
  const promise = new Promise((r) => (resolveOuter = r));

  const risk = RISK[request.risk] || RISK.normal;
  const useBiometric = !!request.biometricAvailable;

  const methodSelector = el('div', { class: 'consent-method' },
    el('label', { class: 'inline' },
      el('input', {
        type: 'radio', name: 'consent-method', value: 'biometric',
        checked: useBiometric, disabled: !useBiometric,
      }),
      el('span', {}, 'Biometric (Touch ID / Face ID)'),
    ),
    el('label', { class: 'inline' },
      el('input', { type: 'radio', name: 'consent-method', value: 'password', checked: !useBiometric }),
      el('span', {}, 'Password fallback'),
    ),
  );

  const passwordInput = el('input', {
    type: 'password',
    placeholder: 'Recovery passphrase',
    class: 'consent-password',
    autocomplete: 'current-password',
  });
  passwordInput.hidden = useBiometric;

  methodSelector.addEventListener('change', (e) => {
    if (e.target.name === 'consent-method') {
      passwordInput.hidden = e.target.value === 'biometric';
      if (!passwordInput.hidden) passwordInput.focus();
    }
  });

  const summaryRows = (request.summary || []).map((row) =>
    el('div', { class: 'consent-row' + (row.highlight ? ' highlight' : '') },
      el('span', { class: 'label' }, row.label),
      el(row.mono ? 'code' : 'span', { class: 'value' }, row.value),
    )
  );

  const detailNode = request.detail
    ? el('details', { class: 'consent-detail' },
        el('summary', {}, 'Show raw data'),
        el('pre', {}, request.detail),
      )
    : null;

  const warningNode = request.warning
    ? el('div', { class: 'consent-warning' }, request.warning)
    : null;

  const card = el('div', { class: 'consent-card', role: 'dialog', 'aria-modal': 'true' },
    el('header', { class: 'consent-header' },
      el('div', { class: 'consent-kind' }, request.kind || 'sign'),
      el('span', { class: 'pill', dataset: { kind: risk.kind } }, risk.label),
    ),
    el('h2', { class: 'consent-title' }, request.title),
    el('div', { class: 'consent-requester' },
      el('span', { class: 'label' }, 'Requester'),
      el('span', {}, request.requester || 'This device'),
    ),
    el('div', { class: 'consent-summary' }, ...summaryRows),
    warningNode,
    detailNode,
    methodSelector,
    passwordInput,
    el('div', { class: 'consent-actions' },
      el('button', { class: 'ghost', type: 'button', on: { click: () => close({ approved: false }) } }, 'Cancel'),
      el('button', {
        class: 'primary', type: 'button',
        on: { click: () => {
          const method = methodSelector.querySelector('input[name="consent-method"]:checked').value;
          if (method === 'password' && !passwordInput.value) {
            passwordInput.focus();
            return;
          }
          close({ approved: true, method, password: method === 'password' ? passwordInput.value : undefined });
        }},
      }, request.approveLabel || 'Approve & sign'),
    ),
  );

  const backdrop = el('div', { class: 'consent-backdrop' }, card);

  function close(result) {
    document.removeEventListener('keydown', onKey);
    backdrop.remove();
    resolveOuter(result);
  }
  function onKey(e) {
    if (e.key === 'Escape') close({ approved: false });
  }
  document.addEventListener('keydown', onKey);

  root.append(backdrop);
  setTimeout(() => {
    (useBiometric ? methodSelector.querySelector('input[value="biometric"]') : passwordInput).focus();
  }, 50);

  return promise;
}
