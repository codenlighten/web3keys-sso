import { identiconSvg } from './identicon.js';

// A tiny dropdown component anchored under the account header. Rendered
// when the user clicks the switcher, populated with all stored identities,
// plus an "Add another identity" action.

let opened = false;
let cleanup = null;

function el(tag, attrs = {}, ...kids) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') node.className = v;
    else if (k === 'html') node.innerHTML = v;
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

function renderRow({ vault, isActive, onPick, onRemove }) {
  const handle = vault.handle ? `${vault.handle}@web3keys.com` : 'No handle';
  const display = vault.displayName || (vault.handle ? `@${vault.handle}` : 'Unnamed identity');

  const row = el('div', { class: 'chooser-row' + (isActive ? ' active' : '') });
  const main = el('button', {
    type: 'button',
    class: 'chooser-row-main',
    on: { click: () => onPick(vault) },
  },
    el('div', { class: 'chooser-row-avatar', html: identiconSvg(vault.pubKey, 36) }),
    el('div', { class: 'chooser-row-text' },
      el('div', { class: 'chooser-row-name' }, display),
      el('div', { class: 'chooser-row-handle' }, handle),
    ),
    isActive ? el('div', { class: 'chooser-row-check', 'aria-hidden': 'true' }, '✓') : null,
  );
  row.append(main);
  return row;
}

export function attachChooser({
  trigger, container, getVaults, getActiveId, onPick, onAddIdentity,
}) {
  function close() {
    if (!opened) return;
    opened = false;
    container.hidden = true;
    trigger.setAttribute('aria-expanded', 'false');
    if (cleanup) { cleanup(); cleanup = null; }
  }

  async function open() {
    if (opened) { close(); return; }
    const vaults = await getVaults();
    const activeId = await getActiveId();
    container.innerHTML = '';
    const list = el('div', { class: 'chooser-list' });
    vaults.forEach((v) => {
      list.append(renderRow({
        vault: v,
        isActive: v.pubKey === activeId,
        onPick: async (picked) => {
          close();
          if (picked.pubKey !== activeId) await onPick(picked);
        },
      }));
    });
    container.append(list);
    container.append(el('button', {
      class: 'chooser-action',
      type: 'button',
      on: { click: async () => { close(); await onAddIdentity(); } },
    }, '+ Add another identity'));

    opened = true;
    container.hidden = false;
    trigger.setAttribute('aria-expanded', 'true');

    const onDocClick = (e) => {
      if (container.contains(e.target) || trigger.contains(e.target)) return;
      close();
    };
    const onKey = (e) => { if (e.key === 'Escape') close(); };
    document.addEventListener('mousedown', onDocClick);
    document.addEventListener('keydown', onKey);
    cleanup = () => {
      document.removeEventListener('mousedown', onDocClick);
      document.removeEventListener('keydown', onKey);
    };
  }

  trigger.addEventListener('click', open);
  return { open, close };
}
