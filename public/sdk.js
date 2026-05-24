/*!
 * Web3Keys SDK — Sign in with Web3Keys
 * Drop in: <script src="https://web3keys.com/sdk.js"></script>
 * Then either call Web3Keys.signIn() or use a <button data-web3keys-signin>.
 * Source: https://github.com/codenlighten/web3keys-sso
 */
(function () {
  'use strict';
  if (typeof window === 'undefined' || window.Web3Keys) return;

  var ORIGIN = 'https://web3keys.com';
  var POPUP_PATH = '/sso';
  var POPUP_FEATURES = 'width=480,height=720,menubar=no,toolbar=no,location=no,status=no';

  function rand(n) {
    var a = new Uint8Array(n);
    crypto.getRandomValues(a);
    return a;
  }
  function bytesToHex(a) {
    var out = '';
    for (var i = 0; i < a.length; i++) {
      var s = a[i].toString(16);
      out += s.length === 1 ? '0' + s : s;
    }
    return out;
  }

  function randomNonce() { return bytesToHex(rand(16)); }

  function b64urlToBytes(s) {
    var pad = '='.repeat((4 - (s.length % 4)) % 4);
    var b = atob(s.replace(/-/g, '+').replace(/_/g, '/') + pad);
    var out = new Uint8Array(b.length);
    for (var i = 0; i < b.length; i++) out[i] = b.charCodeAt(i);
    return out;
  }

  function parseIdToken(idToken) {
    var parts = String(idToken || '').split('.');
    if (parts.length !== 3) throw new Error('Malformed idToken');
    var dec = new TextDecoder();
    var header = JSON.parse(dec.decode(b64urlToBytes(parts[0])));
    var payload = JSON.parse(dec.decode(b64urlToBytes(parts[1])));
    return {
      header: header,
      payload: payload,
      signatureHex: parts[2],
      signingInput: parts[0] + '.' + parts[1],
      headerB64: parts[0],
      payloadB64: parts[1],
    };
  }

  function signIn(options) {
    options = options || {};
    var clientId = options.clientId || (typeof location !== 'undefined' ? location.hostname : 'unknown');
    var nonce = options.nonce || randomNonce();
    var scope = options.scope || 'profile';

    return new Promise(function (resolve, reject) {
      if (typeof window === 'undefined') { reject(new Error('No window')); return; }
      var qs = 'client_id=' + encodeURIComponent(clientId)
        + '&nonce='      + encodeURIComponent(nonce)
        + '&scope='      + encodeURIComponent(scope)
        + '&origin='     + encodeURIComponent(location.origin);
      var popup = window.open(ORIGIN + POPUP_PATH + '?' + qs, 'web3keys_signin', POPUP_FEATURES);
      if (!popup) { reject(new Error('Popup was blocked. Allow popups for this site and try again.')); return; }

      var done = false;
      function cleanup() {
        done = true;
        window.removeEventListener('message', onMessage);
        clearInterval(closeTimer);
      }
      function onMessage(event) {
        if (event.origin !== ORIGIN) return;
        if (!event.data || event.data.kind !== 'web3keys:signin-result') return;
        if (event.source !== popup) return;
        cleanup();
        if (event.data.error) reject(new Error(event.data.error));
        else resolve(event.data.payload);
        try { popup.close(); } catch (e) {}
      }
      var closeTimer = setInterval(function () {
        if (popup.closed && !done) { cleanup(); reject(new Error('Sign-in cancelled.')); }
      }, 400);

      window.addEventListener('message', onMessage);
    });
  }

  // Default in-button mark: a tiny styled "w3k" badge + label. Inline styles so
  // a dApp does not need to import our CSS.
  var BUTTON_STYLE = [
    'display:inline-flex','align-items:center','gap:10px',
    'background:#0a0c10','color:#fff',
    'font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif',
    'font-weight:600','font-size:14px','line-height:1',
    'padding:10px 16px','border-radius:10px',
    'border:1px solid rgba(255,255,255,0.12)','cursor:pointer',
    'box-shadow:0 0 0 1px rgba(0,229,255,0.06), 0 0 12px rgba(0,229,255,0.10)',
    'transition:all .2s ease',
  ].join(';');
  var MARK_STYLE = [
    'font-family:ui-monospace,SFMono-Regular,Menlo,monospace',
    'font-weight:800','font-size:11px',
    'background:linear-gradient(135deg,#00e5ff 0%,#6f42fb 100%)',
    'color:#000','padding:3px 6px','border-radius:5px','letter-spacing:-0.5px',
  ].join(';');

  function decorateElement(el) {
    if (el.getAttribute('data-web3keys-decorated') === '1') return;
    el.setAttribute('data-web3keys-decorated', '1');

    // If the element is empty, inject the default label + mark and styling.
    if (!el.textContent.trim() && !el.children.length) {
      el.style.cssText = BUTTON_STYLE;
      el.innerHTML =
        '<span style="' + MARK_STYLE + '">w3k</span>' +
        '<span>Sign in with Web3Keys</span>';
      el.addEventListener('mouseenter', function () { el.style.background = '#11141c'; });
      el.addEventListener('mouseleave', function () { el.style.background = '#0a0c10'; });
    }

    el.addEventListener('click', async function () {
      try {
        var result = await signIn({
          clientId: el.dataset.clientId,
          nonce: el.dataset.nonce,
          scope: el.dataset.scope,
        });
        el.dispatchEvent(new CustomEvent('web3keys-signin', { detail: result, bubbles: true }));
      } catch (e) {
        el.dispatchEvent(new CustomEvent('web3keys-signin-error', { detail: e, bubbles: true }));
      }
    });
  }

  function decorate(root) {
    var scope = root || document;
    var nodes = scope.querySelectorAll('[data-web3keys-signin]');
    for (var i = 0; i < nodes.length; i++) decorateElement(nodes[i]);
  }

  window.Web3Keys = {
    version: 1,
    signIn: signIn,
    parseIdToken: parseIdToken,
    decorate: decorate,
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () { decorate(); });
  } else {
    decorate();
  }
})();
