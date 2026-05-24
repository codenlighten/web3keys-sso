// Server-rendered pages. Kept as template literals to avoid a build step.

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

function identiconSvg(pubKeyHex, size = 96) {
  const hash = String(pubKeyHex || '').toLowerCase().padEnd(20, '0');
  const cells = [];
  for (let i = 0; i < 15; i++) cells.push((parseInt(hash[i] || '0', 16) & 1) === 1);
  const hue = parseInt(hash.slice(15, 18), 16) % 360;
  const color = `hsl(${hue}, 60%, 42%)`;
  const bg = `hsl(${hue}, 60%, 95%)`;
  const cs = size / 5;
  let rects = '';
  for (let row = 0; row < 5; row++) {
    for (let col = 0; col < 5; col++) {
      const cellCol = col < 3 ? col : 4 - col;
      const idx = row * 3 + cellCol;
      if (cells[idx]) {
        rects += `<rect x="${col * cs}" y="${row * cs}" width="${cs}" height="${cs}" fill="${color}"/>`;
      }
    }
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="${size}" height="${size}"><rect width="${size}" height="${size}" fill="${bg}" rx="${size * 0.16}"/>${rects}</svg>`;
}

export function renderProfilePage(record) {
  const handle = escapeHtml(record.handle);
  const display = escapeHtml(record.displayName || record.handle);
  const pubKey = escapeHtml(record.pubKey);
  const address = escapeHtml(record.address);
  const claimedAt = new Date(record.claimedAt).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>${display} (@${handle}) — Web3Keys</title>
  <meta name="description" content="${display}'s verified identity on Web3Keys." />
  <meta name="theme-color" content="#0a0c10" />
  <meta property="og:title" content="${display} (@${handle})" />
  <meta property="og:description" content="Verified identity on Web3Keys" />
  <meta property="og:type" content="profile" />
  <meta property="og:url" content="https://web3keys.com/u/${handle}" />
  <meta name="twitter:card" content="summary" />
  <link rel="icon" type="image/svg+xml" href="/favicon.svg" />
  <link rel="stylesheet" href="/styles.css" />
</head>
<body class="profile-body">
  <main class="card profile-card">
    <a class="profile-back" href="/">← Web3Keys</a>
    <div class="profile-avatar">${identiconSvg(record.pubKey, 112)}</div>
    <h1 class="profile-name">${display}</h1>
    <div class="profile-handle">${handle}@web3keys.com</div>
    <div class="profile-verified"><span class="pill" data-kind="ok">Verified identity</span></div>

    <section class="profile-details">
      <div class="row"><span class="label">Public key</span><code>${pubKey}</code></div>
      <div class="row"><span class="label">BSV address</span><code>${address}</code></div>
      <div class="row"><span class="label">Claimed</span><span>${claimedAt}</span></div>
    </section>

    <section class="profile-cta">
      <p class="muted">This page proves <strong>@${handle}</strong> controls the public key above. Anything signed by this key can be cryptographically verified back to this identity.</p>
      <a class="primary button-link" href="/verify">Verify a signed attestation →</a>
    </section>
  </main>
</body>
</html>`;
}

export function renderNotFoundPage(handle) {
  const h = escapeHtml(handle || '');
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>@${h} not found — Web3Keys</title>
  <link rel="stylesheet" href="/styles.css" />
</head>
<body class="profile-body">
  <main class="card profile-card">
    <a class="profile-back" href="/">← Web3Keys</a>
    <h1>@${h} is unclaimed</h1>
    <p class="muted">No one has claimed this handle on Web3Keys yet. Want it?</p>
    <a class="primary button-link" href="/app">Claim a handle →</a>
  </main>
</body>
</html>`;
}
