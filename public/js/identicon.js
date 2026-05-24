// Deterministic SVG identicon from a pubkey hex string.
// 5x5 grid mirrored across vertical axis, HSL color from the same hash.

export function identiconSvg(pubKeyHex, size = 64) {
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

export function setIdenticon(node, pubKeyHex, size = 64) {
  if (!node) return;
  node.innerHTML = identiconSvg(pubKeyHex, size);
}
