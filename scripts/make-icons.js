#!/usr/bin/env node
/**
 * Regenerate the PNG app icons in public/ from the brand mark.
 * Needs Playwright with a Chromium build (dev-only; not an app dependency):
 *   npx -y playwright@1 install chromium   # once, if not already installed
 *   node scripts/make-icons.js
 * Set CHROMIUM_PATH to use an existing Chromium binary instead.
 */
'use strict';
const path = require('path');
const { chromium } = require('playwright');
const OUT = process.argv[2] || path.join(__dirname, '..', 'public');
const MARK = `
  <defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
    <stop offset="0" stop-color="#8B5CFF"/><stop offset=".55" stop-color="#FF4FA3"/><stop offset="1" stop-color="#FF9147"/>
  </linearGradient></defs>
  <path d="M20 6h24a14 14 0 0 1 14 14v12a14 14 0 0 1-14 14H28L15 57V45.2A14 14 0 0 1 6 32V20A14 14 0 0 1 20 6z" fill="url(#g)"/>
  <rect x="15" y="17" width="34" height="8" rx="2" fill="#0A0614"/>
  <rect x="15" y="29" width="21" height="6" rx="3" fill="#fff" fill-opacity=".92"/>
  <circle cx="43" cy="32" r="3" fill="#C6FF4A"/>`;
// Mark spans x 6..58, y 6..57 in a 64 box -> centre (32, 31.5)
const markAt = (size, frac) => {
  const s = size * frac / 52;                 // 52 = mark width in viewBox units
  const tx = size / 2 - 32 * s, ty = size / 2 - 31.5 * s;
  return `<g transform="translate(${tx} ${ty}) scale(${s})">${MARK}</g>`;
};
const bg = (size, r) => `
  <defs><radialGradient id="glow" cx=".3" cy=".2" r=".9">
    <stop offset="0" stop-color="#2A1452"/><stop offset=".6" stop-color="#120A24"/><stop offset="1" stop-color="#0A0614"/>
  </radialGradient></defs>
  <rect width="${size}" height="${size}" rx="${r}" fill="url(#glow)"/>`;
const ICONS = [
  // "any" icons: rounded tile so they look finished on desktops/launchers
  { file: 'icon-192.png', size: 192, svg: s => bg(s, s * 0.22) + markAt(s, 0.62) },
  { file: 'icon-512.png', size: 512, svg: s => bg(s, s * 0.22) + markAt(s, 0.62) },
  // maskable: full-bleed, mark kept inside the 80% safe zone
  { file: 'icon-maskable-512.png', size: 512, svg: s => bg(s, 0) + markAt(s, 0.5) },
  // iOS home screen: full-bleed square (iOS rounds the corners itself)
  { file: 'apple-touch-icon.png', size: 180, svg: s => bg(s, 0) + markAt(s, 0.6) },
  // Android notification badge: white silhouette on transparent
  { file: 'badge-72.png', size: 72, transparent: true, svg: s => {
      const k = s * 0.78 / 52, tx = s / 2 - 32 * k, ty = s / 2 - 31.5 * k;
      return `<defs><mask id="m"><rect width="64" height="64" fill="#fff"/><rect x="15" y="17" width="34" height="8" rx="2" fill="#000"/><rect x="15" y="29" width="21" height="6" rx="3" fill="#000"/></mask></defs>
        <g transform="translate(${tx} ${ty}) scale(${k})"><path mask="url(#m)" d="M20 6h24a14 14 0 0 1 14 14v12a14 14 0 0 1-14 14H28L15 57V45.2A14 14 0 0 1 6 32V20A14 14 0 0 1 20 6z" fill="#fff"/></g>`; } },
];
(async () => {
  const b = await chromium.launch(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {});
  for (const ic of ICONS) {
    const p = await b.newPage({ viewport: { width: ic.size, height: ic.size }, deviceScaleFactor: 1 });
    await p.setContent(`<html><body style="margin:0;background:transparent"><svg xmlns="http://www.w3.org/2000/svg" width="${ic.size}" height="${ic.size}" viewBox="0 0 ${ic.size} ${ic.size}" style="display:block">${ic.svg(ic.size)}</svg></body></html>`);
    await p.screenshot({ path: `${OUT}/${ic.file}`, omitBackground: true });
    await p.close();
    console.log('wrote', ic.file);
  }
  await b.close();
})();
