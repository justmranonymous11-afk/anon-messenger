#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const html = fs.readFileSync(path.join(root, 'public/index.html'), 'utf8');
const appJs = fs.readFileSync(path.join(root, 'public/app.js'), 'utf8');

const htmlIds = new Set([...html.matchAll(/\bid="([^"]+)"/g)].map((m) => m[1]));
const appIds = new Set([...appJs.matchAll(/\$\(['"]([^'"]+)['"]\)/g)].map((m) => m[1]));

const required = [
  'join-screen', 'chat-screen', 'join-btn', 'room-input', 'name-input', 'gen-btn',
  'mode-tag', 'peer-avatar', 'peer-status', 'messages', 'composer', 'msg-input',
  'send-btn', 'sticker-btn', 'attach-btn', 'mic-btn', 'back-btn', 'reconnect-banner',
  'reconnect-btn', 'notify-btn', 'profile-btn', 'ctx-menu', 'preview-overlay', 'toast',
];

let failed = false;
for (const id of required) {
  if (!htmlIds.has(id)) {
    console.error('MISSING in HTML:', id);
    failed = true;
  }
}

const orphanApp = [...appIds].filter((id) => !htmlIds.has(id));
if (orphanApp.length) {
  console.warn('app.js references IDs not in index.html:', orphanApp.join(', '));
}

if (failed) process.exit(1);
console.log('OK: UI validation passed —', htmlIds.size, 'HTML ids,', appIds.size, 'app.js selectors');
