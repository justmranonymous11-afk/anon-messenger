/*
 * Anonymous Messenger — Signaling Server (zero dependencies)
 *
 * This server is intentionally minimal. Its ONLY job is to:
 *   1) Serve the static web client.
 *   2) Relay WebRTC signaling messages (SDP offers/answers, ICE candidates,
 *      and an opaque ECDH public-key blob) between exactly two peers who
 *      share a room code.
 *
 * It NEVER sees:
 *   - chat messages (encrypted end-to-end with AES-GCM on top of WebRTC DataChannel)
 *   - audio/video media (encrypted end-to-end by WebRTC DTLS-SRTP)
 *   - user identities (there are none; clients are anonymous)
 *
 * It NEVER persists:
 *   - rooms exist only in process memory and disappear when both peers disconnect
 *   - no logs of message content, no analytics, no cookies
 *
 * Implemented with Node.js stdlib only (http + crypto). Implements RFC 6455
 * WebSocket text frames so we don't need the `ws` package.
 */

'use strict';

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 4040;
const PUBLIC_DIR = path.join(__dirname, 'public');

// Web Push (optional — install with `npm install`). Generic "new message" only; no content.
let webpush = null;
let vapidKeys = null;
try {
  webpush = require('web-push');
} catch {
  console.warn('[push] web-push not installed — run npm install for background notifications');
}

function getVapidKeys() {
  if (vapidKeys) return vapidKeys;
  if (!webpush) return null;
  const pub = (process.env.VAPID_PUBLIC_KEY || '').trim();
  const priv = (process.env.VAPID_PRIVATE_KEY || '').trim();
  if (pub && priv) {
    vapidKeys = { publicKey: pub, privateKey: priv };
  } else {
    vapidKeys = webpush.generateVAPIDKeys();
    console.warn(
      '[push] Auto-generated VAPID keys (set on Railway so they persist across deploys):\n' +
      `  VAPID_PUBLIC_KEY=${vapidKeys.publicKey}\n` +
      `  VAPID_PRIVATE_KEY=${vapidKeys.privateKey}`
    );
  }
  webpush.setVapidDetails(
    (process.env.VAPID_SUBJECT || 'mailto:anon@localhost').trim(),
    vapidKeys.publicKey,
    vapidKeys.privateKey
  );
  return vapidKeys;
}

function sendPushTo(ws, data) {
  if (!webpush || !ws._pushSub) return;
  const keys = getVapidKeys();
  if (!keys) return;
  const payload = JSON.stringify({
    title: data.title || 'Anon Messenger',
    body: data.body || 'New message',
    room: data.room || ws._roomId || '',
  });
  webpush.sendNotification(ws._pushSub, payload).catch((err) => {
    if (err && err.statusCode === 410) ws._pushSub = null;
  });
}

// TURN / ICE configuration (priority order):
//   1) TURN_SERVERS or ICE_SERVERS_JSON — raw JSON array of RTCIceServer objects
//   2) Metered.ca — METERED_APP_SUBDOMAIN (+ optional METERED_DOMAIN / METERED_APP_NAME)
//      and METERED_API_KEY or METERED_SECRET_KEY (Secret Key from Developers tab)
//   3) Public STUN fallback (P2P often fails across networks without TURN)
//
// Chat still works without TURN via encrypted WebSocket relay (see `relay` message).
// Credential apiKey (40-char hex from TURN Server → credential). NOT the Developers Secret Key.
function resolveMeteredCredentialApiKey() {
  const explicit = (
    process.env.METERED_TURN_API_KEY
    || process.env.METERED_CREDENTIAL_API_KEY
    || ''
  ).trim();
  if (explicit) return explicit;
  // Common mistake: pasting credential apiKey into METERED_API_KEY on Railway.
  const maybe = (process.env.METERED_API_KEY || '').trim();
  if (/^[a-f0-9]{32,64}$/i.test(maybe)) return maybe;
  return '';
}

// Secret Key from Developers tab — only for optional auto-create (usually skip; use apiKey instead).
function resolveMeteredSecretKey() {
  const s = (process.env.METERED_SECRET_KEY || process.env.METERED_SECRET || '').trim();
  if (s) return s;
  const maybe = (process.env.METERED_API_KEY || '').trim();
  if (maybe && !/^[a-f0-9]{32,64}$/i.test(maybe)) return maybe;
  return '';
}

const TURN_CACHE_MS = 23 * 60 * 60 * 1000; // successful TURN config
const TURN_ERROR_CACHE_MS = 30 * 1000; // do not cache failures for 23h
const MAX_RELAY_BYTES = 512 * 1024;
let turnCache = { expires: 0, body: null };

const STUN_FALLBACK = [
  { urls: 'stun:stun.l.google.com:19302' },
  { urls: 'stun:stun1.l.google.com:19302' },
  { urls: 'stun:stun2.l.google.com:19302' },
];

function meteredHost() {
  const raw = (
    process.env.METERED_APP_SUBDOMAIN
    || process.env.METERED_DOMAIN
    || process.env.METERED_APP_NAME
    || ''
  ).trim();
  if (!raw) return '';
  let h = raw;
  if (h.startsWith('https://')) h = h.slice(8);
  if (h.startsWith('http://')) h = h.slice(7);
  h = h.replace(/\/+$/, '');
  // Allow bare app name "myapp" → "myapp.metered.live"
  if (!h.includes('.') && /^[a-z0-9-]+$/i.test(h)) h = `${h}.metered.live`;
  return h;
}

function iceServersFromEnvJson() {
  const raw = process.env.TURN_SERVERS || process.env.ICE_SERVERS_JSON;
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw);
    const list = Array.isArray(parsed) ? parsed : parsed.iceServers;
    if (!Array.isArray(list) || !list.length) return null;
    return normalizeIceServers(list);
  } catch (e) {
    console.warn('[turn] TURN_SERVERS JSON parse failed:', e.message || e);
    return null;
  }
}

function normalizeIceServers(raw) {
  if (!Array.isArray(raw)) return [...STUN_FALLBACK];
  const out = [];
  for (const entry of raw) {
    if (!entry) continue;
    let urls = entry.urls || entry.url;
    if (!urls) continue;
    if (!Array.isArray(urls)) urls = [String(urls)];
    const item = { urls };
    const user = entry.username || entry.user;
    const cred = entry.credential || entry.password || entry.credentialPassword;
    if (user) item.username = String(user);
    if (cred) item.credential = String(cred);
    out.push(item);
  }
  return out.length ? out : [...STUN_FALLBACK];
}

function iceHasTurn(servers) {
  return servers.some((s) => {
    const u = s.urls;
    const list = Array.isArray(u) ? u : [u];
    return list.some((x) => /^turns?:/i.test(String(x)));
  });
}

/** Never expose secretKey / apiKey in API responses or logs shown to clients. */
function redactSecrets(text) {
  return String(text)
    .replace(/secretKey=[^&\s'"`]+/gi, 'secretKey=[redacted]')
    .replace(/apiKey=[^&\s'"`]+/gi, 'apiKey=[redacted]');
}

function turnFromStaticUserPass() {
  const user = (process.env.METERED_TURN_USERNAME || '').trim();
  const pass = (process.env.METERED_TURN_PASSWORD || '').trim();
  if (!user || !pass) return null;
  return normalizeIceServers([
    { urls: 'stun:stun.relay.metered.ca:80' },
    { urls: 'turn:global.relay.metered.ca:80', username: user, credential: pass },
    { urls: 'turn:global.relay.metered.ca:80?transport=tcp', username: user, credential: pass },
    { urls: 'turn:global.relay.metered.ca:443', username: user, credential: pass },
    { urls: 'turns:global.relay.metered.ca:443?transport=tcp', username: user, credential: pass },
  ]);
}

async function meteredFetchIceByApiKey(apiKey) {
  const raw = await meteredRequest(
    'GET',
    `/api/v1/turn/credentials?apiKey=${encodeURIComponent(apiKey)}`,
  );
  const list = Array.isArray(raw) ? raw : (raw && raw.iceServers);
  return normalizeIceServers(list);
}

function meteredRequest(method, path, body) {
  return new Promise((resolve, reject) => {
    const host = meteredHost();
    if (!host) { reject(new Error('no metered host')); return; }
    const url = new URL(`https://${host}${path}`);
    const payload = body ? JSON.stringify(body) : null;
    const req = https.request(url, {
      method,
      timeout: 8000,
      headers: payload ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } : {},
    }, (res) => {
      let buf = '';
      res.setEncoding('utf8');
      res.on('data', (c) => { buf += c; if (buf.length > 64 * 1024) req.destroy(); });
      res.on('end', () => {
        if (res.statusCode < 200 || res.statusCode >= 300) {
          const snippet = (buf || '').slice(0, 200);
          reject(new Error(`Metered ${method} ${path.split('?')[0]} → ${res.statusCode} ${snippet}`));
          return;
        }
        try { resolve(buf ? JSON.parse(buf) : null); }
        catch (e) { reject(e); }
      });
    });
    req.on('timeout', () => { req.destroy(); reject(new Error('Metered timeout')); });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function fetchTurnFromMetered() {
  const staticUp = turnFromStaticUserPass();
  if (staticUp) {
    return {
      servers: staticUp,
      source: iceHasTurn(staticUp) ? 'metered-static-user' : 'stun-only',
      hint: null,
    };
  }

  const host = meteredHost();
  if (!host) {
    return {
      servers: [...STUN_FALLBACK],
      source: 'stun-only',
      hint: 'Set METERED_APP_SUBDOMAIN to yourapp (→ yourapp.metered.live)',
    };
  }

  const turnApiKey = resolveMeteredCredentialApiKey();
  const secretKey = resolveMeteredSecretKey();

  if (turnApiKey) {
    try {
      const servers = await meteredFetchIceByApiKey(turnApiKey);
      return {
        servers,
        source: iceHasTurn(servers) ? 'metered-turn' : 'metered-stun-only',
        hint: null,
      };
    } catch (e) {
      const msg = redactSecrets(e.message || e);
      console.warn('[turn] credential apiKey fetch failed:', msg);
      // Fall through to username/password or secret POST if configured.
    }
  }

  if (!secretKey) {
    return {
      servers: [...STUN_FALLBACK],
      source: 'stun-only',
      hint: turnApiKey
        ? 'TURN apiKey set but fetch failed — add METERED_TURN_USERNAME + METERED_TURN_PASSWORD from same credential'
        : 'Set METERED_TURN_API_KEY (credential apiKey) on Railway — not the Secret Key',
    };
  }

  try {
    const created = await meteredRequest(
      'POST',
      `/api/v1/turn/credential?secretKey=${encodeURIComponent(secretKey)}`,
      { expiryInSeconds: 86400, label: 'anon-messenger' },
    );
    const apiKey = created && (created.apiKey || created.api_key);
    if (!apiKey) {
      return {
        servers: [...STUN_FALLBACK],
        source: 'metered-no-key',
        hint: 'Metered POST succeeded but no apiKey — use METERED_TURN_API_KEY from dashboard',
      };
    }
    const servers = await meteredFetchIceByApiKey(apiKey);
    return {
      servers,
      source: iceHasTurn(servers) ? 'metered-turn' : 'metered-stun-only',
      hint: null,
    };
  } catch (e) {
    const raw = String(e.message || e);
    const msg = redactSecrets(raw);
    console.warn('[turn] Metered fetch failed:', msg);
    let hint = redactSecrets(raw).slice(0, 120);
    if (raw.includes('403')) {
      hint = 'Metered 403: max credentials. In Metered → TURN Server → open a credential → copy its apiKey → set METERED_TURN_API_KEY on Railway (remove auto-create).';
    } else if (raw.includes('401')) {
      hint = 'Invalid METERED_API_KEY — use Secret Key from Developers tab, or use METERED_TURN_API_KEY instead.';
    }
    return {
      servers: [...STUN_FALLBACK],
      source: 'error',
      hint,
    };
  }
}

async function getIceServers(forceRefresh = false) {
  const now = Date.now();
  if (!forceRefresh && turnCache.body && now < turnCache.expires) return turnCache.body;

  const fromJson = iceServersFromEnvJson();
  if (fromJson) {
    const body = {
      servers: fromJson,
      source: iceHasTurn(fromJson) ? 'env-json-turn' : 'env-json-stun',
      hint: null,
    };
    turnCache = { expires: now + TURN_CACHE_MS, body };
    return body;
  }

  const body = await fetchTurnFromMetered();
  const ok = body.source === 'metered-turn' || iceHasTurn(body.servers);
  turnCache = { expires: now + (ok ? TURN_CACHE_MS : TURN_ERROR_CACHE_MS), body };
  return body;
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.json': 'application/json; charset=utf-8',
  '.webmanifest': 'application/manifest+json; charset=utf-8',
};

// =================================================================
// Static file server
// =================================================================
const httpServer = http.createServer(async (req, res) => {
  try {
    const urlPath = decodeURIComponent((req.url || '/').split('?')[0]);

    if (urlPath === '/api/push-vapid') {
      const keys = getVapidKeys();
      res.writeHead(200, {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store',
      });
      res.end(JSON.stringify({
        publicKey: keys ? keys.publicKey : null,
        enabled: !!keys,
      }));
      return;
    }

    if (urlPath === '/api/turn') {
      const force = (req.url || '').includes('refresh=1');
      const cfg = await getIceServers(force);
      const turnApiKey = resolveMeteredCredentialApiKey();
      res.writeHead(200, {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
      });
      res.end(JSON.stringify({
        iceServers: cfg.servers,
        hasTurn: iceHasTurn(cfg.servers),
        source: cfg.source,
        hint: cfg.hint ? redactSecrets(cfg.hint) : null,
        relayAvailable: true,
        meteredHost: meteredHost() || null,
        config: {
          subdomain: !!meteredHost(),
          turnApiKey: !!turnApiKey,
          secretKey: !!resolveMeteredSecretKey(),
          staticUser: !!(process.env.METERED_TURN_USERNAME && process.env.METERED_TURN_PASSWORD),
          apiKeyInWrongVar: !!(process.env.METERED_API_KEY && /^[a-f0-9]{32,64}$/i.test(process.env.METERED_API_KEY.trim()) && !process.env.METERED_TURN_API_KEY),
        },
      }));
      return;
    }

    // Route /       → landing page
    //       /app    → chat app
    //       /ROOMCODE or /app/ROOMCODE → SPA (chat app reads pathname)
    let filePath;
    if (urlPath === '/') {
      filePath = path.join(PUBLIC_DIR, 'landing.html');
    } else if (urlPath === '/app' || urlPath === '/app/') {
      filePath = path.join(PUBLIC_DIR, 'index.html');
    } else {
      filePath = path.join(PUBLIC_DIR, urlPath);
    }

    if (!filePath.startsWith(PUBLIC_DIR)) {
      res.writeHead(403); res.end('Forbidden'); return;
    }

    fs.stat(filePath, (err, stat) => {
      const send = (p) => {
        const ext = path.extname(p).toLowerCase();
        res.writeHead(200, {
          'Content-Type': MIME[ext] || 'application/octet-stream',
          'Cache-Control': 'no-store',
          'X-Content-Type-Options': 'nosniff',
          'Referrer-Policy': 'no-referrer',
        });
        fs.createReadStream(p).pipe(res);
      };
      if (!err && stat.isFile()) { send(filePath); return; }
      // /@ROOMCODE, /ROOMCODE, or /app/ROOMCODE — serve the SPA.
      const seg = urlPath.replace(/^\/(?:app\/)?/, '').replace(/^@/, '');
      if (/^[A-Za-z0-9]{4,12}$/.test(seg)) {
        const spa = path.join(PUBLIC_DIR, 'index.html');
        fs.stat(spa, (err2, stat2) => {
          if (err2 || !stat2.isFile()) { res.writeHead(404); res.end('Not found'); return; }
          send(spa);
        });
        return;
      }
      res.writeHead(404); res.end('Not found');
    });
  } catch {
    res.writeHead(500); res.end('Server error');
  }
});

// =================================================================
// Minimal RFC 6455 WebSocket server
// =================================================================
const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

function acceptKey(key) {
  return crypto.createHash('sha1').update(key + WS_GUID).digest('base64');
}

httpServer.on('upgrade', (req, socket) => {
  if ((req.headers.upgrade || '').toLowerCase() !== 'websocket') {
    socket.destroy(); return;
  }
  const key = req.headers['sec-websocket-key'];
  if (!key) { socket.destroy(); return; }

  const responseHeaders = [
    'HTTP/1.1 101 Switching Protocols',
    'Upgrade: websocket',
    'Connection: Upgrade',
    `Sec-WebSocket-Accept: ${acceptKey(key)}`,
    '', '',
  ].join('\r\n');
  socket.write(responseHeaders);

  const ws = new WsConnection(socket);
  handleConnection(ws);
});

// Tiny WebSocket connection: text frames + close, masked-from-client.
// Handles fragmentation and large frames. No compression, no extensions.
class WsConnection {
  constructor(socket) {
    this.socket = socket;
    this.isAlive = true;
    this.buffer = Buffer.alloc(0);
    this.listeners = { message: [], close: [], error: [] };
    this._fragOpcode = 0;
    this._fragParts = [];

    socket.on('data', (chunk) => this._onData(chunk));
    socket.on('end', () => this._cleanup());
    socket.on('error', (e) => { this._emit('error', e); this._cleanup(); });
    socket.on('close', () => this._cleanup());

    // ping every 25s to keep NATs alive
    this._pingInt = setInterval(() => {
      if (!this.isAlive) { try { socket.destroy(); } catch {} ; return; }
      this.isAlive = false;
      try { this._send(0x9, Buffer.alloc(0)); } catch {}
    }, 25000);
  }

  on(ev, cb) { (this.listeners[ev] = this.listeners[ev] || []).push(cb); }
  _emit(ev, arg) { (this.listeners[ev] || []).forEach(cb => { try { cb(arg); } catch {} }); }

  _cleanup() {
    if (this._closed) return;
    this._closed = true;
    clearInterval(this._pingInt);
    this._emit('close');
    try { this.socket.destroy(); } catch {}
  }

  send(text) {
    if (this._closed) return;
    const payload = Buffer.from(String(text), 'utf8');
    this._send(0x1, payload);
  }

  close() { this._send(0x8, Buffer.alloc(0)); this._cleanup(); }

  _send(opcode, payload) {
    const len = payload.length;
    let header;
    if (len < 126) {
      header = Buffer.alloc(2);
      header[1] = len;
    } else if (len < 65536) {
      header = Buffer.alloc(4);
      header[1] = 126;
      header.writeUInt16BE(len, 2);
    } else {
      header = Buffer.alloc(10);
      header[1] = 127;
      header.writeBigUInt64BE(BigInt(len), 2);
    }
    header[0] = 0x80 | (opcode & 0x0f); // FIN + opcode
    try {
      this.socket.write(Buffer.concat([header, payload]));
    } catch {
      this._cleanup();
    }
  }

  _onData(chunk) {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    while (true) {
      const frame = this._readFrame();
      if (!frame) return;
      const { fin, opcode, payload } = frame;

      if (opcode === 0x8) { // close
        this.close(); return;
      } else if (opcode === 0x9) { // ping
        this._send(0xA, payload); continue;
      } else if (opcode === 0xA) { // pong
        this.isAlive = true; continue;
      }

      if (opcode === 0x0) {
        // continuation
        this._fragParts.push(payload);
        if (fin) {
          const full = Buffer.concat(this._fragParts);
          const text = full.toString('utf8');
          this._fragParts = []; this._fragOpcode = 0;
          this._emit('message', text);
        }
      } else if (opcode === 0x1 || opcode === 0x2) {
        if (fin) {
          this._emit('message', payload.toString('utf8'));
        } else {
          this._fragOpcode = opcode;
          this._fragParts = [payload];
        }
      }
    }
  }

  _readFrame() {
    if (this.buffer.length < 2) return null;
    const b0 = this.buffer[0];
    const b1 = this.buffer[1];
    const fin = (b0 & 0x80) !== 0;
    const opcode = b0 & 0x0f;
    const masked = (b1 & 0x80) !== 0;
    let payloadLen = b1 & 0x7f;
    let offset = 2;

    if (payloadLen === 126) {
      if (this.buffer.length < offset + 2) return null;
      payloadLen = this.buffer.readUInt16BE(offset); offset += 2;
    } else if (payloadLen === 127) {
      if (this.buffer.length < offset + 8) return null;
      const big = this.buffer.readBigUInt64BE(offset);
      if (big > BigInt(Number.MAX_SAFE_INTEGER)) { this._cleanup(); return null; }
      payloadLen = Number(big); offset += 8;
    }

    let mask = null;
    if (masked) {
      if (this.buffer.length < offset + 4) return null;
      mask = this.buffer.slice(offset, offset + 4);
      offset += 4;
    }

    if (this.buffer.length < offset + payloadLen) return null;

    let payload = this.buffer.slice(offset, offset + payloadLen);
    if (masked) {
      const out = Buffer.allocUnsafe(payloadLen);
      for (let i = 0; i < payloadLen; i++) out[i] = payload[i] ^ mask[i & 3];
      payload = out;
    }

    this.buffer = this.buffer.slice(offset + payloadLen);
    return { fin, opcode, payload };
  }
}

// =================================================================
// Signaling.
// Each room has a mode set by its first joiner:
//   '1on1'  - hard cap 2 peers (private chat + calls)
//   'group' - hard cap 5 peers (mesh group chat, no group calls yet)
// Each peer gets a server-assigned unique id; signals are routed via
// `to: peerId`. Existing peers are notified when someone joins/leaves.
// =================================================================
const CAPS = { '1on1': 2, 'group': 5 };
const rooms = new Map(); // roomId -> { mode, peers: Map<peerId, WsConnection> }

function safeSend(ws, obj) {
  try { ws.send(JSON.stringify(obj)); } catch {}
}

function makePeerId() {
  // 12 chars from a base32-ish alphabet — short, URL-safe, easy to log
  const alphabet = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
  const bytes = crypto.randomBytes(12);
  let id = '';
  for (let i = 0; i < bytes.length; i++) id += alphabet[bytes[i] % alphabet.length];
  return id;
}

function leave(ws) {
  const room = ws._room;
  if (!room || !ws._peerId) return;
  ws._pushSub = null;
  room.peers.delete(ws._peerId);
  for (const peer of room.peers.values()) {
    safeSend(peer, { type: 'peer-left', id: ws._peerId });
  }
  if (room.peers.size === 0 && ws._roomId) rooms.delete(ws._roomId);
  ws._room = null;
  ws._roomId = null;
  ws._peerId = null;
}

// Drop sockets that closed without a clean leave (refresh, tab kill).
function pruneDeadPeers(room) {
  for (const [id, peer] of room.peers) {
    if (peer._closed) room.peers.delete(id);
  }
}

function notifyRoomReady(room) {
  const n = room.peers.size;
  if (room.mode === '1on1') {
    if (n !== 2) return;
  } else if (n < 2) {
    return;
  }
  const ids = Array.from(room.peers.keys());
  for (const peer of room.peers.values()) {
    safeSend(peer, { type: 'ready', peers: ids });
  }
}

function handleConnection(ws) {
  ws._room = null;
  ws._roomId = null;
  ws._peerId = null;
  ws._pushSub = null;

  ws.on('message', (data) => {
    let msg;
    try { msg = JSON.parse(data); } catch { return; }
    if (!msg || typeof msg.type !== 'string') return;

    switch (msg.type) {
      case 'join': {
        const roomId = String(msg.room || '').trim().toUpperCase();
        if (!/^[A-Z0-9]{4,12}$/.test(roomId)) {
          safeSend(ws, { type: 'error', error: 'Invalid room code' }); return;
        }
        const requestedMode = (msg.mode === 'group' || msg.mode === '1on1') ? msg.mode : '1on1';
        // Re-join on same socket without leave left a ghost id in the room.
        if (ws._peerId) leave(ws);
        let room = rooms.get(roomId);
        if (!room) {
          // First joiner sets the room mode.
          room = { mode: requestedMode, peers: new Map() };
          rooms.set(roomId, room);
        }
        pruneDeadPeers(room);
        if (room.peers.size > 0 && requestedMode !== room.mode) {
          safeSend(ws, {
            type: 'error',
            error: room.mode === 'group'
              ? 'This room is already a group — pick Group on the home screen, or use a new code.'
              : 'This room is 1-on-1 only — pick "Just us", or use a new code for a group.',
          });
          return;
        }
        const cap = CAPS[room.mode] || 2;
        if (room.peers.size >= cap) {
          safeSend(ws, {
            type: 'error',
            error: room.mode === 'group'
              ? `Group room is full (max ${cap} users)`
              : `Private room is full (already has 2 people)`,
          });
          return;
        }
        const myId = makePeerId();
        const existingIds = Array.from(room.peers.keys());
        room.peers.set(myId, ws);
        ws._room = room;
        ws._roomId = roomId;
        ws._peerId = myId;
        safeSend(ws, {
          type: 'joined',
          room: roomId,
          you: myId,
          mode: room.mode,
          peers: existingIds,
        });
        // Two-person group uses `ready` only (like 1-on-1). peer-joined + ready
        // together caused offer collisions; 3+ still need peer-joined for mesh.
        const pairGroup = room.mode === 'group' && room.peers.size === 2;
        for (const [id, peer] of room.peers) {
          if (id === myId) continue;
          if (!pairGroup) safeSend(peer, { type: 'peer-joined', id: myId });
        }
        notifyRoomReady(room);
        return;
      }

      case 'signal': {
        if (!ws._room || !ws._peerId) return;
        const toId = typeof msg.to === 'string' ? msg.to : null;
        if (!toId) return;
        const target = ws._room.peers.get(toId);
        if (!target) return;
        safeSend(target, { type: 'signal', from: ws._peerId, payload: msg.payload });
        return;
      }

      case 'reconnect': {
        if (!ws._room || !ws._peerId) return;
        const toId = typeof msg.to === 'string' ? msg.to : null;
        if (!toId) return;
        const target = ws._room.peers.get(toId);
        if (!target) return;
        safeSend(target, { type: 'reconnect', from: ws._peerId, relay: !!msg.relay });
        return;
      }

      case 'relay': {
        if (!ws._room || !ws._peerId) return;
        const toId = typeof msg.to === 'string' ? msg.to : null;
        const payload = msg.payload;
        if (!toId || typeof payload !== 'string') return;
        if (payload.length > MAX_RELAY_BYTES) return;
        const target = ws._room.peers.get(toId);
        if (!target) return;
        safeSend(target, { type: 'relay', from: ws._peerId, payload });
        sendPushTo(target, {
          title: 'Anon Messenger',
          body: 'New message',
          room: ws._roomId,
        });
        return;
      }

      case 'nudge': {
        if (!ws._room || !ws._peerId) return;
        const toId = typeof msg.to === 'string' ? msg.to : null;
        if (!toId) return;
        const target = ws._room.peers.get(toId);
        if (!target) return;
        sendPushTo(target, {
          title: 'Anon Messenger',
          body: 'New message',
          room: ws._roomId,
        });
        return;
      }

      case 'push-sub': {
        if (!ws._room || !ws._peerId) return;
        const sub = msg.subscription;
        if (!sub || typeof sub !== 'object' || !sub.endpoint) return;
        ws._pushSub = sub;
        return;
      }

      case 'push-unsub': {
        ws._pushSub = null;
        return;
      }

      case 'leave': {
        leave(ws);
        return;
      }
    }
  });

  ws.on('close', () => leave(ws));
  ws.on('error', () => leave(ws));
}

httpServer.listen(PORT, () => {
  const host = meteredHost();
  console.log(`
  Anonymous Messenger running:
    Local:   http://localhost:${PORT}
    TURN:    ${host ? host : '(not configured)'} turnApiKey=${resolveMeteredCredentialApiKey() ? 'yes' : 'no'} secret=${resolveMeteredSecretKey() ? 'yes' : 'no'} staticUser=${(process.env.METERED_TURN_USERNAME && process.env.METERED_TURN_PASSWORD) ? 'yes' : 'no'}
    Relay:   encrypted chat fallback enabled (no TURN required for text)

  Open the URL in two browser windows / devices, use the same room
  code in both, and you'll have an end-to-end encrypted chat + call.
`);
});
