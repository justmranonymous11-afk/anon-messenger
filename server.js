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

// Optional Metered.ca TURN proxy. If both env vars are present, the server
// will expose /api/turn which returns time-limited ICE servers (STUN+TURN).
// If absent, /api/turn returns just public Google STUN — the app still works
// for users behind permissive NATs but P2P will fail for strict NATs.
const TURN_APP_SUBDOMAIN = process.env.METERED_APP_SUBDOMAIN || '';
const TURN_API_KEY = process.env.METERED_API_KEY || '';
const TURN_CACHE_MS = 5 * 60 * 1000;
let turnCache = { expires: 0, body: null };

const STUN_FALLBACK = [
  { urls: 'stun:stun.l.google.com:19302' },
  { urls: 'stun:stun1.l.google.com:19302' },
];

function fetchTurnFromMetered() {
  return new Promise((resolve) => {
    if (!TURN_APP_SUBDOMAIN || !TURN_API_KEY) return resolve(STUN_FALLBACK);
    const url = `https://${TURN_APP_SUBDOMAIN}/api/v1/turn/credentials?apiKey=${encodeURIComponent(TURN_API_KEY)}`;
    const req = https.get(url, { timeout: 4000 }, (res) => {
      if (res.statusCode !== 200) { res.resume(); return resolve(STUN_FALLBACK); }
      let buf = '';
      res.setEncoding('utf8');
      res.on('data', (c) => { buf += c; if (buf.length > 64 * 1024) req.destroy(); });
      res.on('end', () => {
        try {
          const parsed = JSON.parse(buf);
          if (Array.isArray(parsed) && parsed.length > 0) resolve(parsed);
          else resolve(STUN_FALLBACK);
        } catch { resolve(STUN_FALLBACK); }
      });
    });
    req.on('timeout', () => { req.destroy(); resolve(STUN_FALLBACK); });
    req.on('error', () => resolve(STUN_FALLBACK));
  });
}

async function getIceServers() {
  const now = Date.now();
  if (turnCache.body && now < turnCache.expires) return turnCache.body;
  const body = await fetchTurnFromMetered();
  turnCache = { expires: now + TURN_CACHE_MS, body };
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
};

// =================================================================
// Static file server
// =================================================================
const httpServer = http.createServer(async (req, res) => {
  try {
    const urlPath = decodeURIComponent((req.url || '/').split('?')[0]);

    if (urlPath === '/api/turn') {
      const iceServers = await getIceServers();
      res.writeHead(200, {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
      });
      res.end(JSON.stringify({ iceServers }));
      return;
    }

    let filePath = path.join(PUBLIC_DIR, urlPath === '/' ? 'index.html' : urlPath);

    if (!filePath.startsWith(PUBLIC_DIR)) {
      res.writeHead(403); res.end('Forbidden'); return;
    }

    fs.stat(filePath, (err, stat) => {
      if (err || !stat.isFile()) {
        res.writeHead(404); res.end('Not found'); return;
      }
      const ext = path.extname(filePath).toLowerCase();
      res.writeHead(200, {
        'Content-Type': MIME[ext] || 'application/octet-stream',
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'no-referrer',
      });
      fs.createReadStream(filePath).pipe(res);
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
// Signaling: rooms hold at most 2 peers
// =================================================================
const rooms = new Map(); // roomId -> Set<WsConnection>

function safeSend(ws, obj) {
  try { ws.send(JSON.stringify(obj)); } catch {}
}

function broadcastToOther(ws, room, obj) {
  for (const peer of room) if (peer !== ws) safeSend(peer, obj);
}

function leave(ws) {
  const room = ws._room;
  if (!room) return;
  room.delete(ws);
  broadcastToOther(ws, room, { type: 'peer-left' });
  if (room.size === 0 && ws._roomId) rooms.delete(ws._roomId);
  ws._room = null;
  ws._roomId = null;
}

function handleConnection(ws) {
  ws._room = null;
  ws._roomId = null;

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
        let room = rooms.get(roomId);
        if (!room) { room = new Set(); rooms.set(roomId, room); }
        if (room.size >= 2) {
          safeSend(ws, { type: 'error', error: 'Room is full (max 2 users)' }); return;
        }
        room.add(ws);
        ws._room = room;
        ws._roomId = roomId;
        const isInitiator = room.size === 1;
        safeSend(ws, { type: 'joined', room: roomId, initiator: isInitiator, peers: room.size });
        if (room.size === 2) {
          for (const peer of room) safeSend(peer, { type: 'ready' });
        }
        return;
      }

      case 'signal': {
        if (!ws._room) return;
        broadcastToOther(ws, ws._room, { type: 'signal', payload: msg.payload });
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
  console.log(`
  Anonymous Messenger running:
    Local:   http://localhost:${PORT}

  Open the URL in two browser windows / devices, use the same room
  code in both, and you'll have an end-to-end encrypted chat + call.
`);
});
