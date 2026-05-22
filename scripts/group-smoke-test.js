#!/usr/bin/env node
'use strict';

/**
 * Group room smoke test: 3 clients join same group code, exchange signals pairwise.
 */
const PORT = process.env.PORT || 4040;
const URL = `ws://${process.env.HOST || '127.0.0.1'}:${PORT}`;

class Client {
  constructor(label) {
    this.label = label;
    this.queue = [];
    this.waiters = [];
    this.myId = null;
  }
  connect() {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(URL);
      this.ws = ws;
      ws.addEventListener('open', () => resolve());
      ws.addEventListener('error', () => reject(new Error(`${this.label} ws error`)));
      ws.addEventListener('message', (ev) => {
        const msg = JSON.parse(ev.data);
        if (this.waiters.length) this.waiters.shift()(msg);
        else this.queue.push(msg);
      });
    });
  }
  send(obj) { this.ws.send(JSON.stringify(obj)); }
  close() { this.ws.close(); }
  async next(ms = 3000) {
    if (this.queue.length) return this.queue.shift();
    return new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error(`${this.label} timeout`)), ms);
      this.waiters.push((m) => { clearTimeout(t); resolve(m); });
    });
  }
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

(async () => {
  const room = 'GRP' + Math.random().toString(36).slice(2, 6).toUpperCase();
  const a = new Client('A');
  const b = new Client('B');
  const c = new Client('C');

  await a.connect();
  a.send({ type: 'join', room, mode: 'group' });
  const aJ = await a.next();
  assert(aJ.type === 'joined' && aJ.mode === 'group', 'A joined as group');
  a.myId = aJ.you;

  await b.connect();
  b.send({ type: 'join', room, mode: 'group' });
  const bJ = await b.next();
  const aPJ = await a.next();
  assert(bJ.type === 'joined' && bJ.peers.includes(a.myId), 'B sees A');
  assert(aPJ.type === 'peer-joined', 'A notified B joined');

  const aReady = await a.next();
  const bReady = await b.next();
  assert(aReady.type === 'ready' && bReady.type === 'ready', 'ready after 2 in group');

  // C joins
  await c.connect();
  c.send({ type: 'join', room, mode: 'group' });
  const cJ = await c.next();
  assert(cJ.type === 'joined' && cJ.peers.length === 2, 'C sees 2 peers');
  c.myId = cJ.you;

  // A and B get peer-joined + ready
  const aC = await a.next();
  const bC = await b.next();
  assert(aC.type === 'peer-joined' && aC.id === c.myId, 'A sees C');
  assert(bC.type === 'peer-joined' && bC.id === c.myId, 'B sees C');

  // Signal A -> C (may receive `ready` first after 3rd join)
  a.send({ type: 'signal', to: c.myId, payload: { kind: 'pubkey', key: 'testA' } });
  let cSig;
  for (let i = 0; i < 5; i++) {
    cSig = await c.next();
    if (cSig.type === 'signal') break;
  }
  assert(cSig && cSig.type === 'signal' && cSig.from === a.myId, 'C got signal from A');

  // Mode mismatch rejected (second client, different mode)
  const room2 = 'ONO' + Math.random().toString(36).slice(2, 5).toUpperCase();
  const d = new Client('D');
  const e = new Client('E');
  await d.connect();
  d.send({ type: 'join', room: room2, mode: '1on1' });
  await d.next();
  await e.connect();
  e.send({ type: 'join', room: room2, mode: 'group' });
  const eErr = await e.next();
  assert(eErr.type === 'error', 'mode mismatch should error');
  d.close(); e.close();

  a.close(); b.close(); c.close();
  console.log('OK: group smoke test passed —', room);
})().catch((e) => {
  console.error('FAIL:', e.message);
  process.exit(1);
});
