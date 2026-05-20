/*
 * Smoke test: two clients join the same room, exchange a signal payload,
 * and verify the server relays it (and only it) to the other peer.
 *
 * Uses only Node's built-in WebSocket (available since Node 22).
 */
'use strict';

const PORT = process.env.PORT || 3789;
const URL = `ws://127.0.0.1:${PORT}`;

class Client {
  constructor(label) {
    this.label = label;
    this.queue = [];
    this.waiters = [];
  }
  connect() {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(URL);
      this.ws = ws;
      ws.addEventListener('open', () => resolve());
      ws.addEventListener('error', () => reject(new Error(`${this.label} error`)));
      ws.addEventListener('message', (ev) => {
        const msg = JSON.parse(ev.data);
        if (this.waiters.length) this.waiters.shift()(msg);
        else this.queue.push(msg);
      });
    });
  }
  send(obj) { this.ws.send(JSON.stringify(obj)); }
  close() { this.ws.close(); }
  next(timeoutMs = 2000) {
    return new Promise((resolve, reject) => {
      if (this.queue.length) return resolve(this.queue.shift());
      const t = setTimeout(() => reject(new Error(`${this.label} next() timeout`)), timeoutMs);
      this.waiters.push((m) => { clearTimeout(t); resolve(m); });
    });
  }
}

function assert(cond, msg) {
  if (!cond) { console.error('FAIL:', msg); process.exit(1); }
}

(async () => {
  const room = 'SMOKE1';

  const a = new Client('A'); await a.connect();
  const b = new Client('B'); await b.connect();

  a.send({ type: 'join', room });
  const aJoined = await a.next();
  console.log('A joined:', aJoined);
  assert(aJoined.type === 'joined' && aJoined.initiator === true, 'A should be initiator');

  b.send({ type: 'join', room });
  const bJoined = await b.next();
  console.log('B joined:', bJoined);
  assert(bJoined.type === 'joined' && bJoined.initiator === false, 'B should not be initiator');

  const aReady = await a.next();
  const bReady = await b.next();
  console.log('A ready:', aReady, ' B ready:', bReady);
  assert(aReady.type === 'ready' && bReady.type === 'ready', 'both should get ready');

  a.send({ type: 'signal', payload: { kind: 'offer', sdp: '<dummy-sdp>' } });
  const got = await b.next();
  console.log('B got relayed signal:', JSON.stringify(got));
  assert(
    got.type === 'signal' && got.payload.kind === 'offer' && got.payload.sdp === '<dummy-sdp>',
    'relay should deliver payload untouched'
  );

  // 2-user cap
  const c = new Client('C'); await c.connect();
  c.send({ type: 'join', room });
  const cErr = await c.next();
  console.log('C tried to join:', cErr);
  assert(cErr.type === 'error', 'server should reject 3rd user');

  // Test invalid room code
  const d = new Client('D'); await d.connect();
  d.send({ type: 'join', room: 'bad!' });
  const dErr = await d.next();
  console.log('D tried bad code:', dErr);
  assert(dErr.type === 'error', 'server should reject invalid code');
  d.close();

  // peer-left
  a.close();
  const bGotLeave = await b.next();
  console.log('B got after A close:', bGotLeave);
  assert(bGotLeave.type === 'peer-left', 'B should be notified peer-left');

  // Large payload relay
  const e = new Client('E'); await e.connect();
  e.send({ type: 'join', room: 'BIG1' });
  await e.next();
  const f = new Client('F'); await f.connect();
  f.send({ type: 'join', room: 'BIG1' });
  await f.next(); await e.next(); await f.next();

  const bigSdp = 'x'.repeat(150000); // > 64KB triggers 16-bit length, > 125 anyway
  e.send({ type: 'signal', payload: { kind: 'offer', sdp: bigSdp } });
  const gotBig = await f.next();
  assert(gotBig.payload.sdp.length === bigSdp.length, 'large payload should pass through');
  console.log('Large payload (150KB) relayed: OK');

  b.close(); c.close(); e.close(); f.close();
  console.log('\n  ALL SMOKE TESTS PASSED ');
  process.exit(0);
})().catch(e => { console.error(e); process.exit(1); });
