/*
 * Anonymous Messenger — Client
 *
 * Security model:
 *  - Server only sees opaque signaling payloads (SDP, ICE, ECDH public key).
 *  - On connect, both peers perform ECDH (P-256) -> HKDF/SHA-256 -> AES-GCM 256.
 *  - Chat / stickers / audio messages all travel over WebRTC DataChannel, but
 *    are additionally encrypted with AES-GCM by us before being sent. The
 *    WebRTC transport itself is also DTLS-encrypted, giving defense in depth.
 *  - Audio/video calls use WebRTC native DTLS-SRTP encryption.
 *  - No identifiers are sent. No persistence. No logs.
 *
 * In-band protocol (after AES-GCM unwrap, all messages are JSON):
 *   {t:'msg',      id, p:{iv,ct}, rp?:{iv,ct}}  encrypted text message; rp = encrypted
 *                                           JSON reply ref {id, by, n, k, s} when quoting
 *   {t:'msg-edit', id, p:{iv,ct}}           replace the text of the sender's own message
 *   {t:'msg-del',  id}                      delete a message for everyone
 *   {t:'typing',  on: bool}                typing indicator
 *   {t:'read',    id}                      read receipt for message id
 *   {t:'react',   id, emoji, on: bool}      add/remove reaction on message
 *   {t:'sticker',  id, s}                   sticker (emoji string)
 *   {t:'audio',    id, dur, mime, p:{iv,ct}} encrypted audio blob (small)
 *   {t:'blob-meta', id, kind, name?, mime, total, dur?}   start of multi-chunk transfer
 *   {t:'blob-chunk', id, idx, p:{iv,ct}}    one encrypted chunk
 *   {t:'blob-end', id}                      end of multi-chunk transfer
 *   {t:'profile',  p:{iv,ct}}                encrypted JSON {name, av} (session-only)
 *   {t:'call-invite', callType}             requesting a call
 *   {t:'call-accept'} / {t:'call-decline'} / {t:'call-end'}
 *   {t:'call-screen', on: bool}              peer started/stopped screen share
 */

(() => {
  'use strict';

  // ---------- Tiny helpers ----------
  const $ = (id) => document.getElementById(id);
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const buf2b64 = (buf) => {
    const bytes = new Uint8Array(buf);
    let s = '';
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
      s += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
    }
    return btoa(s);
  };
  const b642buf = (b64) => Uint8Array.from(atob(b64), c => c.charCodeAt(0)).buffer;
  const nowTime = () => {
    const d = new Date();
    return d.getHours().toString().padStart(2, '0') + ':' + d.getMinutes().toString().padStart(2, '0');
  };
  const randCode = (len = 6) => {
    const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    const bytes = crypto.getRandomValues(new Uint8Array(len));
    return Array.from(bytes, b => alphabet[b % alphabet.length]).join('');
  };
  const randId = () => buf2b64(crypto.getRandomValues(new Uint8Array(9))).replace(/[+/=]/g, '');

  const toast = (msg, ms = 2400) => {
    const t = $('toast');
    t.textContent = msg;
    t.classList.remove('hidden');
    clearTimeout(toast._t);
    toast._t = setTimeout(() => t.classList.add('hidden'), ms);
  };

  // ============ Loading screen ============
  let _loadFallback = null;

  function showLoading(text, pct, waiting = false) {
    const s = $('loading-screen');
    if (!s) return;
    s.classList.remove('hidden', 'fadeout');
    const bar = $('ls-bar');
    const txt = $('ls-txt');
    if (bar) {
      bar.classList.toggle('waiting', waiting);
      if (!waiting) bar.style.width = `${pct}%`;
    }
    if (txt && txt.textContent !== text) {
      txt.classList.add('fade');
      setTimeout(() => { if (txt) { txt.textContent = text; txt.classList.remove('fade'); } }, 180);
    }
  }

  function fadeOutLoading() {
    const s = $('loading-screen');
    if (!s || s.classList.contains('hidden')) return;
    s.classList.add('fadeout');
    setTimeout(() => { s.classList.add('hidden'); s.classList.remove('fadeout'); }, 450);
  }

  function hideLoading(delay = 300) {
    clearTimeout(_loadFallback);
    // Already in the chat (e.g. we were waiting alone) — don't flash the loader back up.
    if ($('loading-screen')?.classList.contains('hidden')) return;
    setTimeout(() => {
      showLoading('Secure channel established', 100);
      setTimeout(fadeOutLoading, 350);
    }, delay);
  }

  function cancelLoading() {
    clearTimeout(_loadFallback);
    const s = $('loading-screen');
    if (s) { s.classList.add('hidden'); s.classList.remove('fadeout'); }
  }

  // ============ WS auto-reconnect state ============
  let _wsRetryDelay = 1000;
  let _wsRetryTimer = null;
  let _wsCdTimer   = null;   // countdown interval

  function cancelWsRetry() {
    clearTimeout(_wsRetryTimer);
    clearInterval(_wsCdTimer);
    _wsRetryDelay = 1000;
    _wsRetryTimer = null;
  }

  function scheduleWsReconnect() {
    if (!state.inChat || !state.room) return;
    cancelWsRetry();
    const delay = _wsRetryDelay;
    _wsRetryDelay = Math.min(_wsRetryDelay * 2, 15000);
    let remaining = Math.ceil(delay / 1000);
    const setTxt = (t) => {
      const el = $('reconnect-banner-text');
      if (el) el.textContent = t;
    };
    setTxt(`Reconnecting in ${remaining}s…`);
    const banner = $('reconnect-banner');
    if (banner) banner.classList.remove('hidden');
    _wsCdTimer = setInterval(() => {
      remaining = Math.max(0, remaining - 1);
      setTxt(remaining > 0 ? `Reconnecting in ${remaining}s…` : 'Reconnecting…');
    }, 1000);
    _wsRetryTimer = setTimeout(async () => {
      clearInterval(_wsCdTimer);
      if (!state.inChat || !state.room) return;
      setTxt('Reconnecting…');
      try {
        await reconnectSession();
        _wsRetryDelay = 1000;
      } catch {
        if (state.inChat) scheduleWsReconnect();
      }
    }, delay);
  }

  // ============ Safety number ============
  function openSafetyDialog() {
    const peers = Array.from(state.peers.values()).filter(p => p.safetyNumber);
    if (!peers.length) { toast('Key exchange not yet complete'); return; }
    const el = $('safety-number');
    if (el) {
      if (peers.length === 1) {
        el.textContent = peers[0].safetyNumber;
      } else {
        el.innerHTML = peers.map((p, i) =>
          `<div class="sn-peer">Peer ${i + 1}: <span>${escapeHtml(p.safetyNumber)}</span></div>`
        ).join('');
      }
    }
    $('safety-dialog').classList.remove('hidden');
  }

  // ============ Smart scroll — only jump to bottom if user was already near bottom
  let unreadScrollCount = 0;

  function isNearBottom(el, threshold = 120) {
    return el.scrollHeight - el.scrollTop - el.clientHeight < threshold;
  }

  function smartScroll(force = false) {
    const wrap = $('messages');
    if (!wrap) return;
    if (force || isNearBottom(wrap)) {
      wrap.scrollTop = wrap.scrollHeight;
      unreadScrollCount = 0;
      updateScrollBtn();
    } else {
      unreadScrollCount++;
      updateScrollBtn();
    }
  }

  function updateScrollBtn() {
    const btn = $('scroll-btn');
    if (!btn) return;
    const wrap = $('messages');
    const atBottom = !wrap || isNearBottom(wrap);
    btn.classList.toggle('hidden', atBottom);
    const cnt = $('scroll-count');
    if (cnt) {
      const n = unreadScrollCount;
      cnt.textContent = n > 99 ? '99+' : n > 0 ? String(n) : '';
      cnt.classList.toggle('hidden', n === 0);
    }
  }

  // Share an invite link (room code) — Web Share API on mobile, clipboard fallback
  async function shareInvite(code) {
    if (!code || !/^[A-Z0-9]{4,12}$/.test(code)) return;
    const url = `${location.origin}/${code}`;
    const shareData = { title: 'Anon Messenger', text: `Join my private chat — room code: ${code}`, url };
    if (navigator.share) {
      try { await navigator.share(shareData); return; }
      catch (e) { if (e.name === 'AbortError') return; }
    }
    try {
      await navigator.clipboard.writeText(url);
      toast('Invite link copied!');
    } catch {
      try { await navigator.clipboard.writeText(code); toast('Room code copied!'); }
      catch { toast('Code: ' + code); }
    }
  }

  // ---------- Application state ----------
  // Multi-peer mesh: state.peers is a Map<peerId, Peer>. For a 2-person chat,
  // it has one entry; for a group, up to 4 entries (MAX_PEERS - 1).
  const state = {
    ws: null,
    myId: null,               // server-assigned id for THIS connection
    room: null,
    roomMode: '1on1',         // '1on1' | 'group' — set on join, confirmed by server
    myKeyPair: null,          // ECDH key pair, shared across all peer derivations
    peers: new Map(),         // peerId -> Peer
    // 1-on-1 call (only when peers.size === 1). Group calls = future.
    callPeerId: null,         // id of the peer we're calling
    localStream: null,
    screenStream: null,
    callType: null,
    callActive: false,
    remoteStream: null,       // incoming call media; only played once the call is accepted
    heldTracks: [],           // [sender, track] pairs the caller holds back until accepted
    sharingScreen: false,
    remoteSharingScreen: false,
    callTimerStart: 0,
    callTimerInt: null,
    senders: [],
    videoSender: null,
    // recording
    mediaRecorder: null,
    recordChunks: [],
    recordStart: 0,
    recordTimerInt: null,
    recordCancelled: false,
    // your session profile (broadcast to all peers, wiped on leave)
    myProfile: { name: '', av: null },
    // Cached from /api/turn — needed for relay retry when direct ICE fails.
    iceServers: null,
    iceHasTurn: false,
    iceSource: '',
    forceRelay: false,       // true when no TURN — chat uses encrypted WS relay
    inChat: false,
    pushEnabled: false,
  };
  let joinedWaiters = [];
  let joinOutcomeWaiters = [];

  function newPeer(id) {
    return {
      id,
      pc: null,
      dc: null,
      sessionKey: null,
      safetyNumber: null,
      polite: false,
      makingOffer: false,
      ignoreOffer: false,
      remoteDescSet: false,
      pendingCandidates: [],
      signalChain: Promise.resolve(),
      incomingBlobs: new Map(),
      profile: { name: '', av: null },
      profileSentToThem: false,
      weInitiate: false,
      iceRetried: false,
      useRelay: false,
      online: false,
      typingUntil: 0,
    };
  }

  const REACTIONS = ['❤️', '👍', '😂', '😮', '😢', '🙏'];
  const typingState = { active: false, stopTimer: null, lastSent: 0 };
  const messageReactions = new Map(); // msgId -> Map emoji -> Set(peerId)

  function peerCount() { return state.peers.size; }
  function isGroup() { return state.roomMode === 'group'; }
  function getPeer(id) { return state.peers.get(id); }

  // Send chunks small enough to comfortably fit a DataChannel message
  // (16 KB is a safe cross-browser default).
  const CHUNK_BYTES = 12 * 1024;
  const MAX_FILE_BYTES = 100 * 1024 * 1024; // 100 MB

  // ===========================================================
  // Cryptography
  // ===========================================================
  async function generateKeyPair() {
    return crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']
    );
  }
  async function exportPublicKey(keyPair) {
    return buf2b64(await crypto.subtle.exportKey('raw', keyPair.publicKey));
  }
  async function importPeerPublicKey(b64) {
    return crypto.subtle.importKey(
      'raw', b642buf(b64), { name: 'ECDH', namedCurve: 'P-256' }, true, []
    );
  }
  async function deriveSessionKey(myPrivateKey, peerPublicKey) {
    const sharedBits = await crypto.subtle.deriveBits(
      { name: 'ECDH', public: peerPublicKey }, myPrivateKey, 256
    );
    const ikm = await crypto.subtle.importKey('raw', sharedBits, 'HKDF', false, ['deriveKey']);
    const aesKey = await crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: enc.encode('anon-messenger-v1'), info: enc.encode('chat-session-key') },
      ikm, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    );
    const fp = await crypto.subtle.digest('SHA-256', sharedBits);
    const view = new DataView(fp);
    const groups = [];
    for (let i = 0; i < 6; i++) groups.push((view.getUint16(i * 2) % 10000).toString().padStart(4, '0'));
    return { key: aesKey, safetyNumber: groups.join(' ') };
  }

  // Encryption helpers — explicit key argument. In group mode each peer has
  // its own pairwise AES-GCM key, so we must pass the right one.
  async function encryptBytes(key, bytes) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes);
    return { iv: buf2b64(iv), ct: buf2b64(ct) };
  }
  async function decryptBytes(key, { iv, ct }) {
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b642buf(iv) }, key, b642buf(ct));
    return new Uint8Array(pt);
  }
  async function encryptText(key, plaintext) { return encryptBytes(key, enc.encode(plaintext)); }
  async function decryptText(key, p) { return dec.decode(await decryptBytes(key, p)); }

  // ===========================================================
  // Signaling (WebSocket)
  // ===========================================================
  function wsConnected() {
    return state.ws && state.ws.readyState === WebSocket.OPEN;
  }

  function waitForJoined(ms = 20000) {
    if (joinedReady && state.myId) return Promise.resolve();
    return new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error('join timeout')), ms);
      joinedWaiters.push(() => { clearTimeout(t); resolve(); });
    });
  }

  function resolveJoinedWaiters() {
    const w = joinedWaiters.splice(0);
    w.forEach((fn) => fn());
  }

  function waitForJoinOutcome(ms = 15000) {
    if (joinedReady && state.myId) return Promise.resolve();
    return new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error('Could not join — check your connection and try again.')), ms);
      joinOutcomeWaiters.push({
        resolve: () => { clearTimeout(t); resolve(); },
        reject: (err) => { clearTimeout(t); reject(new Error(err || 'Could not join room')); },
      });
    });
  }

  function resolveJoinOutcome() {
    joinOutcomeWaiters.splice(0).forEach((w) => w.resolve());
  }

  function rejectJoinOutcome(err) {
    joinOutcomeWaiters.splice(0).forEach((w) => w.reject(err));
  }

  function setRoomError(text) {
    const el = $('room-error');
    if (!el) return;
    if (!text) {
      el.textContent = '';
      el.classList.add('hidden');
      return;
    }
    el.textContent = text;
    el.classList.remove('hidden');
  }

  function handleJoinRejected(message) {
    clearTimeout(state._connectTimeout);
    const codeKept = $('room-input')?.value || '';
    const nameKept = $('name-input')?.value || '';
    const modeKept = selectedMode;
    if (state.inChat || state.ws) {
      cleanupAndReturn();
      if (codeKept) $('room-input').value = codeKept;
      if (nameKept) $('name-input').value = nameKept;
      setMode(modeKept);
    }
    setRoomError(message);
    toast(message);
  }

  function handleServerError(msg) {
    const text = msg.error || 'Something went wrong';
    if (!state.myId) {
      rejectJoinOutcome(text);
      return;
    }
    toast(text);
  }

  function connectSignaling() {
    return new Promise((resolve, reject) => {
      const proto = location.protocol === 'https:' ? 'wss' : 'ws';
      const ws = new WebSocket(`${proto}://${location.host}`);
      state.ws = ws;
      ws.onopen = () => resolve(ws);
      ws.onerror = (e) => reject(e);
      ws.onmessage = (ev) => {
        let msg;
        try { msg = JSON.parse(ev.data); } catch { return; }
        enqueueSignal(() => handleSignal(msg));
      };
      ws.onclose = () => {
        state.ws = null;
        setStatus('disconnected', false);
        updateReconnectBanner();
        if (state.inChat && state.room) scheduleWsReconnect();
      };
    });
  }

  function sendSignal(toId, payload) {
    if (!state.myId) {
      console.warn('[signal] dropped — not joined yet');
      return;
    }
    if (state.ws && state.ws.readyState === WebSocket.OPEN) {
      state.ws.send(JSON.stringify({ type: 'signal', to: toId, payload }));
    }
  }

  function sendReconnectRequest(toId, relay) {
    if (state.ws && state.ws.readyState === WebSocket.OPEN) {
      state.ws.send(JSON.stringify({ type: 'reconnect', to: toId, relay: !!relay }));
    }
  }

  async function reconnectPeer(peerId, opts = {}) {
    const old = getPeer(peerId);
    const weInitiate = old ? old.weInitiate : (state.myId < peerId);
    if (old) {
      try { old.dc && old.dc.close(); } catch {}
      try { old.pc && old.pc.close(); } catch {}
      state.peers.delete(peerId);
    }
    return ensurePeerConnection(peerId, weInitiate, opts);
  }

  // Process signaling messages one at a time (SDP/ICE races break WebRTC).
  let signalInbox = Promise.resolve();
  let joinedReady = false;
  const preJoinQueue = [];

  function enqueueSignal(fn) {
    signalInbox = signalInbox.then(fn).catch((e) => console.error('[signal]', e));
    return signalInbox;
  }

  async function handleSignal(msg) {
    if (msg.type === 'error') {
      handleServerError(msg);
      return;
    }
    if (!joinedReady && msg.type !== 'joined') {
      preJoinQueue.push(msg);
      return;
    }
    switch (msg.type) {
      case 'joined': {
        state.myId = msg.you;
        if (!state.myKeyPair) state.myKeyPair = await generateKeyPair();
        const previousMode = state.roomMode;
        if (msg.mode) state.roomMode = msg.mode;
        if (previousMode && previousMode !== state.roomMode) {
          toast(`Room already exists as ${state.roomMode === 'group' ? 'a group' : '1-on-1'} — joining in that mode.`);
        }
        updateModeIndicator();
        const existing = Array.isArray(msg.peers) ? msg.peers : [];
        if (existing.length === 0) {
          showLoading('Room ready', 100);
          setStatus('waiting', false);
        } else {
          showLoading('Establishing peer connection…', 65);
          showSystemMessage(`Connecting to ${existing.length} peer${existing.length>1?'s':''}…`);
          setStatus('connecting…', false);
          await Promise.all(existing.map(async (peerId) => {
            const weInitiate = state.myId < peerId;
            await ensurePeerConnection(peerId, weInitiate);
          }));
        }
        updateHeaderForPeers();
        joinedReady = true;
        resolveJoinedWaiters();
        resolveJoinOutcome();
        updateReconnectBanner();
        const queued = preJoinQueue.splice(0);
        for (const m of queued) await handleSignal(m);
        break;
      }

      case 'peer-joined': {
        if (!msg.id || msg.id === state.myId) return;
        const weInitiate = state.myId < msg.id;
        await ensurePeerConnection(msg.id, weInitiate);
        showSystemMessage('A peer joined the room.');
        updateHeaderForPeers();
        break;
      }

      case 'ready': {
        showLoading('Establishing peer connection…', 65);
        // Mesh sync — (re)connect any missing links (critical for 2-person group).
        const others = Array.isArray(msg.peers) ? msg.peers : [];
        await Promise.all(others.map(async (peerId) => {
          if (peerId === state.myId) return;
          const peer = getPeer(peerId);
          if (peer && (peerTransportReady(peer) || peerLinkBusy(peer))) return;
          const weInitiate = state.myId < peerId;
          await ensurePeerConnection(peerId, weInitiate);
        }));
        break;
      }

      case 'reconnect': {
        const from = msg.from;
        if (!from || from === state.myId) return;
        const opts = msg.relay && state.iceHasTurn ? { iceTransportPolicy: 'relay' } : {};
        showSystemMessage('Reconnecting…');
        await reconnectPeer(from, opts);
        break;
      }

      case 'relay': {
        const from = msg.from;
        const payload = msg.payload;
        if (!from || typeof payload !== 'string') return;
        let peer = getPeer(from);
        if (!peer) {
          const weInitiate = state.myId < from;
          await ensurePeerConnection(from, weInitiate);
          peer = getPeer(from);
        }
        if (!peer || !peer.sessionKey) return;
        if (!peer.useRelay) activateRelayTransport(peer);
        onDcMessage(peer, payload);
        break;
      }

      case 'signal': {
        const from = msg.from;
        const p = msg.payload;
        if (!from || !p) return;
        let peer = getPeer(from);
        if (!peer) {
          const weInitiate = state.myId < from;
          await ensurePeerConnection(from, weInitiate);
          peer = getPeer(from);
          if (!peer) return;
        }
        if (p.kind === 'description') {
          await onRemoteDescription(peer, p.description);
        } else if (p.kind === 'ice') {
          await addRemoteIce(peer, p.candidate);
        } else if (p.kind === 'pubkey') {
          await onPeerPublicKey(peer, p.key);
        }
        break;
      }

      case 'peer-left': {
        const peer = getPeer(msg.id);
        if (!peer) return;
        showSystemMessage(`${peer.profile.name || 'A peer'} left.`);
        try { peer.dc && peer.dc.close(); } catch {}
        try { peer.pc && peer.pc.close(); } catch {}
        // If we were in a 1-on-1 call with this peer, tear it down.
        if (state.callPeerId === msg.id) teardownCall();
        state.peers.delete(msg.id);
        updateHeaderForPeers();
        if (peerCount() === 0) {
          setStatus('alone', false);
          setBanner('Everyone left. Waiting for others to join…', 'info');
          disableComposer();
        }
        updateReconnectBanner();
        break;
      }

    }
  }

  // ===========================================================
  // WebRTC: perfect negotiation pattern
  // ===========================================================
  // STUN-only fallback used if /api/turn is unreachable or returns nothing.
  // Without TURN, peers behind symmetric/strict NATs (corporate Wi-Fi,
  // many mobile carriers) cannot establish a direct P2P connection.
  const ICE_FALLBACK = [
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'stun:stun1.l.google.com:19302' },
    { urls: 'stun:stun2.l.google.com:19302' },
  ];

  function normalizeIceServers(raw) {
    if (!Array.isArray(raw)) return [...ICE_FALLBACK];
    const out = [];
    for (const entry of raw) {
      if (!entry) continue;
      let urls = entry.urls || entry.url;
      if (!urls) continue;
      if (!Array.isArray(urls)) urls = [String(urls)];
      const item = { urls };
      const user = entry.username || entry.user;
      const cred = entry.credential || entry.password;
      if (user) item.username = String(user);
      if (cred) item.credential = String(cred);
      out.push(item);
    }
    return out.length ? out : [...ICE_FALLBACK];
  }

  function iceConfigHasTurn(servers) {
    return servers.some((s) => {
      const u = s.urls;
      const list = Array.isArray(u) ? u : [u];
      return list.some((x) => /^turns?:/i.test(String(x)));
    });
  }

  async function loadIceConfig() {
    if (state.iceServers) return state.iceServers;
    try {
      const res = await fetch('/api/turn?refresh=1', { cache: 'no-store' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = await res.json();
      state.iceServers = normalizeIceServers(body.iceServers);
      state.iceHasTurn = !!body.hasTurn || iceConfigHasTurn(state.iceServers);
      state.iceSource = body.source || 'unknown';
      state.forceRelay = !state.iceHasTurn;
      console.log('[ice] servers:', state.iceServers.length, 'hasTurn:', state.iceHasTurn, 'source:', state.iceSource, 'forceRelay:', state.forceRelay);
      if (!state.iceHasTurn) {
        const hint = body.hint ? ` (${body.hint})` : '';
        setBanner(`No TURN relay${hint} — chat will use encrypted server relay. Calls need TURN.`, 'warning');
        showSystemMessage('Relay mode: messages stay encrypted; server only forwards ciphertext.');
      }
      return state.iceServers;
    } catch (e) {
      console.warn('[ice] fetch failed', e);
      state.iceServers = [...ICE_FALLBACK];
      state.iceHasTurn = false;
      state.iceSource = 'client-fallback';
      state.forceRelay = true;
      setBanner('Could not reach /api/turn — using encrypted server relay for chat.', 'warning');
      return state.iceServers;
    }
  }

  function toIceCandidateInit(obj) {
    if (!obj) return null;
    if (obj instanceof RTCIceCandidate) return obj;
    const init = {
      candidate: obj.candidate,
      sdpMid: obj.sdpMid,
      sdpMLineIndex: obj.sdpMLineIndex,
    };
    if (obj.usernameFragment) init.usernameFragment = obj.usernameFragment;
    return init;
  }

  async function addRemoteIce(peer, candidate) {
    if (!peer.pc) return;
    const init = toIceCandidateInit(candidate);
    if (!init || !init.candidate) return; // end-of-candidates
    if (!peer.remoteDescSet) {
      peer.pendingCandidates.push(init);
      return;
    }
    try {
      await peer.pc.addIceCandidate(init);
    } catch (e) {
      if (!peer.ignoreOffer) console.warn(`[pc:${peer.id}] ICE add failed`, e);
    }
  }

  async function flushPendingIce(peer) {
    if (!peer.pc || !peer.remoteDescSet) return;
    const pending = peer.pendingCandidates.splice(0);
    for (const c of pending) {
      try { await peer.pc.addIceCandidate(c); }
      catch (e) { console.warn(`[pc:${peer.id}] flush ICE failed`, e); }
    }
  }

  async function ensurePeerConnection(peerId, weInitiate, opts = {}) {
    const existing = getPeer(peerId);
    if (existing && existing.pc) {
      const st = existing.pc.connectionState;
      if (st !== 'failed' && st !== 'closed') return existing;
      try { existing.dc && existing.dc.close(); } catch {}
      try { existing.pc.close(); } catch {}
      state.peers.delete(peerId);
    }
    const peer = newPeer(peerId);
    peer.polite = !weInitiate;
    peer.weInitiate = weInitiate;
    state.peers.set(peerId, peer);

    const iceServers = await loadIceConfig();
    const pcConfig = {
      iceServers,
      iceCandidatePoolSize: 10,
      bundlePolicy: 'max-bundle',
    };
    if (opts.iceTransportPolicy === 'relay' && state.iceHasTurn) {
      pcConfig.iceTransportPolicy = 'relay';
      console.log(`[pc:${peerId}] using relay-only ICE policy`);
    }
    peer.pc = new RTCPeerConnection(pcConfig);

    peer.pc.onicecandidate = (e) => {
      if (e.candidate) {
        sendSignal(peerId, { kind: 'ice', candidate: e.candidate.toJSON ? e.candidate.toJSON() : e.candidate });
      } else {
        sendSignal(peerId, { kind: 'ice', candidate: null });
      }
    };
    peer.pc.onicegatheringstatechange = () => {
      console.log(`[pc:${peerId}] iceGatheringState=${peer.pc.iceGatheringState}`);
    };

    peer.pc.onconnectionstatechange = () => {
      const st = peer.pc.connectionState;
      console.log(`[pc:${peerId}] connectionState=${st}`);
      if (st === 'connected') {
        peer.online = true;
        enableChatIfReady();
      } else if (st === 'failed' && !peer.useRelay && !state.forceRelay) {
        peer.online = false;
        setStatus('p2p failed', false);
      } else if (st === 'disconnected') {
        peer.online = false;
        setStatus('reconnecting…', false);
      }
      updateHeaderForPeers();
      updatePresenceUI();
    };
    peer.pc.oniceconnectionstatechange = async () => {
      const iceSt = peer.pc.iceConnectionState;
      console.log(`[pc:${peerId}] iceConnectionState=${iceSt}`);
      if (iceSt === 'failed' && !peer.iceRetried) {
        peer.iceRetried = true;
        if (state.iceHasTurn) {
          toast('Direct connection failed — retrying via TURN…');
          sendReconnectRequest(peerId, true);
          await reconnectPeer(peerId, { iceTransportPolicy: 'relay' });
        }
        if (peer.sessionKey) {
          activateRelayTransport(peer);
        } else {
          toast('Connection failed — waiting for encryption keys…');
        }
      }
    };

    peer.pc.ontrack = (e) => {
      console.log(`[pc:${peerId}] ontrack kind=${e.track.kind}`);
      // In 1-on-1 calls only (current implementation). Group video = future.
      if (peerCount() > 1) return;
      if (!state.remoteStream) state.remoteStream = new MediaStream();
      const ms = state.remoteStream;
      ms.getTracks().filter(t => t.kind === e.track.kind).forEach(t => ms.removeTrack(t));
      ms.addTrack(e.track);
      // Never play the other side while the call is still ringing — only once
      // it has been accepted (see attachRemoteMedia).
      if (state.callActive) attachRemoteMedia();
    };

    peer.pc.onnegotiationneeded = async () => {
      try {
        peer.makingOffer = true;
        console.log(`[pc:${peerId}] negotiationneeded -> creating offer`);
        await peer.pc.setLocalDescription();
        sendSignal(peerId, { kind: 'description', description: peer.pc.localDescription });
      } catch (e) {
        console.error(`[pc:${peerId}] negotiation error`, e);
      } finally {
        peer.makingOffer = false;
      }
    };

    if (weInitiate) {
      const dc = peer.pc.createDataChannel('chat', { ordered: true });
      setupDataChannel(peer, dc);
    } else {
      peer.pc.ondatachannel = (ev) => setupDataChannel(peer, ev.channel);
    }

    if (!state.myKeyPair) state.myKeyPair = await generateKeyPair();
    const pubB64 = await exportPublicKey(state.myKeyPair);
    sendSignal(peerId, { kind: 'pubkey', key: pubB64 });

    return peer;
  }

  async function onRemoteDescription(peer, description) {
    const pc = peer.pc;
    const offerCollision =
      description.type === 'offer' && (peer.makingOffer || pc.signalingState !== 'stable');
    peer.ignoreOffer = !peer.polite && offerCollision;
    console.log(`[pc:${peer.id}] remote ${description.type}, collision=${offerCollision}, ignoring=${peer.ignoreOffer}, state=${pc.signalingState}`);
    if (peer.ignoreOffer) {
      // Impolite side ignored a glare offer — retry once after the polite peer settles.
      setTimeout(async () => {
        if (!peer.pc || peerTransportReady(peer) || peerLinkBusy(peer)) return;
        if (peer.pc.connectionState === 'failed' || peer.pc.connectionState === 'closed') return;
        if (!peer.weInitiate || peer.pc.signalingState !== 'stable') return;
        try {
          peer.makingOffer = true;
          await peer.pc.setLocalDescription();
          sendSignal(peer.id, { kind: 'description', description: peer.pc.localDescription });
        } catch (e) { console.warn(`[pc:${peer.id}] glare retry failed`, e); }
        finally { peer.makingOffer = false; }
      }, 600);
      return;
    }
    if (offerCollision) {
      await Promise.all([
        pc.setLocalDescription({ type: 'rollback' }).catch(() => {}),
        pc.setRemoteDescription(description),
      ]);
    } else {
      await pc.setRemoteDescription(description);
    }
    peer.remoteDescSet = true;
    await flushPendingIce(peer);
    if (description.type === 'offer') {
      await pc.setLocalDescription();
      sendSignal(peer.id, { kind: 'description', description: pc.localDescription });
    }
  }

  function activateRelayTransport(peer) {
    if (peer.useRelay) return;
    peer.useRelay = true;
    console.log(`[relay] active for peer ${peer.id}`);
    peer.online = true;
    setBanner('🔒 Encrypted via server relay (ciphertext only). Configure TURN for direct P2P + calls.', 'ok');
    enableChatIfReady();
    showSystemMessage('Secure channel ready (relay) — you can chat.');
    sendMyProfileTo(peer);
    dcSendTo(peer, { t: 'presence', on: true });
    updatePresenceUI();
  }

  async function onPeerPublicKey(peer, b64) {
    const peerPub = await importPeerPublicKey(b64);
    const { key, safetyNumber } = await deriveSessionKey(state.myKeyPair.privateKey, peerPub);
    peer.sessionKey = key;
    peer.safetyNumber = safetyNumber;
    hideLoading();           // keys verified — fade out loading screen
    updateSecurityBanner();
    if (state.forceRelay) {
      activateRelayTransport(peer);
    } else {
      enableChatIfReady();
    }
    if (peer.dc && peer.dc.readyState === 'open' && !peer.profileSentToThem) {
      sendMyProfileTo(peer);
    } else if (peer.useRelay && !peer.profileSentToThem) {
      sendMyProfileTo(peer);
    }
  }

  function setupDataChannel(peer, dc) {
    peer.dc = dc;
    dc.binaryType = 'arraybuffer';
    dc.bufferedAmountLowThreshold = 64 * 1024;
    dc.onopen = () => {
      console.log(`[dc:${peer.id}] open`);
      peer.online = true;
      showLoading('Performing key exchange…', 80);
      enableChatIfReady();
      showSystemMessage('Secure channel ready — you can chat.');
      sendMyProfileTo(peer);
      dcSendTo(peer, { t: 'presence', on: true });
      updatePresenceUI();
    };
    dc.onclose = () => {
      peer.online = false;
      peer.typingUntil = 0;
      updateHeaderForPeers();
    };
    dc.onmessage = (ev) => onDcMessage(peer, ev.data);
  }

  function updateSecurityBanner() {
    const connectedKeys = Array.from(state.peers.values()).filter(p => p.sessionKey).length;
    const anyRelay = Array.from(state.peers.values()).some(p => p.useRelay);
    const canVerify = connectedKeys > 0;
    if (connectedKeys === 0) {
      setBanner('Verifying secure channel…', 'info', false);
    } else if (anyRelay && !state.iceHasTurn) {
      setBanner('Encrypted relay active. Add TURN for calls.', 'ok', canVerify);
    } else if (connectedKeys === peerCount()) {
      const via = anyRelay ? ' (mixed)' : '';
      setBanner(`Encrypted with ${connectedKeys} peer${connectedKeys>1?'s':''}${via}`, 'ok', canVerify);
    } else {
      setBanner(`${connectedKeys}/${peerCount()} peers encrypted…`, 'info', canVerify);
    }
  }

  async function onDcMessage(peer, data) {
    let msg;
    try { msg = JSON.parse(data); } catch { return; }
    try {
      switch (msg.t) {
        case 'msg': {
          const text = await decryptText(peer.sessionKey, msg.p);
          const reply = msg.rp ? await decodeReplyRef(peer, msg.rp) : null;
          renderMessage({ id: msg.id, kind: 'text', text, from: peer, reply }, 'in');
          notifyIncoming(peer, text.length > 80 ? text.slice(0, 77) + '…' : text);
          return;
        }
        case 'sticker':
          renderMessage({ id: msg.id, kind: 'sticker', sticker: msg.s, from: peer }, 'in');
          notifyIncoming(peer, 'Sticker');
          return;
        case 'audio': {
          const bytes = await decryptBytes(peer.sessionKey, msg.p);
          const blob = new Blob([bytes], { type: msg.mime || 'audio/webm' });
          renderMessage({ id: msg.id, kind: 'audio', audioUrl: URL.createObjectURL(blob), duration: msg.dur, from: peer }, 'in');
          notifyIncoming(peer, 'Voice message');
          return;
        }
        case 'msg-edit': {
          if (typeof msg.id !== 'string') return;
          const el = bubbleById(msg.id);
          // Only the original sender may edit, and only their text messages.
          if (!el || !el.classList.contains('in') || el.classList.contains('deleted')
              || el.dataset.from !== peer.id || el.dataset.kind !== 'text') return;
          const text = await decryptText(peer.sessionKey, msg.p);
          if (!text || text.length > 4000) return;
          applyEdit(el, text);
          return;
        }
        case 'msg-del':
          markMessageDeleted(msg.id);
          messageReactions.delete(msg.id);
          return;
        case 'typing':
          peer.typingUntil = msg.on ? Date.now() + 3500 : 0;
          updatePresenceUI();
          return;
        case 'presence':
          peer.online = !!msg.on;
          if (!msg.on) peer.typingUntil = 0;
          updatePresenceUI();
          return;
        case 'read':
          markOutgoingRead(msg.id);
          return;
        case 'react':
          if (msg.emoji && msg.id) setReaction(msg.id, msg.emoji, peer.id, !!msg.on);
          return;
        case 'blob-meta':
          peer.incomingBlobs.set(msg.id, {
            kind: msg.kind, name: msg.name || '', dur: msg.dur, mime: msg.mime,
            total: msg.total, chunks: [],
          });
          return;
        case 'blob-chunk': {
          const entry = peer.incomingBlobs.get(msg.id);
          if (!entry) return;
          const bytes = await decryptBytes(peer.sessionKey, msg.p);
          entry.chunks[msg.idx] = bytes;
          return;
        }
        case 'blob-end': {
          const entry = peer.incomingBlobs.get(msg.id);
          if (!entry) return;
          peer.incomingBlobs.delete(msg.id);
          if (entry.chunks.length !== entry.total || entry.chunks.some(c => !c)) {
            console.warn('Incomplete blob', msg.id); return;
          }
          let totalLen = 0;
          entry.chunks.forEach(c => totalLen += c.length);
          const merged = new Uint8Array(totalLen);
          let off = 0;
          for (const c of entry.chunks) { merged.set(c, off); off += c.length; }
          const blob = new Blob([merged], { type: entry.mime || 'application/octet-stream' });
          if (entry.kind === 'audio') {
            renderMessage({ id: msg.id, kind: 'audio', audioUrl: URL.createObjectURL(blob), duration: entry.dur, from: peer }, 'in');
            notifyIncoming(peer, 'Voice message');
          } else if (entry.kind === 'file') {
            const url = URL.createObjectURL(blob);
            const mk = mediaKindFromMime(entry.mime, entry.name);
            const bubbleKind = mk === 'image' ? 'image' : (mk === 'video' || mk === 'pdf' ? mk : 'file');
            renderMessage({
              id: msg.id, kind: bubbleKind,
              url, name: entry.name, mime: entry.mime, size: totalLen, from: peer,
              previewKind: mk,
            }, 'in');
            notifyIncoming(peer, entry.name || 'File');
          }
          return;
        }
        case 'profile': {
          try {
            const plain = await decryptText(peer.sessionKey, msg.p);
            const obj = JSON.parse(plain);
            const prevName = peer.profile.name;
            peer.profile = { name: String(obj.name || '').slice(0, 40), av: obj.av || null };
            updateHeaderForPeers();
            // Subtle system message when a peer renames mid-session (excluding
            // the initial profile send which would spam on every join).
            const newName = peer.profile.name;
            if (prevName && newName && prevName !== newName) {
              showSystemMessage(`${prevName} is now ${newName}`);
            }
          } catch (e) { console.warn('Bad profile', e); }
          return;
        }
        // Calls — only meaningful when we're 1-on-1 (peerCount === 1).
        case 'call-invite':
          console.log('[call] received invite', msg.callType, 'from', peer.id);
          if (peerCount() > 1) {
            console.log('[call] ignored: group mode');
            return;
          }
          state.callPeerId = peer.id;
          showIncomingCall(msg.callType);
          return;
        case 'call-accept':
          console.log('[call] received accept from', peer.id, 'expected', state.callPeerId);
          if (peer.id !== state.callPeerId) return;
          onCallAccepted();
          return;
        case 'call-decline':
          console.log('[call] received decline from', peer.id);
          if (peer.id !== state.callPeerId) return;
          onCallDeclined();
          return;
        case 'call-end': {
          console.log('[call] received call-end from', peer.id);
          if (peer.id !== state.callPeerId) return;
          const wasActive = state.callActive;
          teardownCall();
          if (wasActive) showSystemMessage('Call ended.');
          return;
        }
        case 'call-screen':
          if (peer.id !== state.callPeerId) return;
          state.remoteSharingScreen = !!msg.on;
          updateCallVideoLayout();
          if (msg.on) {
            $('call-status').textContent = 'Viewing screen share';
            toast('Peer is sharing their screen');
          } else if (state.callActive) {
            $('call-status').textContent = 'Connected';
          }
          return;
      }
    } catch (e) { console.warn('DC handler error', e); }
  }

  function peerTransportReady(p) {
    return p.sessionKey && (
      (p.dc && p.dc.readyState === 'open') || p.useRelay
    );
  }

  function peerLinkBusy(p) {
    if (!p || !p.pc) return false;
    const st = p.pc.connectionState;
    if (st === 'failed' || st === 'closed') return false;
    if (peerTransportReady(p)) return false;
    return true;
  }

  function anyPeerReady() {
    for (const p of state.peers.values()) if (peerTransportReady(p)) return true;
    return false;
  }

  function enableChatIfReady() {
    const ready = anyPeerReady();
    const composerIds = ['msg-input','send-btn','sticker-btn','attach-btn','mic-btn'];
    composerIds.forEach(id => { const el = $(id); if (el) el.disabled = !ready; });
    const hasRelayOnly = Array.from(state.peers.values()).some(p => p.useRelay && !(p.dc && p.dc.readyState === 'open'));
    const callable = ready && state.roomMode === '1on1' && peerCount() === 1 && !hasRelayOnly;
    const audio = $('audio-call-btn'); if (audio) audio.disabled = !callable;
    const video = $('video-call-btn'); if (video) video.disabled = !callable;
    // In group mode, give the call buttons a helpful tooltip explaining they're off.
    if (state.roomMode === 'group') {
      if (audio) audio.title = 'Group calls are not available yet';
      if (video) video.title = 'Group calls are not available yet';
    } else {
      if (audio) audio.title = 'Audio call';
      if (video) video.title = 'Video call';
    }
    if (ready) {
      $('msg-input').focus();
      updatePresenceUI();
      updateSecurityBanner();
    }
    updateReconnectBanner();
  }

  function needsReconnect() {
    if (!state.inChat || !state.room || state._reconnecting) return false;
    if (!wsConnected()) return true;
    return peerCount() > 0 && !anyPeerReady();
  }

  function updateReconnectBanner() {
    const banner = $('reconnect-banner');
    if (!banner) return;
    const show = needsReconnect() && !state._reconnecting;
    banner.classList.toggle('hidden', !show);
    const txt = $('reconnect-banner-text');
    if (txt) {
      if (!wsConnected()) txt.textContent = 'Connection lost';
      else txt.textContent = 'Chat disconnected';
    }
  }

  async function reconnectSession() {
    if (!state.room || state._reconnecting) return;
    state._reconnecting = true;
    updateReconnectBanner();
    showSystemMessage('Reconnecting…');
    try {
      for (const peer of state.peers.values()) {
        try { peer.dc && peer.dc.close(); } catch {}
        try { peer.pc && peer.pc.close(); } catch {}
      }
      state.peers.clear();
      joinedReady = false;
      preJoinQueue.length = 0;
      signalInbox = Promise.resolve();

      if (!wsConnected()) {
        try { state.ws && state.ws.close(); } catch {}
        await connectSignaling();
      } else {
        try { state.ws.send(JSON.stringify({ type: 'leave' })); } catch {}
      }
      if (!state.myKeyPair) state.myKeyPair = await generateKeyPair();
      state.ws.send(JSON.stringify({
        type: 'join', room: state.room, mode: state.roomMode,
      }));
      await waitForJoined();
      await loadIceConfig();
      toast('Reconnected');
      cancelWsRetry();          // clear auto-retry once we're back
      showSystemMessage('Back online — you can chat again.');
      await initPushSubscription();
    } catch (e) {
      console.warn('[reconnect]', e);
      toast('Reconnect failed — retrying…');
    } finally {
      state._reconnecting = false;
      updateReconnectBanner();
    }
  }
  function disableComposer() {
    ['msg-input','send-btn','sticker-btn','attach-btn','mic-btn','audio-call-btn','video-call-btn']
      .forEach(id => { const el = $(id); if (el) el.disabled = true; });
  }

  // Send to a SPECIFIC peer's data channel (JSON).
  function relaySendTo(peerId, json) {
    if (!state.ws || state.ws.readyState !== WebSocket.OPEN) return false;
    if (json.length > 480 * 1024) {
      toast('Message too large for relay mode');
      return false;
    }
    state.ws.send(JSON.stringify({ type: 'relay', to: peerId, payload: json }));
    return true;
  }

  function dcSendTo(peer, obj) {
    const json = JSON.stringify(obj);
    if (peer.dc && peer.dc.readyState === 'open') {
      peer.dc.send(json);
      return true;
    }
    if (peer.useRelay) return relaySendTo(peer.id, json);
    return false;
  }

  // Send the same payload to every peer with an open DC, encrypting per-peer
  // for `p` fields (caller already produced peer-specific ciphertext).
  // For simple non-encrypted broadcasts, use this.
  function dcBroadcastPlain(obj) {
    let sent = 0;
    for (const peer of state.peers.values()) {
      if (dcSendTo(peer, obj)) sent++;
    }
    if (sent > 0 && obj.t && obj.t !== 'typing' && obj.t !== 'presence' && obj.t !== 'read') {
      sendPushNudge();
    }
    return sent;
  }

  // Encrypt the same plaintext separately for each peer (pairwise keys),
  // then send the corresponding ciphertext to each peer.
  // Returns the number of peers we delivered to.
  // `extra` maps field name -> plaintext string; each is encrypted per peer too.
  async function dcBroadcastEncryptedText(plaintext, baseMessage, extra = null) {
    let sent = 0;
    for (const peer of state.peers.values()) {
      if (!peerTransportReady(peer)) continue;
      const out = { ...baseMessage, p: await encryptText(peer.sessionKey, plaintext) };
      if (extra) {
        for (const [k, v] of Object.entries(extra)) out[k] = await encryptText(peer.sessionKey, v);
      }
      if (dcSendTo(peer, out)) sent++;
    }
    if (sent > 0 && baseMessage.t && !['typing', 'presence', 'read', 'msg-edit'].includes(baseMessage.t)) {
      sendPushNudge();
    }
    return sent;
  }

  // Send large bytes as encrypted chunks — to ALL connected peers.
  async function dcBroadcastBlob(kind, bytes, meta = {}, onProgress = null) {
    const id = randId();
    const total = Math.ceil(bytes.length / CHUNK_BYTES);
    dcBroadcastPlain({ t: 'blob-meta', id, kind, total, ...meta });
    for (let i = 0; i < total; i++) {
      const chunk = bytes.subarray(i * CHUNK_BYTES, (i + 1) * CHUNK_BYTES);
      // Encrypt once per peer (different keys), then send to each.
      for (const peer of state.peers.values()) {
        if (!peerTransportReady(peer)) continue;
        if (peer.dc && peer.dc.readyState === 'open') {
          while (peer.dc.bufferedAmount > 4 * 1024 * 1024) {
            await new Promise(r => setTimeout(r, 50));
          }
        }
        const p = await encryptBytes(peer.sessionKey, chunk);
        dcSendTo(peer, { t: 'blob-chunk', id, idx: i, p });
      }
      if (onProgress) onProgress((i + 1) / total);
    }
    dcBroadcastPlain({ t: 'blob-end', id });
    return id;
  }

  function formatBytes(n) {
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
    return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
  }

  function mediaKindFromMime(mime, name) {
    const m = (mime || '').toLowerCase();
    const ext = (name || '').split('.').pop().toLowerCase();
    if (m.startsWith('image/')) return 'image';
    if (m.startsWith('video/')) return 'video';
    if (m === 'application/pdf' || ext === 'pdf') return 'pdf';
    if (m.startsWith('audio/')) return 'audio';
    return 'file';
  }

  function fileTypeLabel(mime, name) {
    const k = mediaKindFromMime(mime, name);
    if (k === 'pdf') return 'PDF';
    if (k === 'video') return 'Video';
    if (k === 'audio') return 'Audio';
    const ext = (name || '').split('.').pop();
    return ext ? ext.toUpperCase() : 'File';
  }

  function sendPushNudge() {
    if (!wsConnected() || !state.pushEnabled) return;
    for (const peer of state.peers.values()) {
      state.ws.send(JSON.stringify({ type: 'nudge', to: peer.id }));
    }
  }

  function urlBase64ToUint8Array(base64) {
    const pad = '='.repeat((4 - (base64.length % 4)) % 4);
    const b64 = (base64 + pad).replace(/-/g, '+').replace(/_/g, '/');
    const raw = atob(b64);
    const out = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; ++i) out[i] = raw.charCodeAt(i);
    return out;
  }

  async function initPushSubscription() {
    if (!('serviceWorker' in navigator) || !('PushManager' in window)) return;
    if (Notification.permission === 'denied') return;
    try {
      const reg = await navigator.serviceWorker.register('/sw.js');
      const res = await fetch('/api/push-vapid');
      const { publicKey, enabled } = await res.json();
      if (!enabled || !publicKey) return;
      let sub = await reg.pushManager.getSubscription();
      if (!sub) {
        if (Notification.permission === 'default') return;
        sub = await reg.pushManager.subscribe({
          userVisibleOnly: true,
          applicationServerKey: urlBase64ToUint8Array(publicKey),
        });
      }
      if (wsConnected()) {
        state.ws.send(JSON.stringify({ type: 'push-sub', subscription: sub.toJSON() }));
        state.pushEnabled = true;
      }
    } catch (e) {
      console.warn('[push] subscribe failed', e);
    }
  }

  async function enableNotifications() {
    if (!('Notification' in window)) {
      toast('Notifications not supported on this browser');
      return;
    }
    const perm = await Notification.requestPermission();
    if (perm !== 'granted') {
      toast('Notifications blocked');
      return;
    }
    await initPushSubscription();
    toast('Notifications on');
    const btn = $('notify-btn');
    if (btn) btn.classList.add('active');
  }

  function notifyIncoming(peer, summary) {
    const name = (peer && peer.profile && peer.profile.name || '').trim() || 'Someone';
    if (document.hidden && Notification.permission === 'granted') {
      try {
        const n = new Notification(name, {
          body: summary,
          icon: '/icon-192.svg',
          tag: state.room ? `room-${state.room}` : 'anon',
        });
        n.onclick = () => { window.focus(); n.close(); };
      } catch { /* ignore */ }
    }
  }

  function openFilePreview(m) {
    const overlay = $('preview-overlay');
    const body = $('preview-body');
    const nameEl = $('preview-name');
    const dl = $('preview-download');
    if (!overlay || !body) return;
    nameEl.textContent = m.name || 'File';
    dl.href = m.url;
    dl.download = m.name || 'download';
    body.innerHTML = '';
    const kind = m.previewKind || mediaKindFromMime(m.mime, m.name);
    if (kind === 'image') {
      const img = document.createElement('img');
      img.src = m.url;
      img.alt = m.name || 'image';
      body.appendChild(img);
    } else if (kind === 'video') {
      const v = document.createElement('video');
      v.src = m.url;
      v.controls = true;
      v.playsInline = true;
      v.autoplay = true;
      body.appendChild(v);
    } else if (kind === 'pdf') {
      const iframe = document.createElement('iframe');
      iframe.src = m.url;
      iframe.title = m.name || 'PDF';
      body.appendChild(iframe);
    } else {
      const box = document.createElement('div');
      box.className = 'preview-generic';
      box.innerHTML = `
        <div class="preview-generic-icon">${escapeHtml(fileTypeLabel(m.mime, m.name))}</div>
        <div class="preview-generic-name">${escapeHtml(m.name || 'File')}</div>
        <div class="preview-generic-size">${formatBytes(m.size || 0)}</div>`;
      body.appendChild(box);
    }
    overlay.classList.remove('hidden');
  }

  function closeFilePreview() {
    const overlay = $('preview-overlay');
    const body = $('preview-body');
    if (!overlay) return;
    overlay.classList.add('hidden');
    if (body) {
      body.querySelectorAll('video').forEach(v => { try { v.pause(); } catch {} });
      body.innerHTML = '';
    }
  }

  function wireFilePreview(el, m) {
    const open = () => openFilePreview(m);
    el.querySelectorAll('.media-preview, .file-row, img').forEach(node => {
      node.addEventListener('click', (e) => {
        if (e.target.closest('a.file-dl')) return;
        e.preventDefault();
        open();
      });
    });
    const row = el.querySelector('.file-row');
    if (row) row.style.cursor = 'pointer';
  }

  async function sendFiles(fileList) {
    if (!anyPeerReady()) { toast('Not connected yet'); return; }
    for (const file of fileList) {
      if (file.size > MAX_FILE_BYTES) {
        toast(`"${file.name}" exceeds ${formatBytes(MAX_FILE_BYTES)} limit`);
        continue;
      }
      const bytes = new Uint8Array(await file.arrayBuffer());
      // Local placeholder bubble with progress
      const placeholderId = randId();
      renderMessage({
        id: placeholderId, kind: 'file-uploading',
        name: file.name, size: file.size,
      }, 'out');
      const placeholder = document.querySelector(`.bubble[data-upload-id="${CSS.escape(placeholderId)}"]`);
      const progressEl = placeholder ? placeholder.querySelector('.file-progress') : null;
      try {
        await dcBroadcastBlob('file', bytes, { name: file.name, mime: file.type || 'application/octet-stream' },
          (frac) => { if (progressEl) progressEl.style.setProperty('--p', Math.round(frac * 100) + '%'); });
        // Replace the placeholder with the final bubble
        if (placeholder) {
          const url = URL.createObjectURL(new Blob([bytes], { type: file.type || 'application/octet-stream' }));
          placeholder.remove();
          const kind = mediaKindFromMime(file.type, file.name);
          const bubbleKind = kind === 'image' ? 'image' : (kind === 'video' || kind === 'pdf' ? kind : 'file');
          renderMessage({
            id: placeholderId, kind: bubbleKind,
            url, name: file.name, mime: file.type, size: file.size,
            previewKind: kind,
          }, 'out');
        }
      } catch (e) {
        console.error('File send failed', e);
        toast('File send failed');
        if (placeholder) placeholder.remove();
      }
    }
  }

  // ===========================================================
  // Session profile (name + avatar — wiped on leave, never persisted)
  // ===========================================================
  async function sendMyProfile() {
    const payload = JSON.stringify({
      name: state.myProfile.name || '',
      av: state.myProfile.av || null,
    });
    try {
      const sent = await dcBroadcastEncryptedText(payload, { t: 'profile' });
      for (const peer of state.peers.values()) {
        if (peerTransportReady(peer)) peer.profileSentToThem = true;
      }
      return sent;
    } catch (e) { console.warn('profile broadcast failed', e); }
  }

  async function sendMyProfileTo(peer) {
    if (!peer.sessionKey) return;
    if (!peer.useRelay && (!peer.dc || peer.dc.readyState !== 'open')) return;
    try {
      const payload = JSON.stringify({
        name: state.myProfile.name || '',
        av: state.myProfile.av || null,
      });
      const p = await encryptText(peer.sessionKey, payload);
      dcSendTo(peer, { t: 'profile', p });
      peer.profileSentToThem = true;
    } catch (e) { console.warn('profile send to peer failed', e); }
  }

  // Update the chat header to reflect current peers.
  // - 0 peers: "Waiting for peer"
  // - 1 peer (1-on-1): show that peer's avatar + name
  // - 2+ peers (group): show stack of avatars + "Group · N peers"
  function updateHeaderForPeers() {
    updateWaitingCard();
    const nameEl = document.querySelector('.peer-name');
    const avEl = $('peer-avatar');
    const statusEl = $('peer-status');
    const count = peerCount();

    if (count === 0) {
      if (nameEl) nameEl.textContent = 'Waiting for peers…';
      if (avEl) {
        avEl.style.backgroundImage = '';
        avEl.textContent = '?';
      }
      return;
    }

    if (count === 1) {
      const peer = state.peers.values().next().value;
      const displayName = (peer.profile.name && peer.profile.name.trim())
        ? peer.profile.name.trim() : 'Anonymous peer';
      if (nameEl) {
        nameEl.textContent = state.roomMode === 'group'
          ? `Group · ${displayName}`
          : displayName;
      }
      if (avEl) {
        if (state.roomMode === 'group') {
          avEl.style.backgroundImage = '';
          avEl.textContent = '2';
        } else if (peer.profile.av) {
          avEl.style.backgroundImage = `url(${peer.profile.av})`;
          avEl.style.backgroundSize = 'cover';
          avEl.style.backgroundPosition = 'center';
          avEl.textContent = '';
        } else {
          avEl.style.backgroundImage = '';
          avEl.textContent = (displayName[0] || '?').toUpperCase();
        }
      }
      updatePresenceUI();
      return;
    }

    // Group mode
    const names = Array.from(state.peers.values())
      .map(p => p.profile.name?.trim() || 'Anonymous')
      .slice(0, 3);
    const more = count > 3 ? `, +${count - 3} more` : '';
    if (nameEl) nameEl.textContent = `Group · ${names.join(', ')}${more}`;
    if (statusEl && statusEl.textContent !== 'online') {
      // status managed by call/connection state, not name
    }
    if (avEl) {
      avEl.style.backgroundImage = '';
      avEl.textContent = String(count + 1); // including you
    }
    updatePresenceUI();
  }

  // Update the profile button to visually represent YOU (your name/avatar).
  // Gives clear self-feedback when you save profile changes.
  function applyMyProfile() {
    const btn = $('profile-btn');
    if (!btn) return;
    const name = (state.myProfile.name || '').trim();
    const av = state.myProfile.av;
    const label = name ? `You: ${name} (tap to edit)` : 'Set your name & avatar (temporary)';
    btn.setAttribute('title', label);
    btn.setAttribute('aria-label', label);
    if (av) {
      btn.style.backgroundImage = `url(${av})`;
      btn.style.backgroundSize = 'cover';
      btn.style.backgroundPosition = 'center';
      btn.innerHTML = '';
      btn.classList.add('has-profile');
    } else if (name) {
      btn.style.backgroundImage = '';
      btn.innerHTML = `<span class="profile-initial">${escapeHtml(name[0].toUpperCase())}</span>`;
      btn.classList.add('has-profile');
    } else {
      btn.style.backgroundImage = '';
      btn.innerHTML = '<svg viewBox="0 0 24 24" width="32" height="32"><path fill="currentColor" d="M12 12a4 4 0 1 0-4-4 4 4 0 0 0 4 4zm0 2c-3.3 0-10 1.7-10 5v3h20v-3c0-3.3-6.7-5-10-5z"/></svg>';
      btn.classList.remove('has-profile');
    }
  }

  // Resize an image File/Blob to <= side x side JPEG. Returns dataURL.
  async function resizeImageFile(file, side = 128, quality = 0.82) {
    const url = URL.createObjectURL(file);
    try {
      const img = await new Promise((resolve, reject) => {
        const i = new Image();
        i.onload = () => resolve(i);
        i.onerror = reject;
        i.src = url;
      });
      const ratio = Math.min(side / img.width, side / img.height, 1);
      const w = Math.max(1, Math.round(img.width * ratio));
      const h = Math.max(1, Math.round(img.height * ratio));
      const canvas = document.createElement('canvas');
      canvas.width = w; canvas.height = h;
      canvas.getContext('2d').drawImage(img, 0, 0, w, h);
      return canvas.toDataURL('image/jpeg', quality);
    } finally {
      URL.revokeObjectURL(url);
    }
  }

  function openProfileDialog() {
    $('profile-name').value = state.myProfile.name || '';
    const preview = $('profile-preview');
    if (state.myProfile.av) {
      preview.style.backgroundImage = `url(${state.myProfile.av})`;
      preview.textContent = '';
    } else {
      preview.style.backgroundImage = '';
      preview.textContent = (state.myProfile.name?.[0] || '?').toUpperCase();
    }
    $('profile-dialog').classList.remove('hidden');
  }
  function closeProfileDialog() { $('profile-dialog').classList.add('hidden'); }

  // ===========================================================
  // Colour themes — only the theme name is kept (localStorage), nothing else
  // ===========================================================
  const THEMES = [
    { id: 'neon',   name: 'Neon',   colors: ['#8B5CFF', '#FF4FA3', '#FF9147'], ink: '#0A0614' },
    { id: 'ocean',  name: 'Ocean',  colors: ['#4A7BFF', '#1FC8FF', '#3DFFC8'], ink: '#050B18' },
    { id: 'sunset', name: 'Sunset', colors: ['#FF4D6D', '#FF8A3D', '#FFD23F'], ink: '#140709' },
    { id: 'toxic',  name: 'Toxic',  colors: ['#1FD67A', '#9BFF3D', '#E9FF5C'], ink: '#050F0A' },
    { id: 'candy',  name: 'Candy',  colors: ['#FF6AD5', '#C774E8', '#94D0FF'], ink: '#110A18' },
    { id: 'ghost',  name: 'Ghost',  colors: ['#FFFFFF', '#C9C9D6', '#8E8EA3'], ink: '#09090C' },
  ];

  function applyTheme(id, save = true) {
    const t = THEMES.find(x => x.id === id) || THEMES[0];
    if (t.id === 'neon') delete document.documentElement.dataset.theme;
    else document.documentElement.dataset.theme = t.id;
    document.querySelector('meta[name="theme-color"]')?.setAttribute('content', t.ink);
    document.querySelectorAll('.theme-swatch').forEach(b => {
      const on = b.dataset.theme === t.id;
      b.classList.toggle('active', on);
      b.setAttribute('aria-checked', String(on));
      b.tabIndex = on ? 0 : -1;
    });
    document.querySelectorAll('.theme-name').forEach(el => { el.textContent = t.name; });
    if (save) { try { localStorage.setItem('anon-theme', t.id); } catch { /* private mode */ } }
  }

  function buildThemePickers() {
    document.querySelectorAll('.theme-picker').forEach(box => {
      box.innerHTML = '';
      THEMES.forEach((t, i) => {
        const b = document.createElement('button');
        b.type = 'button';
        b.className = 'theme-swatch';
        b.dataset.theme = t.id;
        b.title = t.name;
        b.setAttribute('role', 'radio');
        b.setAttribute('aria-label', `${t.name} theme`);
        b.style.setProperty('--sw', `linear-gradient(135deg, ${t.colors.join(', ')})`);
        b.style.setProperty('--sw-ink', t.ink);
        b.addEventListener('click', () => applyTheme(t.id));
        // Arrow keys move between swatches, like a native radio group
        b.addEventListener('keydown', (e) => {
          const step = { ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1 }[e.key];
          if (!step) return;
          e.preventDefault();
          const next = THEMES[(i + step + THEMES.length) % THEMES.length];
          applyTheme(next.id);
          box.querySelector(`[data-theme="${next.id}"]`)?.focus();
        });
        box.appendChild(b);
      });
    });
    let saved = null;
    try { saved = localStorage.getItem('anon-theme'); } catch { /* private mode */ }
    applyTheme(saved || 'neon', false);
  }
  buildThemePickers();

  // ===========================================================
  // UI rendering
  // ===========================================================
  function showScreen(id) {
    document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
    $(id).classList.add('active');
  }
  function setStatus(text, online) {
    const el = $('peer-status');
    if (!el) return;
    el.textContent = text;
    el.classList.toggle('online', !!online);
    el.classList.toggle('typing', /typing/i.test(text));
  }

  function peerAppearsOnline(p) {
    return p.online || peerTransportReady(p);
  }

  function updatePresenceUI() {
    const now = Date.now();
    const typingPeers = [];
    let onlineCount = 0;
    for (const p of state.peers.values()) {
      if (p.typingUntil > now) typingPeers.push(p);
      else if (peerAppearsOnline(p)) onlineCount++;
    }
    updateTypingBubble(typingPeers);
    if (peerCount() === 0) {
      setStatus('waiting', false);
      return;
    }
    if (typingPeers.length > 0) {
      if (peerCount() === 1) {
        const name = (typingPeers[0].profile.name || '').trim() || 'Peer';
        setStatus(`${name} is typing…`, true);
      } else {
        setStatus(`${typingPeers.length} typing…`, true);
      }
      return;
    }
    if (peerCount() === 1) {
      const p = state.peers.values().next().value;
      const on = peerAppearsOnline(p);
      setStatus(on ? 'online' : 'offline', on);
      return;
    }
    setStatus(`${onlineCount}/${peerCount()} online`, onlineCount > 0);
  }

  function broadcastPresence(online) {
    dcBroadcastPlain({ t: 'presence', on: !!online });
    for (const p of state.peers.values()) p.online = !!online;
    updatePresenceUI();
  }
  // Broadcast online/away when the user hides or shows the tab
  document.addEventListener('visibilitychange', () => {
    if (state.inChat) broadcastPresence(!document.hidden);
  });

  function sendTyping(on) {
    const now = Date.now();
    if (on) {
      if (typingState.active && now - typingState.lastSent < 400) return;
      typingState.active = true;
      typingState.lastSent = now;
      dcBroadcastPlain({ t: 'typing', on: true });
    } else {
      if (!typingState.active) return;
      typingState.active = false;
      typingState.lastSent = now;
      dcBroadcastPlain({ t: 'typing', on: false });
    }
  }

  function scheduleTypingStop() {
    clearTimeout(typingState.stopTimer);
    typingState.stopTimer = setTimeout(() => sendTyping(false), 2000);
  }

  function sendReadReceipt(msgId) {
    if (!msgId) return;
    dcBroadcastPlain({ t: 'read', id: msgId });
  }

  function markOutgoingRead(msgId) {
    const el = document.querySelector(`.bubble.out[data-id="${CSS.escape(msgId)}"]`);
    if (!el || el.classList.contains('deleted')) return;
    const ticks = el.querySelector('.read-ticks');
    if (ticks) {
      ticks.textContent = '✓✓';
      ticks.classList.add('read');
      ticks.title = 'Read';
    }
  }

  function getReactionsMap(msgId) {
    if (!messageReactions.has(msgId)) messageReactions.set(msgId, new Map());
    return messageReactions.get(msgId);
  }

  function setReaction(msgId, emoji, peerId, add) {
    const map = getReactionsMap(msgId);
    if (!map.has(emoji)) map.set(emoji, new Set());
    const set = map.get(emoji);
    if (add) set.add(peerId); else set.delete(peerId);
    if (set.size === 0) map.delete(emoji);
    if (map.size === 0) messageReactions.delete(msgId);
    refreshReactionsUI(msgId);
  }

  function refreshReactionsUI(msgId) {
    const el = document.querySelector(`.bubble[data-id="${CSS.escape(msgId)}"]`);
    if (!el || el.classList.contains('deleted')) return;
    let bar = el.querySelector('.reactions-bar');
    const map = messageReactions.get(msgId);
    if (!map || map.size === 0) {
      if (bar) bar.remove();
      return;
    }
    if (!bar) {
      bar = document.createElement('div');
      bar.className = 'reactions-bar';
      el.appendChild(bar);
    }
    bar.innerHTML = '';
    for (const [emoji, peers] of map) {
      if (!peers.size) continue;
      const chip = document.createElement('button');
      chip.type = 'button';
      chip.className = 'reaction-chip';
      chip.textContent = `${emoji} ${peers.size > 1 && isGroup() ? peers.size : ''}`.trim();
      chip.title = 'Toggle reaction';
      chip.addEventListener('click', () => toggleReaction(msgId, emoji));
      bar.appendChild(chip);
    }
  }

  function toggleReaction(msgId, emoji) {
    const map = getReactionsMap(msgId);
    const mine = map.get(emoji)?.has(state.myId);
    const add = !mine;
    setReaction(msgId, emoji, state.myId, add);
    dcBroadcastPlain({ t: 'react', id: msgId, emoji, on: add });
  }

  function queueReadReceipt(msgId) {
    if (!msgId || document.hidden) return;
    sendReadReceipt(msgId);
  }
  function setBanner(text, kind = 'info', canVerify = false) {
    const b = $('security-banner');
    b.classList.remove('warning', 'info');
    if (kind === 'warning') b.classList.add('warning');
    else if (kind === 'info') b.classList.add('info');
    const verifyBtn = canVerify
      ? `<button type="button" class="verify-btn" id="verify-btn">Verify</button>`
      : '';
    b.innerHTML = `<span class="lock">🔒</span><span>${escapeHtml(text)}</span>${verifyBtn}`;
    if (canVerify) {
      $('verify-btn')?.addEventListener('click', (e) => { e.stopPropagation(); openSafetyDialog(); });
    }
  }
  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => ({
      '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
    }[c]));
  }
  function linkify(s) {
    return s.replace(/(https?:\/\/[^\s<]+)/g,
      '<a href="$1" class="msg-link" target="_blank" rel="noopener noreferrer">$1</a>');
  }

  // Basic markdown applied AFTER escapeHtml — only safe tags produced
  function markdownify(s) {
    return s
      .replace(/```([\s\S]*?)```/g, '<pre><code>$1</code></pre>')   // fenced code blocks
      .replace(/`([^`]+)`/g, '<code>$1</code>')                      // inline code
      .replace(/\*\*(.+?)\*\*/gs, '<strong>$1</strong>')             // **bold**
      .replace(/\*([^*\n]+)\*/g, '<em>$1</em>')                      // *italic*
      .replace(/~~(.+?)~~/gs, '<s>$1</s>');                          // ~~strikethrough~~
  }

  // Stable per-name hue so each group member gets their own colour.
  function senderHue(name) {
    let h = 0;
    for (const ch of name) h = (h * 31 + ch.codePointAt(0)) >>> 0;
    return h % 360;
  }

  function bubbleMetaHtml(direction) {
    const time = `<span class="time">${nowTime()}</span>`;
    if (direction === 'out') {
      return `<span class="bubble-meta"><span class="read-ticks" title="Sent">✓</span>${time}</span>`;
    }
    return time;
  }

  // Render a message bubble. `m` = { id, kind, text?, sticker?, audioUrl?, duration? }
  function renderMessage(m, direction) {
    const wrap = $('messages');
    const div = document.createElement('div');
    div.className = `bubble ${direction}`;
    div.dataset.id = m.id;
    div.dataset.kind = m.kind;
    if (direction === 'in' && m.from) {
      div.dataset.from = m.from.id;
      div.dataset.fromName = (m.from.profile.name || '').trim();
    }
    if (m.name) div.dataset.name = m.name;
    // Sender label for group-mode incoming messages.
    let senderHeader = '';
    if (direction === 'in' && isGroup() && peerCount() >= 1 && m.from) {
      const name = (m.from.profile.name || '').trim() || 'Anonymous';
      senderHeader = `<div class="sender" style="--h:${senderHue(name)}">${escapeHtml(name)}</div>`;
    }
    if (m.kind === 'text') {
      div.dataset.text = m.text;
      div.innerHTML = `${senderHeader}${quoteHtml(m.reply)}<span class="msg-text">${linkify(markdownify(escapeHtml(m.text)))}</span>${bubbleMetaHtml(direction)}`;
    } else if (m.kind === 'video') {
      div.classList.add('video', 'image');
      div.innerHTML = `
        ${senderHeader}
        <div class="media-preview" role="button" tabindex="0" aria-label="Open video">
          <video src="${m.url}" muted playsinline preload="metadata"></video>
          <span class="media-play-badge" aria-hidden="true">▶</span>
        </div>
        ${bubbleMetaHtml(direction)}`;
      wireFilePreview(div, { ...m, previewKind: 'video' });
    } else if (m.kind === 'pdf') {
      div.classList.add('pdf', 'file');
      div.innerHTML = `
        ${senderHeader}
        <div class="file-row media-preview" role="button" tabindex="0">
          <div class="file-icon pdf-icon">PDF</div>
          <div class="file-meta">
            <div class="file-name">${escapeHtml(m.name || 'Document.pdf')}</div>
            <div class="file-size">${formatBytes(m.size || 0)} · Tap to preview</div>
          </div>
        </div>
        ${bubbleMetaHtml(direction)}`;
      wireFilePreview(div, { ...m, previewKind: 'pdf' });
    } else if (m.kind === 'sticker') {
      div.classList.add('sticker');
      div.dataset.sticker = m.sticker;
      div.innerHTML = `${senderHeader}<div class="sticker-emoji">${escapeHtml(m.sticker)}</div>${bubbleMetaHtml(direction)}`;
    } else if (m.kind === 'audio') {
      div.classList.add('audio');
      const waveBars = Array.from({ length: 22 }, () => '<span></span>').join('');
      div.innerHTML = `
        ${senderHeader}
        <div class="audio-row">
          <button class="audio-play" type="button" aria-label="Play">
            <svg viewBox="0 0 24 24" width="18" height="18"><path fill="currentColor" d="M8 5v14l11-7z"/></svg>
          </button>
          <div class="audio-info">
            <div class="audio-waves">${waveBars}</div>
            <div class="audio-duration">${formatDuration(m.duration || 0)}</div>
          </div>
          ${bubbleMetaHtml(direction)}
        </div>`;
      wireAudioBubble(div, m.audioUrl, m.duration);
    } else if (m.kind === 'image') {
      div.classList.add('image');
      div.innerHTML = `
        ${senderHeader}
        <div class="media-preview" role="button" tabindex="0" aria-label="Open image">
          <img src="${m.url}" alt="${escapeHtml(m.name || 'image')}" loading="lazy" />
        </div>
        ${bubbleMetaHtml(direction)}`;
      wireFilePreview(div, { ...m, previewKind: 'image' });
    } else if (m.kind === 'file') {
      div.classList.add('file');
      const label = fileTypeLabel(m.mime, m.name);
      div.innerHTML = `
        ${senderHeader}
        <div class="file-row">
          <div class="file-icon file-type-badge">${escapeHtml(label.slice(0, 4))}</div>
          <div class="file-meta">
            <div class="file-name">${escapeHtml(m.name || 'file')}</div>
            <div class="file-size">${formatBytes(m.size || 0)}</div>
          </div>
          <a class="file-dl" href="${m.url}" download="${escapeHtml(m.name || 'file')}" title="Download">
            <svg viewBox="0 0 24 24" width="22" height="22"><path fill="currentColor" d="M12 3v12l4-4 1.4 1.4L12 17.8 6.6 12.4 8 11l4 4V3zM5 19h14v2H5z"/></svg>
          </a>
        </div>`;
      if (mediaKindFromMime(m.mime, m.name) !== 'file') {
        wireFilePreview(div, m);
      }
    } else if (m.kind === 'file-uploading') {
      div.classList.add('file');
      div.dataset.uploadId = m.id;
      div.innerHTML = `
        ${senderHeader}
        <div class="file-row">
          <div class="file-icon">
            <svg viewBox="0 0 24 24" width="22" height="22"><path fill="currentColor" d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM6 4h7v5h5v11H6z"/></svg>
          </div>
          <div class="file-meta">
            <div class="file-name">${escapeHtml(m.name || 'file')}</div>
            <div class="file-size">${formatBytes(m.size || 0)} • Sending…</div>
            <div class="file-progress" style="--p:0%"></div>
          </div>
        </div>`;
    }
    attachContextMenu(div);
    // Group consecutive messages from the same sender (within 3 minutes)
    div.dataset.ts = String(Date.now());
    const prev = lastChatNode(wrap);
    if (prev && prev.classList.contains(direction) && !prev.classList.contains('system')
        && !prev.classList.contains('deleted')
        && (prev.dataset.from || '') === (div.dataset.from || '')
        && Date.now() - Number(prev.dataset.ts || 0) < 180000) {
      prev.classList.add('grp-next');
      div.classList.add('grp-prev');
    }
    appendToChat(div);
    smartScroll();
    if (direction === 'in' && m.id) queueReadReceipt(m.id);
  }

  function formatDuration(s) {
    s = Math.max(0, Math.round(s));
    const m = Math.floor(s / 60);
    const ss = (s % 60).toString().padStart(2, '0');
    return `${m}:${ss}`;
  }

  function wireAudioBubble(bubble, url, duration) {
    const btn = bubble.querySelector('.audio-play');
    const waves = bubble.querySelectorAll('.audio-waves span');
    const durEl = bubble.querySelector('.audio-duration');
    const audio = new Audio(url);
    let playing = false;
    let interval = null;

    function setIcon(icon) {
      btn.innerHTML = icon === 'play'
        ? '<svg viewBox="0 0 24 24" width="18" height="18"><path fill="currentColor" d="M8 5v14l11-7z"/></svg>'
        : '<svg viewBox="0 0 24 24" width="18" height="18"><path fill="currentColor" d="M6 5h4v14H6zm8 0h4v14h-4z"/></svg>';
    }

    btn.addEventListener('click', () => {
      if (playing) { audio.pause(); }
      else { audio.play().catch(() => toast('Cannot play audio')); }
    });

    audio.addEventListener('play', () => {
      playing = true; setIcon('pause');
      interval = setInterval(() => {
        const total = audio.duration || duration || 1;
        const pct = audio.currentTime / total;
        const upto = Math.floor(pct * waves.length);
        waves.forEach((w, i) => w.classList.toggle('played', i < upto));
        durEl.textContent = formatDuration(audio.currentTime);
      }, 80);
    });
    audio.addEventListener('pause', () => {
      playing = false; setIcon('play');
      clearInterval(interval);
    });
    audio.addEventListener('ended', () => {
      playing = false; setIcon('play');
      clearInterval(interval);
      waves.forEach(w => w.classList.remove('played'));
      durEl.textContent = formatDuration(duration || 0);
    });
  }

  // Status lines that supersede each other share a key, so they update in
  // place instead of stacking up (e.g. relay → direct "secure channel ready").
  function systemKey(text) {
    if (/^Secure channel ready/.test(text)) return 'secure';
    if (/^(Reconnecting|Back online)/.test(text)) return 'reconnect';
    return text;
  }

  function showSystemMessage(text) {
    const wrap = $('messages');
    const key = systemKey(text);
    // Look back through the trailing run of status lines (no chat in between).
    for (let n = lastChatNode(wrap); n && n.classList.contains('system'); n = prevChatNode(n)) {
      if (n.dataset.key === key) {
        n.textContent = text;
        smartScroll(true);
        return;
      }
    }
    const div = document.createElement('div');
    div.className = 'bubble system';
    div.dataset.key = key;
    div.textContent = text;
    appendToChat(div);
    smartScroll(true); /* system messages always scroll — they're status, not chat */
  }

  // The waiting card and typing bubble always sit at the end of the list.
  const isFloater = (n) => n.classList.contains('waiting-card') || n.classList.contains('typing-bubble');
  function prevChatNode(n) {
    let p = n.previousElementSibling;
    while (p && isFloater(p)) p = p.previousElementSibling;
    return p;
  }
  function lastChatNode(wrap) {
    let n = wrap.lastElementChild;
    while (n && isFloater(n)) n = n.previousElementSibling;
    return n;
  }
  function appendToChat(el) {
    const wrap = $('messages');
    const floater = wrap.querySelector(':scope > .waiting-card, :scope > .typing-bubble');
    wrap.insertBefore(el, floater);
  }

  // ---- "Waiting for someone" card (shown while you're alone in the room) ----
  function updateWaitingCard() {
    const wrap = $('messages');
    let card = wrap.querySelector(':scope > .waiting-card');
    const alone = state.inChat && peerCount() === 0 && !!state.room;
    if (!alone) { card?.remove(); return; }
    if (card) return;
    card = document.createElement('div');
    card.className = 'waiting-card';
    const tiles = Array.from(state.room).map(ch => `<span>${escapeHtml(ch)}</span>`).join('');
    const group = state.roomMode === 'group';
    card.innerHTML = `
      <div class="wc-radar" aria-hidden="true"><i></i><i></i><i></i>
        <svg width="34" height="34"><use href="#anon-mark"/></svg></div>
      <div class="wc-title">${group ? 'Waiting for others to join' : 'Waiting for someone to join'}</div>
      <div class="wc-sub">${group ? 'Up to 4 more people can join with this code.' : 'Send them this code — they enter it on their device.'}</div>
      <div class="wc-code" aria-label="Room code ${escapeHtml(state.room)}">${tiles}</div>
      <div class="wc-actions">
        <button type="button" class="wc-btn wc-share">Share invite</button>
        <button type="button" class="wc-btn wc-copy">Copy code</button>
      </div>`;
    card.querySelector('.wc-share').addEventListener('click', () => shareInvite(state.room));
    card.querySelector('.wc-copy').addEventListener('click', async () => {
      try { await navigator.clipboard.writeText(state.room); toast('Room code copied'); }
      catch { toast('Code: ' + state.room); }
    });
    wrap.appendChild(card);
    smartScroll(true);
  }

  // ---- In-chat typing bubble ----
  let typingExpiryTimer = null;
  function updateTypingBubble(typingPeers) {
    const wrap = $('messages');
    let el = wrap.querySelector(':scope > .typing-bubble');
    clearTimeout(typingExpiryTimer);
    if (!typingPeers.length) { el?.remove(); return; }
    // Re-check when the newest typing signal expires, in case "stopped typing" never arrives.
    const soonest = Math.min(...typingPeers.map(p => p.typingUntil));
    typingExpiryTimer = setTimeout(updatePresenceUI, Math.max(50, soonest - Date.now() + 50));
    const label = isGroup()
      ? typingPeers.map(p => (p.profile.name || '').trim() || 'Someone').slice(0, 2).join(', ')
      : '';
    if (!el) {
      el = document.createElement('div');
      el.className = 'typing-bubble';
      el.setAttribute('aria-hidden', 'true');
      wrap.appendChild(el);
      if (isNearBottom(wrap)) wrap.scrollTop = wrap.scrollHeight;
    }
    el.innerHTML = `${label ? `<span class="tb-name">${escapeHtml(label)}</span>` : ''}<span class="tb-dots"><i></i><i></i><i></i></span>`;
  }

  function markMessageDeleted(id) {
    if (typeof id !== 'string') return;
    scrubQuotes(id);
    const el = bubbleById(id);
    if (!el) return;
    messageReactions.delete(id);
    el.classList.remove('sticker','audio','image','file');
    el.classList.add('deleted');
    el.innerHTML = `<span style="opacity:.7">Message deleted</span><span class="time">${nowTime()}</span>`;
  }

  // ===========================================================
  // Replies & edits
  // ===========================================================
  const REPLY_ICON = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9 14 4 9l5-5"/><path d="M4 9h10a6 6 0 0 1 6 6v5"/></svg>';
  let composeMode = null; // null | { type: 'reply', id, ref } | { type: 'edit', id }

  const bubbleById = (id) => document.querySelector(`.bubble[data-id="${CSS.escape(String(id))}"]`);

  // Collapse whitespace and cut to `max` characters without splitting emoji.
  function clip(s, max = 140) {
    const chars = Array.from(String(s).replace(/\s+/g, ' ').trim());
    return chars.length > max ? chars.slice(0, max).join('') + '…' : chars.join('');
  }

  function displayNameFor(id, fallback) {
    if (id && id === state.myId) return 'You';
    const p = id ? state.peers.get(id) : null;
    const n = p && p.profile.name && p.profile.name.trim();
    return n || fallback || 'Anonymous';
  }

  // Short plain-text description of any bubble, used inside quotes.
  function snippetOf(el) {
    switch (el.dataset.kind) {
      case 'text':    return clip(el.dataset.text || '');
      case 'sticker': return `Sticker ${el.dataset.sticker || ''}`.trim();
      case 'audio':   return '🎙️ Voice message';
      case 'image':   return '📷 Photo';
      case 'video':   return '🎬 Video';
      default:        return `📎 ${clip(el.dataset.name || 'File', 60)}`;
    }
  }

  function quoteHtml(r) {
    if (!r) return '';
    const name = displayNameFor(r.by, r.n);
    // In groups, colour the quote like that person's name.
    const hue = isGroup()
      ? ` style="--qc:hsl(${senderHue(name === 'You' ? (state.myProfile.name || '').trim() || 'Anonymous' : name)} 100% 74%)"`
      : '';
    return `<button type="button" class="quote" data-ref="${escapeHtml(r.id)}"${hue}>`
      + `<span class="quote-name">${escapeHtml(name)}</span>`
      + `<span class="quote-text">${escapeHtml(r.s || '')}</span></button>`;
  }

  // Decrypt and sanity-check a peer's reply reference.
  async function decodeReplyRef(peer, rp) {
    try {
      const r = JSON.parse(await decryptText(peer.sessionKey, rp));
      if (!r || typeof r.id !== 'string') return null;
      const str = (v, max) => (typeof v === 'string' ? v.slice(0, max) : '');
      const ref = { id: str(r.id, 64), by: str(r.by, 64), n: str(r.n, 40), k: str(r.k, 16), s: clip(str(r.s, 400)) };
      // If we have the quoted message, trust our own copy over the sender's description,
      // so nobody can attribute invented words to a real message.
      const local = bubbleById(ref.id);
      if (local && !local.classList.contains('deleted')) {
        ref.by = local.classList.contains('out') ? state.myId : (local.dataset.from || ref.by);
        ref.n = local.classList.contains('out') ? (state.myProfile.name || '').trim() : (local.dataset.fromName || ref.n);
        ref.k = local.dataset.kind;
        ref.s = snippetOf(local);
      }
      return ref;
    } catch { return null; }
  }

  function showComposeBar(mode, title, text) {
    const bar = $('compose-bar');
    bar.dataset.mode = mode;
    $('compose-bar-title').textContent = title;
    $('compose-bar-text').textContent = text;
    bar.classList.remove('hidden');
    $('chat-screen').classList.add('composing');
    $('chat-screen').classList.toggle('editing', mode === 'edit');
    smartScroll();
  }

  function cancelCompose() {
    if (composeMode?.type === 'edit') $('msg-input').value = '';
    composeMode = null;
    $('compose-bar').classList.add('hidden');
    $('chat-screen').classList.remove('composing', 'editing');
  }

  function startReply(el) {
    if (!el || !el.dataset.id || el.classList.contains('deleted') || el.classList.contains('system')) return;
    if (composeMode?.type === 'edit') cancelCompose();
    const mine = el.classList.contains('out');
    const by = mine ? state.myId : (el.dataset.from || '');
    const n = mine ? (state.myProfile.name || '').trim() : (el.dataset.fromName || '');
    const ref = { id: el.dataset.id, by, n, k: el.dataset.kind, s: snippetOf(el) };
    composeMode = { type: 'reply', id: ref.id, ref };
    showComposeBar('reply', `Replying to ${displayNameFor(by, n)}`, ref.s);
    $('msg-input').focus();
  }

  function startEdit(el) {
    if (!el || !el.classList.contains('out') || el.dataset.kind !== 'text' || el.classList.contains('deleted')) return;
    composeMode = { type: 'edit', id: el.dataset.id };
    showComposeBar('edit', 'Editing message', clip(el.dataset.text || ''));
    const input = $('msg-input');
    input.value = el.dataset.text || '';
    input.focus();
    input.setSelectionRange(input.value.length, input.value.length);
  }

  async function submitEdit(text) {
    const el = bubbleById(composeMode.id);
    if (!el || el.classList.contains('deleted') || text === el.dataset.text) { cancelCompose(); return; }
    const sent = await dcBroadcastEncryptedText(text, { t: 'msg-edit', id: el.dataset.id });
    if (sent > 0) {
      applyEdit(el, text);
      cancelCompose();
    } else {
      toast('No peers connected');
    }
  }

  function applyEdit(el, text) {
    el.dataset.text = text;
    const body = el.querySelector('.msg-text');
    if (body) body.innerHTML = linkify(markdownify(escapeHtml(text)));
    if (!el.querySelector('.edited-tag')) {
      const tag = '<span class="edited-tag">edited</span>';
      const meta = el.querySelector(':scope > .bubble-meta');
      if (meta) meta.insertAdjacentHTML('afterbegin', tag);
      else el.querySelector(':scope > .time')?.insertAdjacentHTML('afterend', tag);
    }
    document.querySelectorAll(`.quote[data-ref="${CSS.escape(el.dataset.id)}"] .quote-text`)
      .forEach(q => { q.textContent = clip(text); });
  }

  // When a message is deleted, remove its words from every quote of it too.
  function scrubQuotes(id) {
    if (!id) return;
    document.querySelectorAll(`.quote[data-ref="${CSS.escape(id)}"]`).forEach(q => {
      q.classList.add('gone');
      q.querySelector('.quote-text').textContent = 'Message deleted';
    });
    if (composeMode?.id === id) cancelCompose();
  }

  // Tap a quote to jump to the original message.
  $('messages').addEventListener('click', (e) => {
    const q = e.target.closest('.quote');
    if (!q) return;
    const target = bubbleById(q.dataset.ref);
    if (!target || target.classList.contains('deleted')) { toast('Original message is gone'); return; }
    target.scrollIntoView({ behavior: 'smooth', block: 'center' });
    target.classList.remove('flash');
    void target.offsetWidth;
    target.classList.add('flash');
    setTimeout(() => target.classList.remove('flash'), 1400);
  });

  $('compose-bar-close').addEventListener('click', () => { cancelCompose(); $('msg-input').focus(); });

  $('msg-input').addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && composeMode && ctxMenu.classList.contains('hidden')) {
      cancelCompose();
    } else if (e.key === 'ArrowUp' && !e.target.value && !composeMode) {
      // Quick-edit your last text message
      const mine = document.querySelectorAll('.bubble.out[data-kind="text"]:not(.deleted)');
      if (mine.length) { e.preventDefault(); startEdit(mine[mine.length - 1]); }
    }
  });

  // ===========================================================
  // Context menu (right-click / long-press to delete)
  // ===========================================================
  const ctxMenu = $('ctx-menu');
  let ctxTargetEl = null;

  function attachContextMenu(bubble) {
    if (bubble.classList.contains('system')) return;
    let lastTap = 0;
    // Hover shortcut (pointer devices) for replying
    const replyBtn = document.createElement('button');
    replyBtn.type = 'button';
    replyBtn.className = 'bubble-reply';
    replyBtn.title = 'Reply';
    replyBtn.setAttribute('aria-label', 'Reply');
    replyBtn.innerHTML = REPLY_ICON;
    replyBtn.addEventListener('click', (e) => { e.stopPropagation(); startReply(bubble); });
    bubble.appendChild(replyBtn);
    // Swipe right to reply (touch)
    let sx = 0, sy = 0, dx = 0, swiping = false;
    bubble.addEventListener('dblclick', (e) => {
      if (bubble.classList.contains('deleted') || e.target.closest('.quote, .bubble-reply')) return;
      toggleReaction(bubble.dataset.id, '❤️');
    });
    bubble.addEventListener('contextmenu', (e) => {
      e.preventDefault();
      openCtxMenu(bubble, e.clientX, e.clientY);
    });
    // Long-press for touch devices; double-tap to ❤️
    let pressTimer = null;
    bubble.addEventListener('touchstart', (e) => {
      const t0 = e.touches[0];
      sx = t0.clientX; sy = t0.clientY; dx = 0; swiping = false;
      bubble.style.transition = '';
      pressTimer = setTimeout(() => {
        const t = e.touches[0];
        openCtxMenu(bubble, t.clientX, t.clientY);
      }, 500);
    }, { passive: true });
    bubble.addEventListener('touchend', (e) => {
      clearTimeout(pressTimer);
      if (swiping) {
        swiping = false;
        bubble.style.transition = 'transform .2s cubic-bezier(.2,.9,.3,1.2)';
        bubble.style.transform = '';
        bubble.classList.remove('swipe-ready');
        if (dx > 56) startReply(bubble);
        return;
      }
      if (e.target.closest('.quote, .bubble-reply')) return;
      const now = Date.now();
      if (now - lastTap < 320) {
        if (!bubble.classList.contains('deleted')) toggleReaction(bubble.dataset.id, '❤️');
        lastTap = 0;
      } else {
        lastTap = now;
      }
    });
    bubble.addEventListener('touchmove', (e) => {
      clearTimeout(pressTimer);
      if (bubble.classList.contains('deleted')) return;
      const t = e.touches[0];
      const mx = t.clientX - sx, my = t.clientY - sy;
      if (!swiping && mx > 12 && mx > Math.abs(my) * 1.5) swiping = true;
      if (!swiping) return;
      dx = Math.max(0, Math.min(mx, 80));
      bubble.style.transform = `translateX(${dx}px)`;
      bubble.classList.toggle('swipe-ready', dx > 56);
    }, { passive: true });
  }

  function openCtxMenu(el, x, y) {
    ctxTargetEl = el;
    const mine = el.classList.contains('out');
    const isText = el.dataset.kind === 'text';
    const deleted = el.classList.contains('deleted');
    $('ctx-delete-all').style.display = (mine && !deleted) ? '' : 'none';
    $('ctx-delete-me').style.display = deleted ? 'none' : '';
    $('ctx-copy').style.display = isText ? '' : 'none';
    $('ctx-react-row').style.display = deleted ? 'none' : '';
    $('ctx-reply').style.display = deleted ? 'none' : '';
    $('ctx-edit').style.display = (mine && isText && !deleted) ? '' : 'none';
    const delAll = $('ctx-delete-all');
    if (delAll) delAll.textContent = isGroup() ? 'Delete for everyone' : 'Delete for both';
    ctxMenu.classList.remove('hidden');
    const box = ctxMenu.getBoundingClientRect();
    ctxMenu.style.left = Math.max(8, Math.min(x, window.innerWidth - box.width - 8)) + 'px';
    ctxMenu.style.top = Math.max(8, Math.min(y, window.innerHeight - box.height - 8)) + 'px';
  }
  function closeCtxMenu() { ctxMenu.classList.add('hidden'); ctxTargetEl = null; }
  document.addEventListener('click', (e) => {
    if (!ctxMenu.contains(e.target)) closeCtxMenu();
  });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeCtxMenu(); });

  $('ctx-delete-me').addEventListener('click', () => {
    if (!ctxTargetEl) return;
    scrubQuotes(ctxTargetEl.dataset.id);
    ctxTargetEl.remove();
    closeCtxMenu();
  });

  $('ctx-delete-all').addEventListener('click', () => {
    if (!ctxTargetEl) return;
    const id = ctxTargetEl.dataset.id;
    dcBroadcastPlain({ t: 'msg-del', id });
    markMessageDeleted(id);
    closeCtxMenu();
  });

  $('ctx-reply').addEventListener('click', () => {
    const el = ctxTargetEl;
    closeCtxMenu();
    startReply(el);
  });
  $('ctx-edit').addEventListener('click', () => {
    const el = ctxTargetEl;
    closeCtxMenu();
    startEdit(el);
  });

  $('ctx-copy').addEventListener('click', async () => {
    if (!ctxTargetEl) return;
    try {
      await navigator.clipboard.writeText(ctxTargetEl.dataset.text || ctxTargetEl.textContent);
      toast('Copied');
    } catch { toast('Copy failed'); }
    closeCtxMenu();
  });

  const ctxReactRow = $('ctx-react-row');
  if (ctxReactRow) {
    REACTIONS.forEach(emoji => {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'ctx-react';
      btn.textContent = emoji;
      btn.addEventListener('click', () => {
        if (!ctxTargetEl || ctxTargetEl.classList.contains('deleted')) return;
        toggleReaction(ctxTargetEl.dataset.id, emoji);
        closeCtxMenu();
      });
      ctxReactRow.appendChild(btn);
    });
  }

  const msgInput = $('msg-input');
  if (msgInput) {
    msgInput.addEventListener('input', () => {
      if (!anyPeerReady()) return;
      sendTyping(true);
      scheduleTypingStop();
    });
    msgInput.addEventListener('blur', () => sendTyping(false));
  }
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) {
      document.querySelectorAll('.bubble.in:not(.deleted)[data-id]').forEach(el => {
        queueReadReceipt(el.dataset.id);
      });
    }
  });

  // ===========================================================
  // Chat send
  // ===========================================================
  $('composer').addEventListener('submit', async (e) => {
    e.preventDefault();
    const input = $('msg-input');
    const text = input.value.trim();
    if (!text || !anyPeerReady()) return;
    sendTyping(false);
    try {
      if (composeMode?.type === 'edit') { await submitEdit(text); return; }
      const reply = composeMode?.type === 'reply' ? composeMode.ref : null;
      const id = randId();
      const sent = await dcBroadcastEncryptedText(text, { t: 'msg', id },
        reply ? { rp: JSON.stringify(reply) } : null);
      if (sent > 0) {
        renderMessage({ id, kind: 'text', text, reply }, 'out');
        input.value = '';
        cancelCompose();
      } else {
        toast('No peers connected');
      }
    } catch (err) {
      console.error(err); toast('Failed to send message');
    }
  });

  // ===========================================================
  // Stickers
  // ===========================================================
  const STICKERS = [
    '😀','😁','😂','🤣','😊','😎','😍','🥰','😘','🤩','🤗','🤔','🫡','🤫','😏','😒','😴','🥱',
    '😭','😢','😤','😡','🤬','🤯','🥳','😇','🤡','👻','💀','☠️','👽','🤖','💩','🔥','💯',
    '👍','👎','👏','🙌','🤝','🙏','✌️','🤞','🤟','🤘','👌','🤌','💪','🫶','👀','👁️',
    '❤️','🧡','💛','💚','💙','💜','🖤','🤍','💔','💖','💘','💝','💞','💕','💋',
    '🐶','🐱','🦊','🐻','🐼','🐯','🦁','🐮','🐷','🐸','🐵','🐔','🦄','🐝','🐢','🐙','🦋','🐉','🐳','🦖',
    '☕','🍕','🍔','🍟','🌮','🍣','🍰','🍩','🍪','🍫','🍿','🍻','🥂','🍷','🍺','🍹','🥤',
    '⚽','🏀','🎮','🎲','🎯','🎸','🎺','🎷','🥁','🎤','🎧','📷','🎥','💻','📱',
    '🚀','✨','⭐','🌟','💫','☀️','🌙','⚡','🌈','🎉','🎊','🎁','🎈','🏆','🥇','💎','🔑','🔒','🗝️',
  ];

  function buildStickerGrid() {
    const grid = $('sticker-grid');
    grid.innerHTML = '';
    STICKERS.forEach(s => {
      const b = document.createElement('button');
      b.type = 'button';
      b.className = 'sticker-item';
      b.textContent = s;
      b.addEventListener('click', () => sendSticker(s));
      grid.appendChild(b);
    });
  }
  buildStickerGrid();

  function sendSticker(s) {
    if (!anyPeerReady()) return;
    const id = randId();
    const sent = dcBroadcastPlain({ t: 'sticker', id, s });
    if (sent > 0) {
      renderMessage({ id, kind: 'sticker', sticker: s }, 'out');
      $('sticker-panel').classList.add('hidden');
      $('sticker-btn').classList.remove('active');
    }
  }

  $('sticker-btn').addEventListener('click', () => {
    const panel = $('sticker-panel');
    panel.classList.toggle('hidden');
    $('sticker-btn').classList.toggle('active', !panel.classList.contains('hidden'));
  });

  // ===========================================================
  // Voice messages
  // ===========================================================
  async function startRecording() {
    if (state.mediaRecorder) return;
    let stream;
    try {
      stream = await navigator.mediaDevices.getUserMedia({
        audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true }
      });
    } catch {
      toast('Microphone permission denied');
      return;
    }
    const mimeCandidates = ['audio/webm;codecs=opus','audio/webm','audio/ogg;codecs=opus','audio/mp4'];
    const mime = mimeCandidates.find(m => MediaRecorder.isTypeSupported(m)) || '';
    const rec = new MediaRecorder(stream, mime ? { mimeType: mime, audioBitsPerSecond: 32000 } : {});
    state.mediaRecorder = rec;
    state.recordChunks = [];
    state.recordCancelled = false;
    rec.ondataavailable = (e) => { if (e.data && e.data.size > 0) state.recordChunks.push(e.data); };
    rec.onstop = async () => {
      stream.getTracks().forEach(t => t.stop());
      const duration = (Date.now() - state.recordStart) / 1000;
      const blob = new Blob(state.recordChunks, { type: rec.mimeType || 'audio/webm' });
      state.mediaRecorder = null;
      clearInterval(state.recordTimerInt);
      $('recording-overlay').classList.add('hidden');
      if (state.recordCancelled || duration < 0.4) return;
      await sendVoiceMessage(blob, duration);
    };
    rec.start();
    state.recordStart = Date.now();
    $('recording-overlay').classList.remove('hidden');
    state.recordTimerInt = setInterval(() => {
      const s = (Date.now() - state.recordStart) / 1000;
      $('recording-time').textContent = formatDuration(s);
      if (s > 120) stopRecording(false); // 2-minute cap
    }, 200);
  }

  function stopRecording(cancel) {
    if (!state.mediaRecorder) return;
    state.recordCancelled = !!cancel;
    try { state.mediaRecorder.stop(); } catch {}
  }

  async function sendVoiceMessage(blob, duration) {
    if (!anyPeerReady()) return;
    const bytes = new Uint8Array(await blob.arrayBuffer());
    const localUrl = URL.createObjectURL(blob);
    if (bytes.length <= CHUNK_BYTES) {
      const id = randId();
      // Encrypt+send per peer
      for (const peer of state.peers.values()) {
        if (!peerTransportReady(peer)) continue;
        const p = await encryptBytes(peer.sessionKey, bytes);
        dcSendTo(peer, { t: 'audio', id, dur: duration, mime: blob.type, p });
      }
      renderMessage({ id, kind: 'audio', audioUrl: localUrl, duration }, 'out');
    } else {
      const id = await dcBroadcastBlob('audio', bytes, { dur: duration, mime: blob.type });
      renderMessage({ id, kind: 'audio', audioUrl: localUrl, duration }, 'out');
    }
  }

  $('mic-btn').addEventListener('click', () => startRecording());
  $('recording-stop').addEventListener('click', () => stopRecording(false));
  $('recording-cancel').addEventListener('click', () => stopRecording(true));

  // File attachments
  $('attach-btn').addEventListener('click', () => {
    if ($('attach-btn').disabled) return;
    $('file-input').click();
  });
  $('file-input').addEventListener('change', async (e) => {
    const files = Array.from(e.target.files || []);
    e.target.value = '';
    if (files.length) await sendFiles(files);
  });

  // Profile dialog
  $('profile-btn').addEventListener('click', openProfileDialog);
  $('profile-cancel').addEventListener('click', closeProfileDialog);
  $('profile-pick').addEventListener('click', () => $('profile-avatar-input').click());
  $('profile-avatar-input').addEventListener('change', async (e) => {
    const file = e.target.files && e.target.files[0];
    e.target.value = '';
    if (!file) return;
    if (!file.type.startsWith('image/')) { toast('Pick an image'); return; }
    try {
      const dataUrl = await resizeImageFile(file, 128, 0.82);
      const preview = $('profile-preview');
      preview.style.backgroundImage = `url(${dataUrl})`;
      preview.textContent = '';
      preview.dataset.pending = dataUrl;
    } catch { toast('Could not load image'); }
  });
  $('profile-clear').addEventListener('click', () => {
    const preview = $('profile-preview');
    preview.style.backgroundImage = '';
    preview.dataset.pending = '';
    preview.textContent = '?';
  });
  $('profile-save').addEventListener('click', () => {
    const name = $('profile-name').value.trim().slice(0, 40);
    const preview = $('profile-preview');
    const pending = preview.dataset.pending;
    state.myProfile.name = name;
    if (pending === '') state.myProfile.av = null;
    else if (pending) state.myProfile.av = pending;
    closeProfileDialog();
    applyMyProfile();
    sendMyProfile();
    toast(name ? `Saved as "${name}"` : 'Profile cleared');
  });

  // ===========================================================
  // Join flow
  // ===========================================================
  $('gen-btn').addEventListener('click', () => {
    $('room-input').value = randCode(6);
    setRoomError('');
  });
  $('room-input')?.addEventListener('input', () => setRoomError(''));
  $('share-code-btn')?.addEventListener('click', () => {
    shareInvite($('room-input').value.trim().toUpperCase());
  });

  function roomFromUrl() {
    const hash = location.hash.replace(/^#/, '').toUpperCase();
    if (/^[A-Z0-9]{4,12}$/.test(hash)) return hash;
    const path = location.pathname.replace(/^\//, '').replace(/^@/, '').toUpperCase();
    if (/^[A-Z0-9]{4,12}$/.test(path)) return path;
    // Also read ?room= query param (generated by share links)
    const qRoom = new URLSearchParams(location.search).get('room')?.toUpperCase() || '';
    if (/^[A-Z0-9]{4,12}$/.test(qRoom)) {
      history.replaceState({}, '', location.pathname); // clean URL
      return qRoom;
    }
    return null;
  }
  const urlRoom = roomFromUrl();
  if (urlRoom) {
    $('room-input').value = urlRoom;
  } else {
    $('room-input').value = randCode(6);
  }

  // Mode toggle (segmented control)
  let selectedMode = '1on1';
  function setMode(mode) {
    selectedMode = mode;
    setRoomError('');
    document.querySelectorAll('.mode-opt').forEach(b => {
      const active = b.dataset.mode === mode;
      b.classList.toggle('active', active);
      b.setAttribute('aria-checked', active ? 'true' : 'false');
    });
    const hint = $('room-hint');
    if (hint) {
      hint.textContent = mode === 'group'
        ? 'Share this code with your group. Up to 5 people can join.'
        : 'Share this code with one other person. Both must enter it.';
    }
  }
  document.querySelectorAll('.mode-opt').forEach(b => {
    b.addEventListener('click', () => setMode(b.dataset.mode));
  });
  setMode('1on1');

  function enterChatScreen(code, mode) {
    state.inChat = true;
    showScreen('chat-screen');
    if (Notification.permission === 'granted') initPushSubscription();
    $('peer-avatar').textContent = code.charAt(0);
    $('peer-avatar').style.backgroundImage = '';
    document.querySelector('.peer-name').textContent =
      mode === 'group' ? 'Group room' : 'Anonymous peer';
    applyMyProfile();
    const intro = mode === 'group'
      ? `Group room "${code}" — up to 5 people can join.`
      : `Room "${code}" — private 1-on-1.`;
    showSystemMessage(intro);
    setBanner('Verifying secure channel…', 'info');
    setStatus('connecting…', false);
    updateModeIndicator();
    if (peerCount() === 0) {
      // Nobody here yet: get the loader out of the way so the invite can be shared right away.
      clearTimeout(_loadFallback);
      _loadFallback = setTimeout(fadeOutLoading, 600);
      updateWaitingCard();
      setStatus('waiting', false);
      setBanner('Room open — share the code to start an encrypted chat', 'info');
    }
    clearTimeout(state._connectTimeout);
    state._connectTimeout = setTimeout(() => {
      if (!anyPeerReady()) {
        setBanner('Still connecting… check both devices use the same room code.', 'warning');
        toast('Not connected yet — try refreshing both tabs');
      }
    }, 25000);
  }

  $('join-btn').addEventListener('click', async () => {
    const code = $('room-input').value.trim().toUpperCase();
    if (!/^[A-Z0-9]{4,12}$/.test(code)) { toast('Room code must be 4–12 letters/digits'); return; }
    setRoomError('');
    const joinBtn = $('join-btn');
    joinBtn.disabled = true;
    state.room = code;
    state.roomMode = selectedMode;
    state.myProfile = { name: ($('name-input').value || '').trim().slice(0, 40), av: null };
    location.hash = code;
    showLoading('Connecting to server…', 15);
    try {
      await Promise.all([connectSignaling(), loadIceConfig()]);
      showLoading('Generating encryption keys…', 32);
      const outcome = waitForJoinOutcome(15000);
      state.ws.send(JSON.stringify({ type: 'join', room: code, mode: selectedMode }));
      showLoading('Joining room…', 48);
      await outcome;
      // Start a fallback — hide loading after 12 s even if key exchange is slow
      clearTimeout(_loadFallback);
      _loadFallback = setTimeout(() => cancelLoading(), 12000);
      enterChatScreen(code, selectedMode);
    } catch (e) {
      cancelLoading();
      const msg = e?.message || 'Could not join room';
      if (!state.myId) handleJoinRejected(msg);
      else toast(msg);
    } finally {
      joinBtn.disabled = false;
    }
  });

  function updateModeIndicator() {
    const tag = $('mode-tag');
    if (!tag) return;
    if (state.roomMode === 'group') {
      tag.textContent = 'Group';
      tag.classList.remove('hidden');
      tag.classList.add('group');
    } else if (state.roomMode === '1on1') {
      tag.textContent = '1-on-1';
      tag.classList.remove('hidden');
      tag.classList.remove('group');
    } else {
      tag.classList.add('hidden');
    }
  }

  $('back-btn').addEventListener('click', () => {
    if (!confirm('Leave this room? Messages will be deleted.')) return;
    cleanupAndReturn();
  });

  $('reconnect-btn')?.addEventListener('click', () => reconnectSession());

  // Scroll-to-bottom button
  $('messages').addEventListener('scroll', () => {
    if (isNearBottom($('messages'))) unreadScrollCount = 0;
    updateScrollBtn();
  }, { passive: true });
  $('scroll-btn')?.addEventListener('click', () => {
    const wrap = $('messages');
    wrap.scrollTo({ top: wrap.scrollHeight, behavior: 'smooth' });
    unreadScrollCount = 0;
    updateScrollBtn();
  });

  $('safety-close-btn')?.addEventListener('click', () => $('safety-dialog').classList.add('hidden'));
  $('safety-dialog')?.addEventListener('click', (e) => {
    if (e.target.id === 'safety-dialog') $('safety-dialog').classList.add('hidden');
  });

  $('preview-close')?.addEventListener('click', closeFilePreview);
  $('preview-overlay')?.addEventListener('click', (e) => {
    if (e.target.id === 'preview-overlay') closeFilePreview();
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeFilePreview();
  });
  $('notify-btn')?.addEventListener('click', () => enableNotifications());
  $('chat-share-btn')?.addEventListener('click', () => {
    if (state.room) shareInvite(state.room);
  });

  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.addEventListener('message', (ev) => {
      if (ev.data && ev.data.type === 'open-room' && ev.data.room) {
        location.hash = ev.data.room;
        if (!state.inChat) $('room-input').value = ev.data.room;
      }
    });
  }

  function cleanupAndReturn() {
    cancelLoading();
    cancelWsRetry();
    state.inChat = false;
    state.pushEnabled = false;
    sendTyping(false);
    if (anyPeerReady()) dcBroadcastPlain({ t: 'presence', on: false });
    messageReactions.clear();
    try {
      if (wsConnected()) state.ws.send(JSON.stringify({ type: 'push-unsub' }));
      state.ws.send(JSON.stringify({ type: 'leave' }));
    } catch {}
    try { state.ws && state.ws.close(); } catch {}
    for (const peer of state.peers.values()) {
      try { peer.dc && peer.dc.close(); } catch {}
      try { peer.pc && peer.pc.close(); } catch {}
    }
    state.peers.clear();
    teardownCall();
    joinedReady = false;
    preJoinQueue.length = 0;
    joinOutcomeWaiters.length = 0;
    signalInbox = Promise.resolve();
    setRoomError('');
    clearTimeout(state._connectTimeout);
    Object.assign(state, {
      ws: null, myId: null, room: null,
      myKeyPair: null,
      myProfile: { name: '', av: null },
      callPeerId: null,
      iceServers: null, iceHasTurn: false, iceSource: '', forceRelay: false,
      inChat: false, pushEnabled: false,
    });
    updateReconnectBanner();
    $('messages').innerHTML = '';
    cancelCompose();
    $('msg-input').value = '';
    $('name-input').value = '';
    disableComposer();
    $('sticker-panel').classList.add('hidden');
    closeProfileDialog();
    applyMyProfile();
    location.hash = '';
    showScreen('join-screen');
  }

  // ===========================================================
  // Calls (audio / video / screen share)
  // ===========================================================
  async function getMedia(video) {
    return navigator.mediaDevices.getUserMedia({
      audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true },
      video: video ? { width: { ideal: 1280 }, height: { ideal: 720 }, facingMode: 'user' } : false,
    });
  }

  async function getDisplayMedia() {
    if (!navigator.mediaDevices?.getDisplayMedia) {
      throw new Error('unsupported');
    }
    return navigator.mediaDevices.getDisplayMedia({
      video: { frameRate: { ideal: 15, max: 30 } },
      audio: false,
    });
  }

  function getCallPeer() {
    return state.callPeerId ? getPeer(state.callPeerId) : null;
  }

  function getVideoSender() {
    if (state.videoSender) return state.videoSender;
    const peer = getCallPeer();
    if (peer?.pc) {
      const s = peer.pc.getSenders().find(x => x.track?.kind === 'video');
      if (s) return s;
    }
    return state.senders.find(s => s.track?.kind === 'video') || null;
  }

  async function replaceOutgoingVideoTrack(track) {
    const peer = getCallPeer();
    if (!peer?.pc) return;
    const sender = getVideoSender();
    if (sender) {
      await sender.replaceTrack(track);
      return;
    }
    if (!track) return;
    const stream = state.screenStream || state.localStream || new MediaStream([track]);
    const s = peer.pc.addTrack(track, stream);
    state.senders.push(s);
    state.videoSender = s;
  }

  function updateCallVideoLayout() {
    const localVideo = $('local-video');
    const remoteVideo = $('remote-video');
    const showLocal = state.sharingScreen || state.callType === 'video';
    const showRemote = state.remoteSharingScreen || state.callType === 'video';
    if (localVideo) {
      localVideo.style.display = showLocal ? 'block' : 'none';
      localVideo.classList.toggle('screen-share', state.sharingScreen);
    }
    if (remoteVideo) {
      remoteVideo.style.display = showRemote ? 'block' : 'none';
      remoteVideo.classList.toggle('screen-share', state.remoteSharingScreen);
    }

    // Screen-share button: teal glow when ON
    const ssBtn = $('screen-share-btn');
    if (ssBtn) ssBtn.classList.toggle('active', state.sharingScreen);

    // Camera button:
    //  - audio-only call and not screen sharing → dim (nothing to toggle)
    //  - screen sharing → ss-mode style + title changes to "switch back to camera"
    //  - video call, not sharing → normal toggle
    const camBtn = $('cam-btn');
    if (camBtn) {
      const audioOnly = state.callType === 'audio' && !state.sharingScreen;
      camBtn.classList.toggle('ss-mode', state.sharingScreen);
      camBtn.style.opacity = audioOnly ? '0.35' : '';
      camBtn.style.pointerEvents = audioOnly ? 'none' : '';
      camBtn.title = state.sharingScreen ? 'Stop sharing / switch to camera' : 'Toggle camera';
    }
  }

  async function startScreenShare() {
    if (!state.callActive) { toast('Start a call first'); return; }
    const peer = getCallPeer();
    if (!peer?.pc) { toast('Not connected'); return; }
    if (state.sharingScreen) { await stopScreenShare(); return; }
    try {
      state.screenStream = await getDisplayMedia();
    } catch (e) {
      if (e?.name === 'NotAllowedError') toast('Screen share cancelled');
      else toast('Screen share not supported on this device');
      return;
    }
    const screenTrack = state.screenStream.getVideoTracks()[0];
    if (!screenTrack) {
      state.screenStream.getTracks().forEach(t => t.stop());
      state.screenStream = null;
      toast('No video track from screen');
      return;
    }
    screenTrack.onended = () => stopScreenShare();
    try {
      await replaceOutgoingVideoTrack(screenTrack);
    } catch (e) {
      console.error('[screen]', e);
      state.screenStream.getTracks().forEach(t => t.stop());
      state.screenStream = null;
      toast('Could not share screen');
      return;
    }
    state.sharingScreen = true;
    const localVideo = $('local-video');
    if (localVideo) localVideo.srcObject = state.screenStream;
    dcSendTo(peer, { t: 'call-screen', on: true });
    updateCallVideoLayout();
    $('call-status').textContent = 'Sharing your screen';
    toast('Screen sharing on');
  }

  async function stopScreenShare(notify = true) {
    if (!state.sharingScreen && !state.screenStream) return;
    const peer = getCallPeer();
    state.sharingScreen = false;
    if (state.screenStream) {
      state.screenStream.getTracks().forEach(t => t.stop());
      state.screenStream = null;
    }
    const camTrack = state.localStream?.getVideoTracks()[0] || null;
    try {
      if (state.callType === 'video' && camTrack?.enabled) {
        await replaceOutgoingVideoTrack(camTrack);
        const localVideo = $('local-video');
        if (localVideo) localVideo.srcObject = state.localStream;
      } else {
        await replaceOutgoingVideoTrack(null);
        const localVideo = $('local-video');
        if (localVideo) localVideo.srcObject = null;
      }
    } catch (e) {
      console.warn('[screen] restore camera failed', e);
    }
    if (notify && peer) dcSendTo(peer, { t: 'call-screen', on: false });
    updateCallVideoLayout();
    if (state.callActive) $('call-status').textContent = 'Connected';
  }

  async function startCall(type) {
    console.log('[call] startCall', type, 'peers:', peerCount(), 'mode:', state.roomMode);
    if (state.callActive) { toast('Already in a call'); return; }
    if (peerCount() !== 1) {
      toast('Calls are only available in 1-on-1 mode (group calls coming soon)');
      return;
    }
    const peer = state.peers.values().next().value;
    console.log('[call] target peer:', peer && peer.id, 'dc:', peer && peer.dc && peer.dc.readyState);
    if (!peer || !peer.dc || peer.dc.readyState !== 'open') {
      toast('Peer not connected yet'); return;
    }
    try {
      state.localStream = await getMedia(type === 'video');
      console.log('[call] got local stream, tracks:', state.localStream.getTracks().map(t => t.kind));
    }
    catch (e) {
      console.error('[call] getMedia failed', e);
      toast('Microphone/camera permission denied');
      return;
    }
    state.callType = type;
    state.callPeerId = peer.id;
    try {
      addLocalTracks(peer, { hold: true });
      console.log('[call] media lines added (held until accepted), awaiting renegotiation');
    } catch (e) {
      console.error('[call] addLocalTracks failed', e);
      toast('Could not start call (track error)');
      teardownCall();
      return;
    }
    const delivered = dcSendTo(peer, { t: 'call-invite', callType: type });
    console.log('[call] invite delivered to DC:', delivered);
    if (!delivered) {
      toast('Could not reach peer');
      teardownCall();
      return;
    }
    showCallOverlay('Ringing…');
  }

  // With `hold`, the media lines are negotiated while ringing but no track is
  // attached to the senders, so nothing leaves this device until the other
  // side accepts (releaseHeldTracks).
  function addLocalTracks(peer, { hold = false } = {}) {
    if (!state.localStream || !peer.pc) return;
    const localVideo = $('local-video');
    localVideo.srcObject = state.localStream;
    state.senders.forEach(s => { try { peer.pc.removeTrack(s); } catch {} });
    state.senders = [];
    state.videoSender = null;
    state.heldTracks = [];
    state.localStream.getTracks().forEach(track => {
      let sender;
      if (hold) {
        sender = peer.pc.addTransceiver(track.kind, {
          direction: 'sendrecv', streams: [state.localStream],
        }).sender;
        state.heldTracks.push([sender, track]);
      } else {
        sender = peer.pc.addTrack(track, state.localStream);
      }
      state.senders.push(sender);
      if (track.kind === 'video') state.videoSender = sender;
    });
  }

  async function releaseHeldTracks() {
    const held = state.heldTracks;
    state.heldTracks = [];
    await Promise.all(held.map(([sender, track]) =>
      sender.replaceTrack(track).catch(e => console.warn('[call] replaceTrack failed', e))));
  }

  // Start playing the other side's audio/video. Only called once a call is active.
  function attachRemoteMedia() {
    const rv = $('remote-video');
    if (!rv || !state.remoteStream) return;
    if (rv.srcObject !== state.remoteStream) rv.srcObject = state.remoteStream;
    rv.play().catch(() => {});
  }

  function dropRemoteMedia() {
    state.remoteStream = null;
    const rv = $('remote-video');
    if (rv) rv.srcObject = null;
  }

  function showCallOverlay(status) {
    $('call-overlay').classList.remove('hidden');
    $('call-status').textContent = status;
    state.remoteSharingScreen = false;
    updateCallVideoLayout();
  }

  function hideCallOverlay() {
    $('call-overlay').classList.add('hidden');
    $('call-status').textContent = '';
    $('call-timer').textContent = '';
    state.remoteSharingScreen = false;
    state.sharingScreen = false;
  }

  function showIncomingCall(type) {
    state.callType = type;
    $('incoming-type').textContent = type === 'video' ? 'Incoming video call' : 'Incoming audio call';
    $('incoming-call').classList.remove('hidden');
  }

  $('accept-btn').addEventListener('click', async () => {
    $('incoming-call').classList.add('hidden');
    const peer = state.callPeerId && getPeer(state.callPeerId);
    if (!peer) return;
    try { state.localStream = await getMedia(state.callType === 'video'); }
    catch { toast('Permission denied'); dcSendTo(peer, { t: 'call-decline' }); return; }
    addLocalTracks(peer);
    dcSendTo(peer, { t: 'call-accept' });
    showCallOverlay('Connected');
    startCallTimer();
    state.callActive = true;
    attachRemoteMedia();
  });

  $('decline-btn').addEventListener('click', () => {
    $('incoming-call').classList.add('hidden');
    const peer = state.callPeerId && getPeer(state.callPeerId);
    if (peer) dcSendTo(peer, { t: 'call-decline' });
    state.callType = null;
    state.callPeerId = null;
    dropRemoteMedia();
  });

  function onCallAccepted() {
    if (state.callActive || !state.localStream) return;
    $('call-status').textContent = 'Connected';
    startCallTimer();
    state.callActive = true;
    releaseHeldTracks();
    attachRemoteMedia();
  }
  function onCallDeclined() { toast('Call declined'); teardownCall(); }

  function startCallTimer() {
    state.callTimerStart = Date.now();
    clearInterval(state.callTimerInt);
    state.callTimerInt = setInterval(() => {
      const s = Math.floor((Date.now() - state.callTimerStart) / 1000);
      const m = Math.floor(s / 60).toString().padStart(2, '0');
      const ss = (s % 60).toString().padStart(2, '0');
      $('call-timer').textContent = `${m}:${ss}`;
    }, 500);
  }

  function teardownCall() {
    const wasRinging = !$('incoming-call').classList.contains('hidden');
    $('incoming-call').classList.add('hidden');
    if (wasRinging) showSystemMessage('Missed call.');
    stopScreenShare(false);
    clearInterval(state.callTimerInt);
    state.callTimerInt = null;
    state.callActive = false;
    state.callType = null;
    state.remoteSharingScreen = false;
    if (state.localStream) {
      state.localStream.getTracks().forEach(t => t.stop());
      state.localStream = null;
    }
    const peer = state.callPeerId && getPeer(state.callPeerId);
    if (peer && peer.pc) {
      state.senders.forEach(s => { try { peer.pc.removeTrack(s); } catch {} });
    }
    state.senders = [];
    state.videoSender = null;
    state.heldTracks = [];
    state.callPeerId = null;
    const lv = $('local-video'); lv.srcObject = null;
    dropRemoteMedia();
    hideCallOverlay();
  }

  $('audio-call-btn').addEventListener('click', () => startCall('audio'));
  $('video-call-btn').addEventListener('click', () => startCall('video'));

  $('hangup-btn').addEventListener('click', () => {
    const peer = state.callPeerId && getPeer(state.callPeerId);
    if (peer) dcSendTo(peer, { t: 'call-end' });
    teardownCall();
    showSystemMessage('Call ended.');
  });

  $('mute-btn').addEventListener('click', (e) => {
    if (!state.localStream) return;
    const audio = state.localStream.getAudioTracks()[0];
    if (!audio) return;
    audio.enabled = !audio.enabled;
    e.currentTarget.classList.toggle('muted', !audio.enabled);
  });

  $('cam-btn').addEventListener('click', async (e) => {
    if (state.sharingScreen) {
      await stopScreenShare();
      return;
    }
    if (!state.localStream) return;
    const video = state.localStream.getVideoTracks()[0];
    if (!video) return;
    video.enabled = !video.enabled;
    e.currentTarget.classList.toggle('muted', !video.enabled);
    if (state.callActive && video.enabled) {
      try { await replaceOutgoingVideoTrack(video); } catch {}
    }
  });

  $('screen-share-btn')?.addEventListener('click', () => startScreenShare());

  window.addEventListener('beforeunload', () => {
    try { state.ws && state.ws.send(JSON.stringify({ type: 'leave' })); } catch {}
  });
})();
