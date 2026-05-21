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
 *   {t:'msg',      id, p:{iv,ct}}           encrypted text message
 *   {t:'msg-del',  id}                      delete a message by id (for both)
 *   {t:'sticker',  id, s}                   sticker (emoji string)
 *   {t:'audio',    id, dur, mime, p:{iv,ct}} encrypted audio blob (small)
 *   {t:'blob-meta', id, kind, name?, mime, total, dur?}   start of multi-chunk transfer
 *   {t:'blob-chunk', id, idx, p:{iv,ct}}    one encrypted chunk
 *   {t:'blob-end', id}                      end of multi-chunk transfer
 *   {t:'profile',  p:{iv,ct}}                encrypted JSON {name, av} (session-only)
 *   {t:'call-invite', callType}             requesting a call
 *   {t:'call-accept'} / {t:'call-decline'} / {t:'call-end'}
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

  // ---------- Application state ----------
  // Multi-peer mesh: state.peers is a Map<peerId, Peer>. For a 2-person chat,
  // it has one entry; for a group, up to 4 entries (MAX_PEERS - 1).
  const MAX_PEERS_TOTAL = 5;
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
    callType: null,
    callActive: false,
    callTimerStart: 0,
    callTimerInt: null,
    senders: [],
    // recording
    mediaRecorder: null,
    recordChunks: [],
    recordStart: 0,
    recordTimerInt: null,
    recordCancelled: false,
    // your session profile (broadcast to all peers, wiped on leave)
    myProfile: { name: '', av: null },
  };

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
    };
  }

  function peerCount() { return state.peers.size; }
  function isGroup() { return peerCount() >= 2; }
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
      ws.onclose = () => setStatus('disconnected', false);
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

  // Process signaling messages one at a time (SDP/ICE races break WebRTC).
  let signalInbox = Promise.resolve();
  let joinedReady = false;
  const preJoinQueue = [];

  function enqueueSignal(fn) {
    signalInbox = signalInbox.then(fn).catch((e) => console.error('[signal]', e));
    return signalInbox;
  }

  async function handleSignal(msg) {
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
          showSystemMessage(state.roomMode === 'group'
            ? 'Group room created. Waiting for others to join…'
            : 'Waiting for the other person to join…');
          setStatus('waiting', false);
        } else {
          showSystemMessage(`Connecting to ${existing.length} peer${existing.length>1?'s':''}…`);
          setStatus('connecting…', false);
          for (const peerId of existing) {
            // Symmetric initiator role: the lex-smaller id is impolite (initiates).
            // Both sides compute the same answer, so exactly one peer creates the DC.
            const weInitiate = state.myId < peerId;
            await ensurePeerConnection(peerId, weInitiate);
          }
        }
        updateHeaderForPeers();
        joinedReady = true;
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
        // 1-on-1 sync: both peers are in the room — (re)connect if needed.
        if (state.roomMode !== '1on1') break;
        const others = Array.isArray(msg.peers) ? msg.peers : [];
        for (const peerId of others) {
          if (peerId === state.myId) continue;
          const weInitiate = state.myId < peerId;
          await ensurePeerConnection(peerId, weInitiate);
        }
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
        break;
      }

      case 'error':
        toast(msg.error);
        break;
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
  ];

  async function fetchIceServers() {
    try {
      const res = await fetch('/api/turn', { cache: 'no-store' });
      if (!res.ok) return ICE_FALLBACK;
      const body = await res.json();
      const list = Array.isArray(body && body.iceServers) ? body.iceServers : null;
      return list && list.length ? list : ICE_FALLBACK;
    } catch {
      return ICE_FALLBACK;
    }
  }

  async function addRemoteIce(peer, candidate) {
    if (!peer.pc) return;
    if (!candidate) return; // end-of-candidates
    if (!peer.remoteDescSet) {
      peer.pendingCandidates.push(candidate);
      return;
    }
    try {
      await peer.pc.addIceCandidate(candidate);
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

  async function ensurePeerConnection(peerId, weInitiate) {
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
    state.peers.set(peerId, peer);

    const iceServers = await fetchIceServers();
    peer.pc = new RTCPeerConnection({ iceServers });

    peer.pc.onicecandidate = (e) => {
      if (e.candidate) sendSignal(peerId, { kind: 'ice', candidate: e.candidate });
    };

    peer.pc.onconnectionstatechange = () => {
      const st = peer.pc.connectionState;
      console.log(`[pc:${peerId}] connectionState=${st}`);
      if (st === 'connected') {
        setStatus('online', true);
        enableChatIfReady();
      } else if (st === 'failed') {
        setStatus('connection failed', false);
        setBanner('Connection failed — try leaving and rejoining the room.', 'warning');
        disableComposer();
      } else if (st === 'disconnected') {
        setStatus('reconnecting…', false);
      }
      updateHeaderForPeers();
    };
    peer.pc.oniceconnectionstatechange = () => {
      console.log(`[pc:${peerId}] iceConnectionState=${peer.pc.iceConnectionState}`);
    };

    peer.pc.ontrack = (e) => {
      console.log(`[pc:${peerId}] ontrack kind=${e.track.kind}`);
      // In 1-on-1 calls only (current implementation). Group video = future.
      if (peerCount() > 1) return;
      const remoteVideo = $('remote-video');
      if (!remoteVideo.srcObject) remoteVideo.srcObject = new MediaStream();
      const ms = remoteVideo.srcObject;
      ms.getTracks().filter(t => t.kind === e.track.kind).forEach(t => ms.removeTrack(t));
      ms.addTrack(e.track);
      // Force playback (audio elements with display:none still play audio,
      // but Safari is picky about autoplay until there's interaction).
      remoteVideo.play().catch(() => {});
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
    if (peer.ignoreOffer) return;
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

  async function onPeerPublicKey(peer, b64) {
    const peerPub = await importPeerPublicKey(b64);
    const { key, safetyNumber } = await deriveSessionKey(state.myKeyPair.privateKey, peerPub);
    peer.sessionKey = key;
    peer.safetyNumber = safetyNumber;
    updateSecurityBanner();
    enableChatIfReady();
    // RACE FIX: dc.onopen may have fired BEFORE the pubkey arrived, in which
    // case sendMyProfileTo would have returned early (no sessionKey). Now that
    // we DO have the session key, send the profile if it hasn't been sent yet.
    if (peer.dc && peer.dc.readyState === 'open' && !peer.profileSentToThem) {
      sendMyProfileTo(peer);
    }
  }

  function setupDataChannel(peer, dc) {
    peer.dc = dc;
    dc.binaryType = 'arraybuffer';
    dc.bufferedAmountLowThreshold = 64 * 1024;
    dc.onopen = () => {
      console.log(`[dc:${peer.id}] open`);
      enableChatIfReady();
      showSystemMessage('Secure channel ready — you can chat.');
      sendMyProfileTo(peer);
    };
    dc.onclose = () => { updateHeaderForPeers(); };
    dc.onmessage = (ev) => onDcMessage(peer, ev.data);
  }

  function updateSecurityBanner() {
    const connectedKeys = Array.from(state.peers.values()).filter(p => p.sessionKey).length;
    if (connectedKeys === 0) {
      setBanner('Verifying secure channel…', 'info');
    } else if (connectedKeys === peerCount()) {
      setBanner(`🔒 Encrypted with ${connectedKeys} peer${connectedKeys>1?'s':''}`, 'ok');
    } else {
      setBanner(`🔒 ${connectedKeys}/${peerCount()} peers encrypted…`, 'info');
    }
  }

  async function onDcMessage(peer, data) {
    let msg;
    try { msg = JSON.parse(data); } catch { return; }
    try {
      switch (msg.t) {
        case 'msg': {
          const text = await decryptText(peer.sessionKey, msg.p);
          renderMessage({ id: msg.id, kind: 'text', text, from: peer }, 'in');
          return;
        }
        case 'sticker':
          renderMessage({ id: msg.id, kind: 'sticker', sticker: msg.s, from: peer }, 'in');
          return;
        case 'audio': {
          const bytes = await decryptBytes(peer.sessionKey, msg.p);
          const blob = new Blob([bytes], { type: msg.mime || 'audio/webm' });
          renderMessage({ id: msg.id, kind: 'audio', audioUrl: URL.createObjectURL(blob), duration: msg.dur, from: peer }, 'in');
          return;
        }
        case 'msg-del':
          markMessageDeleted(msg.id);
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
          } else if (entry.kind === 'file') {
            const url = URL.createObjectURL(blob);
            const isImage = (entry.mime || '').startsWith('image/');
            renderMessage({
              id: msg.id, kind: isImage ? 'image' : 'file',
              url, name: entry.name, mime: entry.mime, size: totalLen, from: peer,
            }, 'in');
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
        case 'call-end':
          console.log('[call] received call-end from', peer.id);
          if (peer.id !== state.callPeerId) return;
          teardownCall();
          showSystemMessage('Call ended.');
          return;
      }
    } catch (e) { console.warn('DC handler error', e); }
  }

  // Any peer connected = chat is usable.
  function anyPeerReady() {
    for (const p of state.peers.values())
      if (p.dc && p.dc.readyState === 'open' && p.sessionKey) return true;
    return false;
  }

  function enableChatIfReady() {
    const ready = anyPeerReady();
    const composerIds = ['msg-input','send-btn','sticker-btn','attach-btn','mic-btn'];
    composerIds.forEach(id => { const el = $(id); if (el) el.disabled = !ready; });
    // Calls are only enabled in 1-on-1 mode AND when the one peer is connected.
    const callable = ready && state.roomMode === '1on1' && peerCount() === 1;
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
      setStatus('online', true);
      updateSecurityBanner();
    }
  }
  function disableComposer() {
    ['msg-input','send-btn','sticker-btn','attach-btn','mic-btn','audio-call-btn','video-call-btn']
      .forEach(id => { const el = $(id); if (el) el.disabled = true; });
  }

  // Send to a SPECIFIC peer's data channel (JSON).
  function dcSendTo(peer, obj) {
    if (peer.dc && peer.dc.readyState === 'open') {
      peer.dc.send(JSON.stringify(obj));
      return true;
    }
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
    return sent;
  }

  // Encrypt the same plaintext separately for each peer (pairwise keys),
  // then send the corresponding ciphertext to each peer.
  // Returns the number of peers we delivered to.
  async function dcBroadcastEncryptedText(plaintext, baseMessage) {
    let sent = 0;
    for (const peer of state.peers.values()) {
      if (!peer.sessionKey || !peer.dc || peer.dc.readyState !== 'open') continue;
      const p = await encryptText(peer.sessionKey, plaintext);
      dcSendTo(peer, { ...baseMessage, p });
      sent++;
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
        if (!peer.sessionKey || !peer.dc || peer.dc.readyState !== 'open') continue;
        while (peer.dc.bufferedAmount > 4 * 1024 * 1024) {
          await new Promise(r => setTimeout(r, 50));
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
          const isImage = (file.type || '').startsWith('image/');
          renderMessage({
            id: placeholderId, kind: isImage ? 'image' : 'file',
            url, name: file.name, mime: file.type, size: file.size,
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
        if (peer.dc && peer.dc.readyState === 'open' && peer.sessionKey) {
          peer.profileSentToThem = true;
        }
      }
      return sent;
    } catch (e) { console.warn('profile broadcast failed', e); }
  }

  async function sendMyProfileTo(peer) {
    if (!peer.dc || peer.dc.readyState !== 'open' || !peer.sessionKey) return;
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
      if (nameEl) nameEl.textContent = displayName;
      if (avEl) {
        if (peer.profile.av) {
          avEl.style.backgroundImage = `url(${peer.profile.av})`;
          avEl.style.backgroundSize = 'cover';
          avEl.style.backgroundPosition = 'center';
          avEl.textContent = '';
        } else {
          avEl.style.backgroundImage = '';
          avEl.textContent = (displayName[0] || '?').toUpperCase();
        }
      }
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
  // UI rendering
  // ===========================================================
  function showScreen(id) {
    document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
    $(id).classList.add('active');
  }
  function setStatus(text, online) {
    const el = $('peer-status');
    el.textContent = text;
    el.classList.toggle('online', !!online);
  }
  function setBanner(text, kind = 'info') {
    const b = $('security-banner');
    b.classList.remove('warning', 'info');
    if (kind === 'warning') b.classList.add('warning');
    else if (kind === 'info') b.classList.add('info');
    b.innerHTML = `<span class="lock">🔒</span><span>${escapeHtml(text)}</span>`;
  }
  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => ({
      '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
    }[c]));
  }
  function linkify(s) {
    return s.replace(/(https?:\/\/[^\s<]+)/g,
      '<a href="$1" target="_blank" rel="noopener noreferrer" style="color:#22E5C4;">$1</a>');
  }

  // Render a message bubble. `m` = { id, kind, text?, sticker?, audioUrl?, duration? }
  function renderMessage(m, direction) {
    const wrap = $('messages');
    const div = document.createElement('div');
    div.className = `bubble ${direction}`;
    div.dataset.id = m.id;
    div.dataset.kind = m.kind;
    // Sender label for group-mode incoming messages.
    let senderHeader = '';
    if (direction === 'in' && isGroup() && m.from) {
      const name = (m.from.profile.name || '').trim() || 'Anonymous';
      senderHeader = `<div class="sender">${escapeHtml(name)}</div>`;
    }
    if (m.kind === 'text') {
      div.dataset.text = m.text;
      div.innerHTML = `${senderHeader}${linkify(escapeHtml(m.text))}<span class="time">${nowTime()}</span>`;
    } else if (m.kind === 'sticker') {
      div.classList.add('sticker');
      div.innerHTML = `${senderHeader}<div class="sticker-emoji">${escapeHtml(m.sticker)}</div><span class="time">${nowTime()}</span>`;
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
          <span class="time">${nowTime()}</span>
        </div>`;
      wireAudioBubble(div, m.audioUrl, m.duration);
    } else if (m.kind === 'image') {
      div.classList.add('image');
      div.innerHTML = `
        ${senderHeader}
        <img src="${m.url}" alt="${escapeHtml(m.name || 'image')}" />
        <span class="time">${nowTime()}</span>`;
      const img = div.querySelector('img');
      img.addEventListener('click', () => window.open(m.url, '_blank'));
    } else if (m.kind === 'file') {
      div.classList.add('file');
      div.innerHTML = `
        ${senderHeader}
        <div class="file-row">
          <div class="file-icon">
            <svg viewBox="0 0 24 24" width="22" height="22"><path fill="currentColor" d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM6 4h7v5h5v11H6z"/></svg>
          </div>
          <div class="file-meta">
            <div class="file-name">${escapeHtml(m.name || 'file')}</div>
            <div class="file-size">${formatBytes(m.size || 0)}</div>
          </div>
          <a class="file-dl" href="${m.url}" download="${escapeHtml(m.name || 'file')}" title="Download">
            <svg viewBox="0 0 24 24" width="22" height="22"><path fill="currentColor" d="M12 3v12l4-4 1.4 1.4L12 17.8 6.6 12.4 8 11l4 4V3zM5 19h14v2H5z"/></svg>
          </a>
        </div>`;
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
    attachContextMenu(div, direction);
    wrap.appendChild(div);
    wrap.scrollTop = wrap.scrollHeight;
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

  function showSystemMessage(text) {
    const wrap = $('messages');
    const div = document.createElement('div');
    div.className = 'bubble system';
    div.textContent = text;
    wrap.appendChild(div);
    wrap.scrollTop = wrap.scrollHeight;
  }

  function markMessageDeleted(id) {
    const el = document.querySelector(`.bubble[data-id="${CSS.escape(id)}"]`);
    if (!el) return;
    el.classList.remove('sticker','audio');
    el.classList.add('deleted');
    el.innerHTML = `<span style="opacity:.7">message deleted</span><span class="time">${nowTime()}</span>`;
  }

  // ===========================================================
  // Context menu (right-click / long-press to delete)
  // ===========================================================
  const ctxMenu = $('ctx-menu');
  let ctxTargetEl = null;

  function attachContextMenu(bubble, direction) {
    if (bubble.classList.contains('system')) return;
    bubble.addEventListener('contextmenu', (e) => {
      e.preventDefault();
      openCtxMenu(bubble, e.clientX, e.clientY);
    });
    // Long-press for touch devices
    let pressTimer = null;
    bubble.addEventListener('touchstart', (e) => {
      pressTimer = setTimeout(() => {
        const t = e.touches[0];
        openCtxMenu(bubble, t.clientX, t.clientY);
      }, 500);
    }, { passive: true });
    bubble.addEventListener('touchend', () => clearTimeout(pressTimer));
    bubble.addEventListener('touchmove', () => clearTimeout(pressTimer));
  }

  function openCtxMenu(el, x, y) {
    ctxTargetEl = el;
    const mine = el.classList.contains('out');
    const isText = el.dataset.kind === 'text';
    $('ctx-delete-all').style.display = mine ? '' : 'none';
    $('ctx-copy').style.display = isText ? '' : 'none';
    ctxMenu.style.left = Math.min(x, window.innerWidth - 180) + 'px';
    ctxMenu.style.top = Math.min(y, window.innerHeight - 140) + 'px';
    ctxMenu.classList.remove('hidden');
  }
  function closeCtxMenu() { ctxMenu.classList.add('hidden'); ctxTargetEl = null; }
  document.addEventListener('click', (e) => {
    if (!ctxMenu.contains(e.target)) closeCtxMenu();
  });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeCtxMenu(); });

  $('ctx-delete-me').addEventListener('click', () => {
    if (!ctxTargetEl) return;
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

  $('ctx-copy').addEventListener('click', async () => {
    if (!ctxTargetEl) return;
    try {
      await navigator.clipboard.writeText(ctxTargetEl.dataset.text || ctxTargetEl.textContent);
      toast('Copied');
    } catch { toast('Copy failed'); }
    closeCtxMenu();
  });

  // ===========================================================
  // Chat send
  // ===========================================================
  $('composer').addEventListener('submit', async (e) => {
    e.preventDefault();
    const input = $('msg-input');
    const text = input.value.trim();
    if (!text || !anyPeerReady()) return;
    try {
      const id = randId();
      const sent = await dcBroadcastEncryptedText(text, { t: 'msg', id });
      if (sent > 0) {
        renderMessage({ id, kind: 'text', text }, 'out');
        input.value = '';
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
        if (!peer.sessionKey || !peer.dc || peer.dc.readyState !== 'open') continue;
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
  $('gen-btn').addEventListener('click', () => { $('room-input').value = randCode(6); });

  function roomFromUrl() {
    const hash = location.hash.replace(/^#/, '').toUpperCase();
    if (/^[A-Z0-9]{4,12}$/.test(hash)) return hash;
    const path = location.pathname.replace(/^\//, '').replace(/^@/, '').toUpperCase();
    if (/^[A-Z0-9]{4,12}$/.test(path)) return path;
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

  $('join-btn').addEventListener('click', async () => {
    const code = $('room-input').value.trim().toUpperCase();
    if (!/^[A-Z0-9]{4,12}$/.test(code)) { toast('Room code must be 4–12 letters/digits'); return; }
    state.room = code;
    state.roomMode = selectedMode;
    state.myProfile = { name: ($('name-input').value || '').trim().slice(0, 40), av: null };
    location.hash = code;
    try {
      await connectSignaling();
      state.ws.send(JSON.stringify({ type: 'join', room: code, mode: selectedMode }));
      showScreen('chat-screen');
      $('peer-avatar').textContent = code.charAt(0);
      $('peer-avatar').style.backgroundImage = '';
      document.querySelector('.peer-name').textContent =
        selectedMode === 'group' ? 'Group room' : 'Anonymous peer';
      applyMyProfile();
      const intro = selectedMode === 'group'
        ? `Group room "${code}" — up to 5 people can join.`
        : `Room "${code}" — private 1-on-1.`;
      showSystemMessage(intro);
      setBanner('Verifying secure channel…', 'info');
      setStatus('connecting…', false);
      updateModeIndicator();
      clearTimeout(state._connectTimeout);
      state._connectTimeout = setTimeout(() => {
        if (!anyPeerReady()) {
          setBanner('Still connecting… check both devices use the same room code.', 'warning');
          toast('Not connected yet — try refreshing both tabs');
        }
      }, 25000);
    } catch { toast('Could not reach server'); }
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

  function cleanupAndReturn() {
    try { state.ws && state.ws.send(JSON.stringify({ type: 'leave' })); } catch {}
    try { state.ws && state.ws.close(); } catch {}
    for (const peer of state.peers.values()) {
      try { peer.dc && peer.dc.close(); } catch {}
      try { peer.pc && peer.pc.close(); } catch {}
    }
    state.peers.clear();
    teardownCall();
    joinedReady = false;
    preJoinQueue.length = 0;
    signalInbox = Promise.resolve();
    clearTimeout(state._connectTimeout);
    Object.assign(state, {
      ws: null, myId: null, room: null,
      myKeyPair: null,
      myProfile: { name: '', av: null },
      callPeerId: null,
    });
    $('messages').innerHTML = '';
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
  // Calls (audio / video)
  // ===========================================================
  async function getMedia(video) {
    return navigator.mediaDevices.getUserMedia({
      audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true },
      video: video ? { width: { ideal: 1280 }, height: { ideal: 720 }, facingMode: 'user' } : false,
    });
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
      addLocalTracks(peer);
      console.log('[call] tracks added, awaiting renegotiation');
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
    showCallOverlay(type, 'Ringing…');
  }

  function addLocalTracks(peer) {
    if (!state.localStream || !peer.pc) return;
    const localVideo = $('local-video');
    localVideo.srcObject = state.localStream;
    state.senders.forEach(s => { try { peer.pc.removeTrack(s); } catch {} });
    state.senders = [];
    state.localStream.getTracks().forEach(track => {
      const sender = peer.pc.addTrack(track, state.localStream);
      state.senders.push(sender);
    });
  }

  function showCallOverlay(type, status) {
    $('call-overlay').classList.remove('hidden');
    $('call-status').textContent = status;
    $('local-video').style.display = (type === 'video') ? 'block' : 'none';
    $('remote-video').style.display = (type === 'video') ? 'block' : 'none';
  }

  function hideCallOverlay() {
    $('call-overlay').classList.add('hidden');
    $('call-status').textContent = '';
    $('call-timer').textContent = '';
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
    showCallOverlay(state.callType, 'Connected');
    startCallTimer();
    state.callActive = true;
  });

  $('decline-btn').addEventListener('click', () => {
    $('incoming-call').classList.add('hidden');
    const peer = state.callPeerId && getPeer(state.callPeerId);
    if (peer) dcSendTo(peer, { t: 'call-decline' });
    state.callType = null;
    state.callPeerId = null;
  });

  function onCallAccepted() {
    $('call-status').textContent = 'Connected';
    startCallTimer();
    state.callActive = true;
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
    clearInterval(state.callTimerInt);
    state.callTimerInt = null;
    state.callActive = false;
    state.callType = null;
    if (state.localStream) {
      state.localStream.getTracks().forEach(t => t.stop());
      state.localStream = null;
    }
    const peer = state.callPeerId && getPeer(state.callPeerId);
    if (peer && peer.pc) {
      state.senders.forEach(s => { try { peer.pc.removeTrack(s); } catch {} });
    }
    state.senders = [];
    state.callPeerId = null;
    const lv = $('local-video'); lv.srcObject = null;
    const rv = $('remote-video'); rv.srcObject = null;
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

  $('cam-btn').addEventListener('click', (e) => {
    if (!state.localStream) return;
    const video = state.localStream.getVideoTracks()[0];
    if (!video) return;
    video.enabled = !video.enabled;
    e.currentTarget.classList.toggle('muted', !video.enabled);
  });

  window.addEventListener('beforeunload', () => {
    try { state.ws && state.ws.send(JSON.stringify({ type: 'leave' })); } catch {}
  });
})();
