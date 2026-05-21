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
  const state = {
    ws: null,
    pc: null,                 // RTCPeerConnection
    dc: null,                 // RTCDataChannel for chat
    room: null,
    isInitiator: false,
    polite: false,            // perfect-negotiation role
    makingOffer: false,
    ignoreOffer: false,
    myKeyPair: null,
    sessionKey: null,
    safetyNumber: null,
    localStream: null,
    callType: null,
    callActive: false,
    callTimerStart: 0,
    callTimerInt: null,
    senders: [],              // local track senders
    // multi-chunk reassembly
    incomingBlobs: new Map(), // id -> { kind, dur, mime, total, chunks: [Uint8Array...] }
    // recording
    mediaRecorder: null,
    recordChunks: [],
    recordStart: 0,
    recordTimerInt: null,
    recordCancelled: false,
    // session profiles (never persisted)
    myProfile: { name: '', av: null },   // av: dataURL string or null
    peerProfile: { name: '', av: null },
  };

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
  async function encryptBytes(bytes) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, state.sessionKey, bytes);
    return { iv: buf2b64(iv), ct: buf2b64(ct) };
  }
  async function decryptBytes({ iv, ct }) {
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b642buf(iv) }, state.sessionKey, b642buf(ct));
    return new Uint8Array(pt);
  }
  async function encryptText(plaintext) { return encryptBytes(enc.encode(plaintext)); }
  async function decryptText(p) { return dec.decode(await decryptBytes(p)); }

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
      ws.onmessage = async (ev) => {
        let msg;
        try { msg = JSON.parse(ev.data); } catch { return; }
        try { await handleSignal(msg); } catch (e) { console.error(e); }
      };
      ws.onclose = () => setStatus('disconnected', false);
    });
  }

  function sendSignal(payload) {
    if (state.ws && state.ws.readyState === WebSocket.OPEN) {
      state.ws.send(JSON.stringify({ type: 'signal', payload }));
    }
  }

  async function handleSignal(msg) {
    switch (msg.type) {
      case 'joined':
        state.isInitiator = msg.initiator;
        state.polite = !msg.initiator;
        if (msg.peers === 1) {
          showSystemMessage('Waiting for the other person to join…');
          setStatus('waiting', false);
        }
        break;

      case 'ready':
        showSystemMessage('Peer joined. Establishing secure channel…');
        await startPeerConnection();
        break;

      case 'signal': {
        const p = msg.payload;
        if (!p || !state.pc) return;
        if (p.kind === 'description') {
          await onRemoteDescription(p.description);
        } else if (p.kind === 'ice' && p.candidate) {
          try { await state.pc.addIceCandidate(p.candidate); }
          catch (e) { if (!state.ignoreOffer) console.warn('ICE add failed', e); }
        } else if (p.kind === 'pubkey') {
          await onPeerPublicKey(p.key);
        }
        break;
      }

      case 'peer-left':
        showSystemMessage('Peer disconnected.');
        setStatus('disconnected', false);
        teardownCall();
        if (state.dc) try { state.dc.close(); } catch {}
        if (state.pc) try { state.pc.close(); } catch {}
        state.pc = null; state.dc = null; state.sessionKey = null;
        state.peerProfile = { name: '', av: null };
        applyPeerProfile(state.peerProfile);
        disableComposer();
        setBanner('Peer left. The session is closed.', 'warning');
        break;

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

  async function startPeerConnection() {
    const iceServers = await fetchIceServers();
    state.pc = new RTCPeerConnection({ iceServers });

    state.pc.onicecandidate = (e) => {
      if (e.candidate) sendSignal({ kind: 'ice', candidate: e.candidate });
    };

    state.pc.onconnectionstatechange = () => {
      const st = state.pc.connectionState;
      if (st === 'connected') setStatus('online', true);
      else if (st === 'failed' || st === 'disconnected' || st === 'closed') setStatus(st, false);
    };

    state.pc.ontrack = (e) => {
      const remoteVideo = $('remote-video');
      if (!remoteVideo.srcObject) remoteVideo.srcObject = new MediaStream();
      const ms = remoteVideo.srcObject;
      ms.getTracks().filter(t => t.kind === e.track.kind).forEach(t => ms.removeTrack(t));
      ms.addTrack(e.track);
    };

    // Perfect negotiation: this fires whenever local config changes (DC added, tracks added, etc.)
    state.pc.onnegotiationneeded = async () => {
      try {
        state.makingOffer = true;
        await state.pc.setLocalDescription();
        sendSignal({ kind: 'description', description: state.pc.localDescription });
      } catch (e) {
        console.error('negotiation error:', e);
      } finally {
        state.makingOffer = false;
      }
    };

    if (state.isInitiator) {
      const dc = state.pc.createDataChannel('chat', { ordered: true });
      setupDataChannel(dc);
      // creating the DC triggers onnegotiationneeded automatically
    } else {
      state.pc.ondatachannel = (ev) => setupDataChannel(ev.channel);
    }

    state.myKeyPair = await generateKeyPair();
    const pubB64 = await exportPublicKey(state.myKeyPair);
    sendSignal({ kind: 'pubkey', key: pubB64 });
  }

  async function onRemoteDescription(description) {
    const pc = state.pc;
    const offerCollision =
      description.type === 'offer' && (state.makingOffer || pc.signalingState !== 'stable');
    state.ignoreOffer = !state.polite && offerCollision;
    if (state.ignoreOffer) return;
    if (offerCollision) {
      // Polite peer: roll back so we can accept the incoming offer.
      await Promise.all([
        pc.setLocalDescription({ type: 'rollback' }).catch(() => {}),
        pc.setRemoteDescription(description),
      ]);
    } else {
      await pc.setRemoteDescription(description);
    }
    if (description.type === 'offer') {
      await pc.setLocalDescription();
      sendSignal({ kind: 'description', description: pc.localDescription });
    }
  }

  async function onPeerPublicKey(b64) {
    const peerPub = await importPeerPublicKey(b64);
    const { key, safetyNumber } = await deriveSessionKey(state.myKeyPair.privateKey, peerPub);
    state.sessionKey = key;
    state.safetyNumber = safetyNumber;
    setBanner(`Encrypted • Safety number: ${safetyNumber}`, 'ok');
    enableChatIfReady();
  }

  function setupDataChannel(dc) {
    state.dc = dc;
    dc.binaryType = 'arraybuffer';
    dc.bufferedAmountLowThreshold = 64 * 1024;
    dc.onopen = enableChatIfReady;
    dc.onclose = disableComposer;
    dc.onmessage = (ev) => onDcMessage(ev.data);
  }

  async function onDcMessage(data) {
    let msg;
    try { msg = JSON.parse(data); } catch { return; }
    try {
      switch (msg.t) {
        case 'msg': {
          const text = await decryptText(msg.p);
          renderMessage({ id: msg.id, kind: 'text', text }, 'in');
          return;
        }
        case 'sticker':
          renderMessage({ id: msg.id, kind: 'sticker', sticker: msg.s }, 'in');
          return;
        case 'audio': {
          const bytes = await decryptBytes(msg.p);
          const blob = new Blob([bytes], { type: msg.mime || 'audio/webm' });
          renderMessage({ id: msg.id, kind: 'audio', audioUrl: URL.createObjectURL(blob), duration: msg.dur }, 'in');
          return;
        }
        case 'msg-del':
          markMessageDeleted(msg.id);
          return;
        case 'blob-meta':
          state.incomingBlobs.set(msg.id, {
            kind: msg.kind, name: msg.name || '', dur: msg.dur, mime: msg.mime,
            total: msg.total, chunks: [],
          });
          return;
        case 'blob-chunk': {
          const entry = state.incomingBlobs.get(msg.id);
          if (!entry) return;
          const bytes = await decryptBytes(msg.p);
          entry.chunks[msg.idx] = bytes;
          return;
        }
        case 'blob-end': {
          const entry = state.incomingBlobs.get(msg.id);
          if (!entry) return;
          state.incomingBlobs.delete(msg.id);
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
            renderMessage({ id: msg.id, kind: 'audio', audioUrl: URL.createObjectURL(blob), duration: entry.dur }, 'in');
          } else if (entry.kind === 'file') {
            const url = URL.createObjectURL(blob);
            const isImage = (entry.mime || '').startsWith('image/');
            renderMessage({
              id: msg.id, kind: isImage ? 'image' : 'file',
              url, name: entry.name, mime: entry.mime, size: totalLen,
            }, 'in');
          }
          return;
        }
        case 'profile': {
          try {
            const plain = await decryptText(msg.p);
            const obj = JSON.parse(plain);
            applyPeerProfile({ name: String(obj.name || '').slice(0, 40), av: obj.av || null });
          } catch (e) { console.warn('Bad profile', e); }
          return;
        }
        case 'call-invite':
          showIncomingCall(msg.callType);
          return;
        case 'call-accept':
          onCallAccepted();
          return;
        case 'call-decline':
          onCallDeclined();
          return;
        case 'call-end':
          teardownCall();
          showSystemMessage('Call ended.');
          return;
      }
    } catch (e) { console.warn('DC handler error', e); }
  }

  function enableChatIfReady() {
    if (state.dc && state.dc.readyState === 'open' && state.sessionKey) {
      ['msg-input','send-btn','sticker-btn','attach-btn','mic-btn','audio-call-btn','video-call-btn']
        .forEach(id => { const el = $(id); if (el) el.disabled = false; });
      $('msg-input').focus();
      setStatus('online', true);
      sendMyProfile();
    }
  }
  function disableComposer() {
    ['msg-input','send-btn','sticker-btn','attach-btn','mic-btn','audio-call-btn','video-call-btn']
      .forEach(id => { const el = $(id); if (el) el.disabled = true; });
  }

  function dcSend(obj) {
    if (state.dc && state.dc.readyState === 'open') {
      state.dc.send(JSON.stringify(obj));
      return true;
    }
    return false;
  }

  // Send large bytes as encrypted chunks. onProgress(fraction 0..1) optional.
  async function dcSendBlob(kind, bytes, meta = {}, onProgress = null) {
    const id = randId();
    const total = Math.ceil(bytes.length / CHUNK_BYTES);
    dcSend({ t: 'blob-meta', id, kind, total, ...meta });
    for (let i = 0; i < total; i++) {
      const chunk = bytes.subarray(i * CHUNK_BYTES, (i + 1) * CHUNK_BYTES);
      const p = await encryptBytes(chunk);
      while (state.dc.bufferedAmount > 4 * 1024 * 1024) {
        await new Promise(r => setTimeout(r, 50));
      }
      dcSend({ t: 'blob-chunk', id, idx: i, p });
      if (onProgress) onProgress((i + 1) / total);
    }
    dcSend({ t: 'blob-end', id });
    return id;
  }

  function formatBytes(n) {
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
    return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
  }

  async function sendFiles(fileList) {
    if (!state.sessionKey) { toast('Not connected yet'); return; }
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
        await dcSendBlob('file', bytes, { name: file.name, mime: file.type || 'application/octet-stream' },
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
    if (!state.dc || state.dc.readyState !== 'open' || !state.sessionKey) return;
    const payload = JSON.stringify({
      name: state.myProfile.name || '',
      av: state.myProfile.av || null,
    });
    try {
      const p = await encryptText(payload);
      dcSend({ t: 'profile', p });
    } catch (e) { console.warn('profile send failed', e); }
  }

  function applyPeerProfile(prof) {
    state.peerProfile = prof;
    const nameEl = document.querySelector('.peer-name');
    const avEl = $('peer-avatar');
    const displayName = (prof.name && prof.name.trim()) ? prof.name.trim() : 'Anonymous peer';
    if (nameEl) nameEl.textContent = displayName;
    if (avEl) {
      if (prof.av) {
        avEl.style.backgroundImage = `url(${prof.av})`;
        avEl.style.backgroundSize = 'cover';
        avEl.style.backgroundPosition = 'center';
        avEl.textContent = '';
      } else {
        avEl.style.backgroundImage = '';
        avEl.textContent = (displayName[0] || '?').toUpperCase();
      }
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
    if (m.kind === 'text') {
      div.dataset.text = m.text;
      div.innerHTML = `${linkify(escapeHtml(m.text))}<span class="time">${nowTime()}</span>`;
    } else if (m.kind === 'sticker') {
      div.classList.add('sticker');
      div.innerHTML = `<div class="sticker-emoji">${escapeHtml(m.sticker)}</div><span class="time">${nowTime()}</span>`;
    } else if (m.kind === 'audio') {
      div.classList.add('audio');
      const waveBars = Array.from({ length: 22 }, () => '<span></span>').join('');
      div.innerHTML = `
        <button class="audio-play" type="button" aria-label="Play">
          <svg viewBox="0 0 24 24" width="18" height="18"><path fill="currentColor" d="M8 5v14l11-7z"/></svg>
        </button>
        <div class="audio-info">
          <div class="audio-waves">${waveBars}</div>
          <div class="audio-duration">${formatDuration(m.duration || 0)}</div>
        </div>
        <span class="time">${nowTime()}</span>`;
      wireAudioBubble(div, m.audioUrl, m.duration);
    } else if (m.kind === 'image') {
      div.classList.add('image');
      div.innerHTML = `
        <img src="${m.url}" alt="${escapeHtml(m.name || 'image')}" />
        <span class="time">${nowTime()}</span>`;
      const img = div.querySelector('img');
      img.addEventListener('click', () => window.open(m.url, '_blank'));
    } else if (m.kind === 'file') {
      div.classList.add('file');
      div.innerHTML = `
        <div class="file-icon">
          <svg viewBox="0 0 24 24" width="22" height="22"><path fill="currentColor" d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM6 4h7v5h5v11H6z"/></svg>
        </div>
        <div class="file-meta">
          <div class="file-name">${escapeHtml(m.name || 'file')}</div>
          <div class="file-size">${formatBytes(m.size || 0)}</div>
        </div>
        <a class="file-dl" href="${m.url}" download="${escapeHtml(m.name || 'file')}" title="Download">
          <svg viewBox="0 0 24 24" width="22" height="22"><path fill="currentColor" d="M12 3v12l4-4 1.4 1.4L12 17.8 6.6 12.4 8 11l4 4V3zM5 19h14v2H5z"/></svg>
        </a>`;
    } else if (m.kind === 'file-uploading') {
      div.classList.add('file');
      div.dataset.uploadId = m.id;
      div.innerHTML = `
        <div class="file-icon">
          <svg viewBox="0 0 24 24" width="22" height="22"><path fill="currentColor" d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM6 4h7v5h5v11H6z"/></svg>
        </div>
        <div class="file-meta">
          <div class="file-name">${escapeHtml(m.name || 'file')}</div>
          <div class="file-size">${formatBytes(m.size || 0)} • Sending…</div>
          <div class="file-progress" style="--p:0%"></div>
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
    dcSend({ t: 'msg-del', id });
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
    if (!text || !state.sessionKey) return;
    try {
      const id = randId();
      const p = await encryptText(text);
      dcSend({ t: 'msg', id, p });
      renderMessage({ id, kind: 'text', text }, 'out');
      input.value = '';
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
    if (!state.sessionKey) return;
    const id = randId();
    if (dcSend({ t: 'sticker', id, s })) {
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
    if (!state.sessionKey) return;
    const bytes = new Uint8Array(await blob.arrayBuffer());
    // Render locally first (instant feedback)
    const localUrl = URL.createObjectURL(blob);
    if (bytes.length <= CHUNK_BYTES) {
      const id = randId();
      const p = await encryptBytes(bytes);
      dcSend({ t: 'audio', id, dur: duration, mime: blob.type, p });
      renderMessage({ id, kind: 'audio', audioUrl: localUrl, duration }, 'out');
    } else {
      const id = await dcSendBlob('audio', bytes, { dur: duration, mime: blob.type });
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
    sendMyProfile();
    toast('Profile updated (session only)');
  });

  // ===========================================================
  // Join flow
  // ===========================================================
  $('gen-btn').addEventListener('click', () => { $('room-input').value = randCode(6); });

  if (location.hash && /^#[A-Za-z0-9]{4,12}$/.test(location.hash)) {
    $('room-input').value = location.hash.slice(1).toUpperCase();
  } else {
    $('room-input').value = randCode(6);
  }

  $('join-btn').addEventListener('click', async () => {
    const code = $('room-input').value.trim().toUpperCase();
    if (!/^[A-Z0-9]{4,12}$/.test(code)) { toast('Room code must be 4–12 letters/digits'); return; }
    state.room = code;
    state.myProfile = { name: ($('name-input').value || '').trim().slice(0, 40), av: null };
    location.hash = code;
    try {
      await connectSignaling();
      state.ws.send(JSON.stringify({ type: 'join', room: code }));
      showScreen('chat-screen');
      $('peer-avatar').textContent = code.charAt(0);
      $('peer-avatar').style.backgroundImage = '';
      document.querySelector('.peer-name').textContent = 'Anonymous peer';
      showSystemMessage(`Room "${code}" — anyone with this code (and only one other person) can join.`);
      setBanner('Verifying secure channel…', 'info');
      setStatus('connecting…', false);
    } catch { toast('Could not reach server'); }
  });

  $('back-btn').addEventListener('click', () => {
    if (!confirm('Leave this room? Messages will be deleted.')) return;
    cleanupAndReturn();
  });

  function cleanupAndReturn() {
    try { state.ws && state.ws.send(JSON.stringify({ type: 'leave' })); } catch {}
    try { state.ws && state.ws.close(); } catch {}
    try { state.dc && state.dc.close(); } catch {}
    try { state.pc && state.pc.close(); } catch {}
    teardownCall();
    Object.assign(state, {
      ws: null, pc: null, dc: null, room: null, isInitiator: false, polite: false,
      makingOffer: false, ignoreOffer: false,
      myKeyPair: null, sessionKey: null, safetyNumber: null,
      incomingBlobs: new Map(),
      myProfile: { name: '', av: null },
      peerProfile: { name: '', av: null },
    });
    $('messages').innerHTML = '';
    $('msg-input').value = '';
    $('name-input').value = '';
    disableComposer();
    $('sticker-panel').classList.add('hidden');
    closeProfileDialog();
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
    if (state.callActive) return;
    if (!state.dc || state.dc.readyState !== 'open') {
      toast('Peer not connected yet'); return;
    }
    try { state.localStream = await getMedia(type === 'video'); }
    catch { toast('Microphone/camera permission denied'); return; }
    state.callType = type;
    addLocalTracks();
    // onnegotiationneeded will fire automatically because addTrack() changed config.
    dcSend({ t: 'call-invite', callType: type });
    showCallOverlay(type, 'Ringing…');
  }

  function addLocalTracks() {
    if (!state.localStream || !state.pc) return;
    const localVideo = $('local-video');
    localVideo.srcObject = state.localStream;
    state.senders.forEach(s => { try { state.pc.removeTrack(s); } catch {} });
    state.senders = [];
    state.localStream.getTracks().forEach(track => {
      const sender = state.pc.addTrack(track, state.localStream);
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
    try { state.localStream = await getMedia(state.callType === 'video'); }
    catch { toast('Permission denied'); dcSend({ t: 'call-decline' }); return; }
    addLocalTracks();
    dcSend({ t: 'call-accept' });
    showCallOverlay(state.callType, 'Connected');
    startCallTimer();
    state.callActive = true;
  });

  $('decline-btn').addEventListener('click', () => {
    $('incoming-call').classList.add('hidden');
    dcSend({ t: 'call-decline' });
    state.callType = null;
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
    if (state.pc) {
      state.senders.forEach(s => { try { state.pc.removeTrack(s); } catch {} });
      state.senders = [];
    }
    const lv = $('local-video'); lv.srcObject = null;
    const rv = $('remote-video'); rv.srcObject = null;
    hideCallOverlay();
  }

  $('audio-call-btn').addEventListener('click', () => startCall('audio'));
  $('video-call-btn').addEventListener('click', () => startCall('video'));

  $('hangup-btn').addEventListener('click', () => {
    dcSend({ t: 'call-end' });
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
