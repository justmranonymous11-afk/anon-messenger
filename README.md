# Anon Messenger

An anonymous, end-to-end encrypted messenger with **text chat** and **audio/video calls** between two users. Telegram-style dark UI, no accounts, no logs, no persistence.

## Features

- **Text chat** over WebRTC `DataChannel`, with every message also wrapped in **AES-GCM 256** using a key derived from **ECDH P-256 → HKDF/SHA-256** between the two peers.
- **Audio & video calls** over WebRTC, natively encrypted by the browser with **DTLS-SRTP**.
- **Anonymous by design**: no signup, no phone number, no email. Just a 6-character room code.
- **Zero-knowledge server**: the Node.js signaling server only relays opaque WebRTC handshake payloads. It cannot decrypt messages or media.
- **No persistence**: rooms only live in server memory while the two peers are connected. Messages live only in the browser tab and are wiped on disconnect.
- **Safety number**: both peers see the same 24-digit safety number derived from the shared secret, so they can verbally verify they aren't being MITM'd.

## Run it

Requires **Node.js 18+**. **Zero dependencies** — no `npm install` needed.

```bash
cd anon-messenger
node server.js
```

Then open `http://localhost:4040` in two browser windows (or two devices on the same network using your LAN IP).

> If port `4040` is also taken, just pass a different one: `PORT=5050 node server.js`

1. In window A, click **Enter room** with the auto-generated code.
2. In window B, paste the same code and click **Enter room**.
3. Once you see the `🔒 Encrypted • Safety number: …` banner, your secure channel is up.
4. Type messages, or hit the phone/video icon to start a call.

## Run on two different networks (over the internet)

The signaling server only needs to be reachable by both peers. The simplest way:

- Run `npm start` on a small VPS, behind HTTPS (use Caddy/Traefik/nginx for TLS). The client auto-uses `wss://` when served over HTTPS.
- WebRTC needs **STUN** (already configured — Google's public STUN). For peers behind strict NATs, add a **TURN** server (e.g. Coturn) to the `iceServers` array in `public/app.js`.

> HTTPS is required for `getUserMedia` (mic/camera) to work on non-localhost origins. Localhost is exempt for development.

## Threat model & what this does/doesn't protect

**Protects against:**
- Server operator reading your chat or listening to calls (the server only sees encrypted handshake data).
- Network eavesdroppers (everything is TLS to the server, plus DTLS-SRTP and AES-GCM end-to-end).
- Replay or tampering of individual chat messages (AES-GCM provides integrity).
- Persistence-based subpoenas — there are no message logs to subpoena.

**Does NOT protect against:**
- Malicious endpoint (compromised browser, screen recorder, keylogger). E2E always assumes endpoints are trusted.
- Active MITM on your *very first connection* if you don't verify the safety number out-of-band. Always read the safety numbers to each other on the first call.
- Traffic analysis (an observer can see two IPs are talking to each other and how much, even if not what).
- Whoever shares your room code — anyone with the code can join (one-at-a-time limit, so you'd notice).

## Project structure

```
anon-messenger/
├── package.json
├── server.js            # Minimal Node.js signaling server (WebSocket + static files)
├── README.md
└── public/
    ├── index.html       # UI shell
    ├── styles.css       # Telegram-style dark theme
    └── app.js           # WebRTC + ECDH + AES-GCM client logic
```

## Notes

- Two users per room is a hard cap enforced server-side.
- The room is destroyed the moment both peers disconnect.
- You can share `http://your-host:4040/#YOURCODE` as a one-link join; the hash is filled into the room input automatically.
# anom-messenger
# anom-messenger
