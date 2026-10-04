/*
 * Anon — landing page motion.
 * Pure progressive enhancement: with JS off or reduced motion on, the page
 * shows its static content (including a static demo conversation).
 */
(() => {
  'use strict';

  window.__anonReveal = true;
  const root = document.documentElement;
  const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  // ---------- Scroll reveal ----------
  const reveals = document.querySelectorAll('.reveal');
  if (!root.classList.contains('js') || !('IntersectionObserver' in window)) {
    root.classList.remove('js');
  } else {
    const io = new IntersectionObserver((entries) => {
      let i = 0;
      for (const e of entries) {
        if (!e.isIntersecting) continue;
        e.target.style.transitionDelay = `${Math.min(i++, 6) * 70}ms`;
        e.target.classList.add('in');
        io.unobserve(e.target);
      }
    }, { rootMargin: '0px 0px -6% 0px', threshold: 0.06 });
    reveals.forEach((el) => io.observe(el));
  }

  if (reduce) return;

  // ---------- Cipher text helpers ----------
  const GLYPHS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
  const glyph = () => GLYPHS[(Math.random() * GLYPHS.length) | 0];
  const noise = (n) => Array.from({ length: n }, glyph).join('');

  // Reveal `text` left-to-right out of random glyphs.
  function decrypt(el, text, duration = 900) {
    const chars = Array.from(text);
    return new Promise((resolve) => {
      const start = performance.now();
      const frame = (now) => {
        const t = Math.min(1, (now - start) / duration);
        const shown = Math.floor(t * chars.length);
        el.textContent = chars
          .map((c, i) => (i < shown || c === ' ' ? c : glyph()))
          .join('');
        if (t < 1) requestAnimationFrame(frame);
        else { el.textContent = text; resolve(); }
      };
      requestAnimationFrame(frame);
    });
  }

  // ---------- Hero demo conversation ----------
  const msgs = document.getElementById('demo-msgs');
  const input = document.getElementById('demo-input');
  const status = document.getElementById('demo-status');
  const SCRIPT = [
    { dir: 'in',  text: 'hey — is this actually private?' },
    { dir: 'out', text: 'keys never leave our browsers 🔐' },
    { dir: 'in',  text: 'and the server?' },
    { dir: 'out', text: "only sees noise. close the tab and it's gone ✨" },
    { dir: 'in',  text: 'ok. call me 📞' },
  ];

  function bubble(dir, cls = '') {
    const b = document.createElement('div');
    b.className = `dm ${dir} ${cls}`.trim();
    msgs.appendChild(b);
    return b;
  }

  async function typeInto(text) {
    input.classList.add('typing');
    const chars = Array.from(text);
    for (let i = 1; i <= chars.length; i++) {
      input.textContent = chars.slice(0, i).join('');
      await sleep(28 + Math.random() * 40);
    }
    await sleep(260);
    input.classList.remove('typing');
    input.textContent = 'Write a message…';
  }

  async function playDemo() {
    for (;;) {
      msgs.innerHTML = '';
      await sleep(700);
      for (const m of SCRIPT) {
        if (m.dir === 'in') {
          status.textContent = 'typing…';
          const typing = bubble('in', 'typing');
          typing.innerHTML = '<i></i><i></i><i></i>';
          await sleep(1100);
          typing.remove();
          status.textContent = 'online · encrypted';
          const b = bubble('in', 'cipher-on');
          b.textContent = noise(Math.min(28, m.text.length));
          await sleep(350);
          b.classList.remove('cipher-on');
          await decrypt(b, m.text, 700);
        } else {
          await typeInto(m.text);
          bubble('out').textContent = m.text;
        }
        await sleep(900);
      }
      await sleep(2600);
      msgs.querySelectorAll('.dm').forEach((d) => d.classList.add('leaving'));
      await sleep(600);
    }
  }
  if (msgs && input && status) playDemo();

  // ---------- "Wire sees" ciphertext in the features grid ----------
  const wire = document.querySelector('.cipher-v.scramble');
  if (wire) {
    const len = wire.textContent.length;
    setInterval(() => {
      if (document.hidden) return;
      decrypt(wire, noise(len), 600);
    }, 2800);
  }
})();
