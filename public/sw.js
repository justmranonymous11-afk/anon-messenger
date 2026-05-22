/* Anon Messenger — service worker (push + open app) */
'use strict';

self.addEventListener('install', (e) => {
  e.waitUntil(self.skipWaiting());
});

self.addEventListener('activate', (e) => {
  e.waitUntil(self.clients.claim());
});

self.addEventListener('push', (e) => {
  let data = { title: 'Anon Messenger', body: 'New message', room: '' };
  try {
    if (e.data) data = { ...data, ...e.data.json() };
  } catch { /* ignore */ }
  const tag = data.room ? `room-${data.room}` : 'anon-msg';
  e.waitUntil(self.registration.showNotification(data.title || 'Anon Messenger', {
    body: data.body || 'New message',
    tag,
    icon: '/icon-192.svg',
    badge: '/icon-192.svg',
    data: { room: data.room || '' },
    renotify: true,
  }));
});

self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  const room = e.notification.data && e.notification.data.room;
  const url = room ? `/app#${room}` : '/app';
  e.waitUntil((async () => {
    const all = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const c of all) {
      if ('focus' in c) {
        await c.focus();
        c.postMessage({ type: 'open-room', room });
        return;
      }
    }
    if (self.clients.openWindow) await self.clients.openWindow(url);
    // Also try navigating an existing client to the room
    for (const c of all) {
      if ('navigate' in c) { await c.navigate(url); return; }
    }
  })());
});
