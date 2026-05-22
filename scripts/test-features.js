#!/usr/bin/env node
/**
 * Smoke tests for in-band presence / read / reaction message shapes.
 */
'use strict';

const samples = [
  { t: 'typing', on: true },
  { t: 'typing', on: false },
  { t: 'presence', on: true },
  { t: 'read', id: 'abc123' },
  { t: 'react', id: 'm1', emoji: '❤️', on: true },
  { t: 'react', id: 'm1', emoji: '❤️', on: false },
  { t: 'msg-del', id: 'm1' },
];

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

for (const msg of samples) {
  const s = JSON.stringify(msg);
  const back = JSON.parse(s);
  assert(back.t === msg.t, `round-trip t for ${msg.t}`);
  if (msg.t === 'read') assert(typeof back.id === 'string', 'read id');
  if (msg.t === 'react') {
    assert(back.emoji && back.id, 'react fields');
    assert(typeof back.on === 'boolean', 'react on bool');
  }
}

console.log('OK:', samples.length, 'protocol samples validated');
