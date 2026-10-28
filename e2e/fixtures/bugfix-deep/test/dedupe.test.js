const test = require('node:test');
const assert = require('node:assert/strict');
const { dedupeUsers } = require('../src/dedupe');

test('dedupes exact duplicate emails with different ids', () => {
  const users = [
    { id: 1, email: 'foo@bar.com' },
    { id: 2, email: 'foo@bar.com' },
  ];
  assert.equal(dedupeUsers(users).length, 1);
});

test('dedupes case-insensitive duplicate emails', () => {
  const users = [
    { id: 1, email: 'Foo@Bar.com' },
    { id: 2, email: 'foo@bar.com' },
  ];
  assert.equal(dedupeUsers(users).length, 1);
});

test('dedupes duplicate emails with surrounding whitespace', () => {
  const users = [
    { id: 1, email: '  foo@bar.com  ' },
    { id: 2, email: 'foo@bar.com' },
  ];
  assert.equal(dedupeUsers(users).length, 1);
});
