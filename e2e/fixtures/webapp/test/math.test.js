const test = require('node:test');
const assert = require('node:assert/strict');
const { add, multiply } = require('../src/math');

test('add works', () => {
  assert.equal(add(2, 3), 5);
});

test('multiply works', () => {
  assert.equal(multiply(2, 3), 6);
});
