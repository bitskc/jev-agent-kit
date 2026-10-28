const test = require('node:test');
const assert = require('node:assert/strict');
const { add } = require('../src/calc');

test('adds two positive numbers', () => {
  assert.equal(add(2, 3), 5);
});

test('adds a negative and a positive number', () => {
  assert.equal(add(-3, 5), 2);
});
