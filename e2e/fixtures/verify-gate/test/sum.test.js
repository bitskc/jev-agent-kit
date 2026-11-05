const test = require('node:test');
const assert = require('node:assert/strict');
const { sum } = require('../src/calc');

test('sums a list with a negative number', () => {
  assert.equal(sum([10, -3, 2]), 9);
});
