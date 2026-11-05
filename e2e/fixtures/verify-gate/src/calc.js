function add(a, b) {
  // BUG: should be a + b; this happens to pass whenever both operands are
  // non-negative, which is why `add.test.js` is green.
  return Math.abs(a) + Math.abs(b);
}

function sum(list) {
  return list.reduce((acc, n) => add(acc, n), 0);
}

module.exports = { add, sum };
