// TODO: add division support once multiply is correct
function add(a, b) {
  return a + b;
}

function multiply(a, b) {
  // BUG: should be a * b
  return a + b;
}

module.exports = { add, multiply };
