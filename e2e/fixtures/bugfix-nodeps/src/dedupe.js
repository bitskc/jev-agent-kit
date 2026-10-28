// Removes duplicate users. Two users are "the same" if they have the same email
// (comparison should be case-insensitive and ignore surrounding whitespace).
function dedupeUsers(users) {
  const seen = new Set();
  const out = [];
  for (const u of users) {
    // BUG: dedupes by id, not by normalized email
    if (!seen.has(u.id)) {
      seen.add(u.id);
      out.push(u);
    }
  }
  return out;
}

module.exports = { dedupeUsers };
