# fixture-bugfix
`dedupeUsers(users)` should collapse users that share the same email address
(case-insensitive, ignoring leading/trailing whitespace), keeping the first
occurrence. There is a bug in `src/dedupe.js`.
