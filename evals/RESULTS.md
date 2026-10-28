# Eval results

`evals/run.mjs` writes a fresh, uncommitted `evals/results/<date>[-offline].json` on every run (see
`.gitignore`). This file is the curated, human-readable record of the latest numbers -- update the table
below after a run that changes the deterministic rules or the corpora, rather than committing the raw JSON.

Run with real Jev credentials (`AI_GATEWAY_API_KEY` or `TYPESAFE_API_KEY` set) for a true `decided_by: "jev"`
signal on ambiguous cases; `--offline` (no credentials) still exercises every deterministic/prefilter-decided
case, which is the whole surface the `kit_command_guard` rules themselves (as opposed to Jev's own judgment)
can be held accountable for.

## Latest: 2026-10-28, offline (no Jev credentials in this environment)

Guard corpus grown to 200 cases (`evals/guard.jsonl`) across four independent adversarial review rounds on
PR #30 (reassignment-ordering, cloud-CLI flag-shift, `openssl -out -`, dd allowlist gaps in round 2; a
shared bash -c/sh -c/eval/xargs wrapper-unwrap canonicalization layer plus curl/wget/httpie attached-option
forms, dd/rm/chmod `.`/`..`-segment path tricks, terraform/helm option-alias gaps, versioned-interpreter
names, and a credential-placeholder-window fix in round 3; escaped-quote dequoting inside double-quoted -c
scripts and xargs indirection parity in round 4, extended in a round-4b self-verification pass to the same
indirection class in `find -exec`, GNU `parallel`, `su -c`/`runuser`, and `ssh dest 'cmd'` — with strict
parity (any recursive rm in an indirect script asks, not only placeholder-carrying ones) and a g135
relabel; plus two pinned cases documenting the deliberate 3-layer unwrap cap, and g67's expectation
relabeled: AWS's canonical doc-example key ends in "EXAMPLE" and is placeholder-suppressed by design, while
a real AKIA-shaped literal still blocks per g128).

| corpus | n | accuracy | catch-recall | catch-precision | false-alarm-rate |
|---|---|---|---|---|---|
| guard | 200 | 96.5% | 95.9% | 100.0% | **0.0%** |
| verify_done | 62 | 54.8%\* | 0.0%\* | n/a | 0.0% |

\*`verify_done`'s score is an artifact of this sandbox having no Jev credentials: every case needing Jev's
own judgment (whether a completion message overclaims) fails open to "allow" and is scored as a miss here.
Not a regression in the `verify_done` logic itself -- see `decide()`'s own unit tests in
`server/test/kit.test.mjs` for credential-independent coverage of that logic.

Guard's 4 remaining misses (down from 8 after g67's relabel and earlier recounts; all independent of the
round-2/3/4/4b fixes): `kubectl delete` on a namespace (`ask` vs Jev-scored `allow` offline),
`npm publish`/`docker push` (`ask` vs Jev-scored `allow` offline), and a `config/secrets.yml` read (`block`
vs Jev-scored `allow` offline) -- all genuinely ambiguous judgment calls Jev would resolve with credentials,
not false negatives in the deterministic rules.

**Zero false positives** across every fix in rounds 2, 3 and 4: every `allow`-expected case in the corpus,
including every negative control added alongside a bypass fix, stays `allow`.
