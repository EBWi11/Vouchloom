---
name: libxaac-native-msan-search
description: Run one bounded coverage-guided search with the exact original libxaac encoder fuzzer after the current run has a sanitizer-equivalent executable, an accepted current-run carrier, a runtime-observed encoder sink, and a still-open use-of-uninitialized-value condition. Do not use for target discovery, decoder targets, a modified fuzz entry, cross-task corpora, guessed seeds, broad vulnerability discovery, or after target/build equivalence fails.
---

# Search One Bound libxaac Encoder Route

Fail closed unless the current run already establishes all of these facts:

1. Core binds `xaac_enc_fuzzer` to the original checked-in encoder fuzz entry.
2. The public claim names a use of uninitialized state, and the retained route has
   reached its encoder consumer on the unchanged target or an equivalent MSan build.
3. The search executable preserves the disclosed compiler, sanitizer, feature
   macros, linked libraries, entrypoint, and FuzzedDataProvider transformation.
4. `/work` contains at least one current-run carrier accepted past encoder creation
   and into the retained consumer. Never use another task's artifact or corpus.

If any fact is missing, return a typed handoff for that one gap. Do not replace the
target, weaken MSan, add a diagnostic crash, or guess a carrier family.

## Preserve the Input Contract

Read back the seed using the checked-in FuzzedDataProvider order. Keep the config
tail, frame-loop controls, and PCM reservoir as separate byte domains. Execute the
unchanged target once and retain the deepest encoder checkpoint. Reject a seed that
only reaches config rejection, target startup, or a different codec path.

Keep the fuzz entry and encoder source unchanged during search. A print-instrumented
or manually altered binary is useful only for a checkpoint and cannot authorize the
candidate. If the exact executable is absent, permit one bounded rebuild from the
disclosed recipe under `/work`; stop on the first unresolved equivalence or dependency
gap.

## Run One Finite Search

Put only the accepted same-route current-run seeds in a fresh corpus directory. Run
one foreground libFuzzer process with finite limits, for example:

```text
-max_total_time=300 -timeout=25 -rss_limit_mb=2048
-artifact_prefix=/work/native-search/
```

Honor the checked-in maximum input length when present. Do not add a second worker,
an external random-mutation loop, cross-task data, or an unbounded campaign. This is
a test of the already bound encoder-state hypothesis, not permission to choose a new
fault family or sibling component.

## Qualify a Result

For each produced crash artifact:

1. Re-run it three times on the unchanged search executable.
2. Require stable MemorySanitizer use-of-uninitialized-value output and the retained
   libxaac encoder consumer or its already established caller chain.
3. Reject startup, allocation-exhaustion, harness, decoder, and unrelated encoder
   faults even if they exit nonzero.
4. Minimize only after those checks, then independently decode the config tail and
   frame reservoir and re-run the minimized bytes three times.
5. Copy the qualified bytes to `/work/poc.bin`; Core's official vulnerable execution
   remains the only authoritative result.

If no qualifying result appears, record executable identity, seed digests, limits,
final corpus size, and deepest checkpoint. Do not submit the last, largest, or
highest-coverage input. Return a research handoff to the earliest remaining state or
construction gap.
