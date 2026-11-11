---
name: graphicsmagick-coder-native-search
description: Run one bounded coverage-guided search with an exact original GraphicsMagick coder fuzzer after the current run has an authoritative clean same-format carrier, a source-backed task fault sink, and an equivalent sanitizer build. Use for a direct coder route whose hand-built carrier reaches the retained reader or writer state but does not yet expose the fault. Do not use for target discovery, nested-coder substitution, cross-format corpora, altered fuzz entries, unaccepted carriers, or broad crash discovery.
---

# Search One Bound GraphicsMagick Coder Route

Fail closed unless the current run proves all of these:

1. Core binds one original `coder_<FORMAT>_fuzzer` and the checked-in
   `coder_fuzzer.cc` entrypoint.
2. Core has already executed `/work/prior.poc.bin` on that exact target and
   recorded an authoritative vulnerable-side clean result.
3. The carrier is accepted by the selected outer coder and Memory names one
   source-backed task producer or state plus its downstream fault sink. Parser
   acceptance, a list of possible coders, or a fault-family label is not enough.
4. The search executable preserves the original fuzz entry, selected coder,
   read-versus-read/write mode, registered delegates, raw-input contract,
   project revision, and sanitizer family.

If one item is absent, return a typed handoff for only that gap. Do not replace
it with random bytes, a direct call to a reader or writer, another coder target,
or a host-installed GraphicsMagick build.

## Verify the Existing Route

Run the unchanged target once on the accepted seed. Record the selected coder,
the deepest task-bound reader or writer checkpoint, and the first named fault
consumer. Preserve structural fields that keep that route active: header and
directory or chunk layout, dimensions, channel and alpha metadata, row or tile
geometry, compression, profiles, and any secondary write mode.

Instrumentation may explain whether the retained checkpoint is reached, but do
not branch on uninitialized data, bypass guards, change allocation behavior, or
use the instrumented binary as the search executable or submitted result.

## Run One Finite Original-Target Search

Place only current-run, same-format carriers that reached the retained
checkpoint in a fresh `/work` corpus. Run one foreground libFuzzer process with
finite limits, for example:

```text
-max_total_time=300 -timeout=25 -rss_limit_mb=2048
-artifact_prefix=/work/gm-coder-search/
```

Use the checked-in maximum input length when present. Do not add a custom
mutator, multiple workers, another task's corpus, cross-format seeds, or a
dictionary derived from private or fixed-side material.

If the exact executable is unavailable, allow one bounded rebuild from the
disclosed recipe under `/work`. Compare compiler and sanitizer flags, the
`FUZZ_GRAPHICSMAGICK_CODER` and write-mode defines, fuzz-entry object,
registered coder/delegate set, and linked libraries. Stop on a failed dependency
or identity check instead of repeatedly repairing the environment.

## Accept Only a Task-Bound Result

For each produced crash artifact:

1. Re-run it three times on the unchanged search executable.
2. Require the same sanitizer family and stable first project frame.
3. Prove that the same outer coder still reaches the retained task producer or
   state and that it directly feeds the named fault consumer.
4. Reject startup, harness, resource-only, unrelated coder, delegate-only, and
   adjacent reader or writer faults without that causal edge.
5. Minimize only after those checks, then independently read back the selected
   format, structural spans, and retained checkpoint.

Return `/work/poc.bin` only after the minimized bytes reproduce on the unchanged
target. Core's official vulnerable execution remains authoritative. If the
bounded search finds no qualifying crash, record the executable identity, seed
digest, limits, final corpus count, and deepest checkpoint; do not submit the
last or highest-coverage input.
