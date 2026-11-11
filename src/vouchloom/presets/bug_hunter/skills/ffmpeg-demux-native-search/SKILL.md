---
name: ffmpeg-demux-native-search
description: Run one bounded coverage-guided search with an exact original FFmpeg per-demuxer fuzzer when a public uninitialized-value claim is bound to its outer demux path, an authoritative clean candidate and a current-run accepted outer-format carrier exist, one demuxer-to-consumer route is source-backed, and no vulnerable crash exists. A source-backed nested content probe remains part of the same unchanged outer target. Do not use for decoder, encoder, BSF, SWS, or generic demux targets; target discovery; broad vulnerability discovery; a direct nested fuzzer; an altered fuzz entry; a guessed or unrelated corpus; or after a build/equivalence gate fails.
---

# Search One Bound FFmpeg Demux Route

Fail closed unless all of these are already evidenced in the current run:

1. Core names one `ffmpeg_dem_<demuxer>_fuzzer`, and the disclosed build recipe
   binds that specialization to the original `tools/target_dem_fuzzer.c`.
2. The task claim retains an uninitialized-value producer, and Memory contains a
   source-backed demuxer-to-consumer route under that same outer target. The route
   may include a nested format or codec probe only when the selected demuxer's own
   header or packet path directly invokes that probe.
3. An executable preserves the original fuzz entry, forced input format, feature
   macros, linked libraries, raw-input transform, and sanitizer family.
4. `/work/prior.poc.bin` is a current-run carrier already accepted through the
   selected outer demuxer and into at least one packet or one source-backed nested
   callback. Never use another task's artifact or corpus.

If any item is absent, return a typed research handoff for that one item. Do not
replace it with random bytes, another format, a direct parser driver, or an
instrumented diagnostic executable.

## Preserve the Demux Harness Contract

Read back the exact target-dem envelope before searching. Separate container
bytes from any harness-owned filename, flags, interrupt, or I/O-control suffix.
Keep the selected outer demuxer, header grammar, stream table, packet loop, and
finalization path fixed. Execute the unchanged target once on the seed and record
the deepest demuxer callback reached. A forced top-level format may still perform
nested content probing from its own read path; retain that callback only with a
source-backed call edge from the selected outer demuxer. Reject a seed that reaches
only startup, an unbound generic probe, an unrelated nested format, or header
rejection. Never replace the outer target with a direct nested driver.

Keep the fuzz entry and demuxer source unchanged during the search. Added prints,
shadow tests, direct callbacks, or changed optimization are useful supporting
diagnostics but cannot be the search executable or authorize a candidate.

## Run One Bounded Search

Place only accepted current-route seeds in a fresh `/work` corpus. Run the exact
libFuzzer executable once with finite limits, for example:

```text
-max_total_time=300 -timeout=25 -rss_limit_mb=2048
-artifact_prefix=/work/native-demux-search/
```

Use the target's checked-in maximum length when present. Do not add an external
mutation script, a second fuzz process, an unbounded run, or a search over several
container formats. This tests whether the original sanitizer and coverage can
complete the already-bound header/table/packet relation; it does not select a new
fault.

If the exact executable is absent, allow one bounded rebuild from the disclosed
recipe under `/work`. Compare compiler, sanitizer flags, selected demuxer,
generated configuration, fuzz-entry object, raw-input suffix contract, and linked
archives before using it. On a missing dependency, changed component set, or
failed equivalence check, stop and hand off the single build-contract gap instead
of repairing the environment repeatedly.

## Accept or Close the Search

For a produced crash artifact:

1. Run it three times on the unchanged search executable.
2. Require the same sanitizer family and stable first fault frame.
3. Trace the report through the retained outer-demux route to its producer and
   downstream consumer, including any already bound nested probe callback; reject
   startup, generic I/O, harness, and unrelated format faults.
4. Minimize only after those checks, then independently read back the target-dem
   envelope and selected container checkpoints.
5. Return `/work/poc.bin` only after the minimized bytes reproduce on the unchanged
   executable. Core's official vulnerable execution remains authoritative.

If the bounded run finds no qualifying crash, record executable identity, seed
digests, limits, final corpus count, and deepest checkpoint. Do not submit the
last, largest, or highest-coverage input merely because the search ended. Return
a research handoff for the earliest missing format or observability relation.
