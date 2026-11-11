---
name: ffmpeg-target-dec-native-search
description: Run one bounded coverage-guided search with an exact original FFmpeg target_dec codec fuzzer when a public missing-slice or unwritten-frame claim is bound to that target, a sanitizer-equivalent executable and an accepted same-codec seed are available, construction remains open, and no vulnerable crash exists. Do not use for demuxer, encoder, BSF, or SWS targets; target discovery; broad vulnerability discovery; an altered fuzz entry; a guessed or cross-codec corpus; or after a build/equivalence gate fails.
---

# Search One Bound FFmpeg Decoder Route

Fail closed unless all of these are already evidenced in the current run:

1. Core names one `ffmpeg_AV_CODEC_ID_<codec>_fuzzer`, and the disclosed build
   recipe binds that specialization to the original `tools/target_dec_fuzzer.c`.
2. The task claim and active route retain the same missing-slice or unwritten-frame
   producer and one source-backed decoder or recovery consumer.
3. An executable preserves the original fuzz entry, codec configuration, feature
   macros, linked libraries, input transform, sanitizer family, and recovery flags.
4. `/work` contains at least one same-codec input already accepted past the codec
   header. Derive it from a disclosed fixture, checked-in test, or current-run
   construction; never import another task's corpus or artifact.

If any item is absent, return a typed research handoff for that one item. Do not
replace it with random bytes, another codec, or a modified diagnostic target.

## Preserve the Harness Contract

Read back the exact target-dec envelope before searching. Keep packet separators,
the final control block, extradata region, dimensions, flush pattern, and other
source-visible controls distinct from codec payload bytes. Execute the unchanged
target once on every seed and record the deepest parser or decoder checkpoint.
Reject seeds that only reach startup, generic packet rejection, or another codec.

Keep the fuzz entry and decoder source unchanged during the search. Instrumented
copies with added prints or altered allocation are useful research checkpoints but
are not search executables and cannot authorize a candidate.

## Run One Bounded Search

Place only the accepted same-route seeds in a fresh `/work` corpus. Run the exact
libFuzzer executable once with finite limits, for example:

```text
-max_total_time=300 -timeout=25 -rss_limit_mb=2048
-artifact_prefix=/work/native-search/
```

Use the target's checked-in maximum length when it exists. Do not add an external
mutation script, a second fuzz process, an unbounded run, or a search over control
and codec grammars that the current evidence has not separated. This run tests
whether the original sanitizer and coverage can discover a carrier for the already
bound producer-consumer relation; it does not select a new fault.

If the exact executable is absent, allow one bounded rebuild from the disclosed
recipe under `/work`. Compare compiler, sanitizer flags, codec enablement, generated
configuration, fuzz-entry object, and linked archives before using it. On a missing
dependency, changed component set, or failed equivalence check, stop and hand off the
single build-contract gap instead of repairing the environment repeatedly.

## Accept or Close the Search

For a produced crash artifact:

1. Run it three times on the unchanged search executable.
2. Require the same sanitizer family and stable first fault frame.
3. Trace the report to the retained unwritten allocation and decoder/recovery
   consumer; reject startup faults, harness faults, and unrelated codec sites.
4. Use libFuzzer's bounded crash minimization only after those checks, then read the
   final target-dec envelope and codec checkpoint back independently.
5. Return `/work/poc.bin` only after the minimized bytes reproduce on the unchanged
   executable. Core's official vulnerable execution remains authoritative.

If the bounded run finds no qualifying crash, record executable identity, seed
digests, limits, final corpus count, and deepest checkpoint. Do not submit the last,
largest, or highest-coverage input merely because the search ended. Return a research
handoff that moves the proof ladder to the earliest missing construction or
observability row.
