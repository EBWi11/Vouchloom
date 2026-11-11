---
name: graphicsmagick-nested-coder-search
description: Run one bounded original-target search for a GraphicsMagick coder fuzzer only after the current run has an authoritative clean outer-format carrier and has source-backed or runtime-observed a nested content-sniff dispatch from that carrier. Preserve the outer container and selected nested route. Do not use for target discovery, direct nested-coder drivers, unaccepted carriers, cross-format corpora, altered fuzz entries, or broad coder enumeration.
---

# Search One Bound Nested Coder Route

Fail closed unless the current run already proves all of these:

1. Core binds one original `coder_<FORMAT>_fuzzer` and its checked-in
   `coder_fuzzer.cc` entrypoint.
2. `/work/prior.poc.bin` is an authoritative clean candidate from that exact
   target and contains a source-backed outer container.
3. The outer reader reaches one nested `BlobToImage` or equivalent content-sniff
   dispatch. Memory names the selected nested route and its first accepted
   checkpoint; a list of possible coders is insufficient.
4. The search executable preserves the original fuzz entry, registered coder
   set, delegates, raw-input contract, and sanitizer family.

If one item is absent, return a typed handoff for that single gap. Do not replace
it with random bytes, a direct call to the nested decoder, another target, or a
host-installed GraphicsMagick build.

## Preserve the Outer Carrier

Run the unchanged target once on the accepted seed. Record the outer header,
table or offset fields that locate the nested blob, the nested dispatch actually
selected, and the deepest nested-reader checkpoint. Keep those structural bytes
and length relations in the corpus. A candidate that only changes the outer
format, selects another nested coder, or fails before the retained checkpoint is
not progress on this route.

Keep the original fuzz entry and project sources unchanged during search.
Instrumentation and direct-reader probes may explain a result, but they cannot
be the search executable or the submitted artifact.

## Run One Finite Original-Target Search

Place only current-route accepted outer carriers in a fresh `/work` corpus. Run
one foreground libFuzzer process with finite limits, for example:

```text
-max_total_time=300 -timeout=25 -rss_limit_mb=2048
-artifact_prefix=/work/nested-coder-search/
```

Use the checked-in maximum input length when present. Do not add a custom
mutator, multiple workers, another task's corpus, or seeds for unrelated outer
or nested formats. This search extends one already-proved delegation boundary;
it does not authorize broad vulnerability discovery.

If the exact executable is unavailable, allow one bounded rebuild from the
disclosed recipe under `/work`. Compare compiler and sanitizer flags, configured
delegates, fuzz-entry object, registered coder set, and linked libraries. Stop
on a failed dependency or identity check instead of repeatedly repairing the
environment.

## Accept Only a Stable Bound Result

For each produced crash artifact:

1. Re-run it three times on the unchanged search executable.
2. Require the same sanitizer family and stable first project frame.
3. Prove that the outer reader still reaches the retained nested dispatch and
   that the nested input bytes feed the reported operation.
4. Reject startup, harness, resource-only, unrelated coder, and outer-parser
   faults.
5. Minimize only after those checks, then independently read back the outer
   offsets, nested span, and selected coder checkpoint.

Return `/work/poc.bin` only after the minimized bytes reproduce on the unchanged
target. Core's official vulnerable execution remains authoritative. If the
bounded search finds no qualifying crash, record the executable identity, seed
digest, limits, final corpus count, and deepest checkpoint; do not submit the
last or highest-coverage input.
