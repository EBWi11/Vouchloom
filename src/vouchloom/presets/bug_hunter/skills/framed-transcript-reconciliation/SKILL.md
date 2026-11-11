---
name: framed-transcript-reconciliation
description: Reconcile one existing length-framed carrier with one ordered runtime event stream from the same bound entrypoint. Use when Core supplies a concrete carrier, a source-backed sequential frame reader, and one typed framing or construction gap whose runtime frame order or offsets disagree with the decoded artifact. Do not use for target discovery, format guessing, broad transcript synthesis, unrelated protocol semantics, or a contradicted route.
---

# Reconcile One Framed Transcript

Keep the bound target, entrypoint, route, carrier, and first consumer fixed. Resolve
only the supplied framing gap.

1. Select exactly one Core-supplied carrier. Record its path, size, and SHA-256.
   Decode that exact file independently from byte zero through the source-backed
   frame reader. For every frame, record its ordinal, header half-open span,
   payload half-open span, declared length, decoded length, and terminal cursor.
   Stop on truncation, overlap, trailing bytes, or arithmetic inferred from a
   generator rather than read back from the file.
2. Observe one execution of the same digest through the bound entrypoint. Use an
   existing bound executable when available. Otherwise an instrumented build is
   auxiliary only: retain the exact entrypoint, raw-byte transform, source
   revision, and pre-consumer path, and do not promote it to official authority.
   Record frame ordinal, cursor before and after the read, returned span, and the
   immediate downstream event. Do not infer frame roles from remembered probe
   counts or from a different run.
3. Join the decoded and runtime tables by ordinal, then compare absolute spans and
   terminal cursors. The artifact digest, entrypoint, and frame count must agree.
   If any row differs, stop and return the first mismatching row as the changed
   framing constraint. Do not construct another transcript in that turn.
4. For the first consumer only, join one consumed frame ordinal and response span
   to one source-backed scalar checkpoint. Record the scalar name, width, decoded
   value, and first guard or state transition that consumes it. If that scalar
   cannot be attributed to one frame in the agreed table, stop at the missing join;
   do not search for a later sibling consumer.
5. Only after every consumed row and that scalar join agree, use the exact-byte
   construction skill to replace one source-backed frame or append one
   source-backed suffix. Read back the complete frame table and run the same bound
   entrypoint once. Preserve all earlier rows byte-for-byte.

Report the receipt as:

```text
artifact digest -> decoded frame table -> runtime frame table -> first mismatch
```

or, after agreement:

```text
artifact digest -> agreed prefix -> frame/response -> first scalar -> one changed frame -> complete readback
```

Never encode a task ID, vulnerability-specific bytes, private grader behavior, or
fixed-version behavior. A matching local table proves framing only; it does not
prove official reach, object materialization, the vulnerable consumer, or a crash.
