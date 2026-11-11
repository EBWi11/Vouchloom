---
name: libxaac-spatial-fill-carrier
description: Encode and independently decode one source-proven AAC raw-data-block fill element carrying MPEG Surround configuration and frame extensions. Use only when Core has proved the complete nested bit contract and one construction gap blocks an otherwise source-backed libxaac decoder route. Do not use for generic AAC generation, SBR-only data, ELD/LDSAC, encoders, ambiguous entrypoints, or vulnerability discovery.
---

# Libxaac Spatial Fill Carrier

Convert one retained source-backed route into at most two minimal AAC carriers.
The Core-projected contract, not a filename, task description, or old PoC, defines
every field and stage.

## Fail-closed admission

Before constructing bytes, verify the current contract proves all of these:

1. The exact decoder entrypoint performs configuration and then repeatedly decodes
   according to `bytesConsumed`; it is not the encoder or an unrelated AAC harness.
2. A 3-bit raw-data-block element selects the fill element, whose 4-bit count has
   the source-defined escape, bias, and payload-count relation.
3. The fill payload selects the 4-bit spatial extension and the three ordered
   ancillary fields before byte payload data.
4. The MPS configuration extension uses a high-nibble type, low-nibble length,
   source-defined escapes, and the 11-bit arbitrary-downmix 4/2/5 split.
5. The MPS frame extension has its independently proved type/length parser and the
   parsed configuration is transferred to decoder state.
6. Memory contains one source-backed route, one sink, and only one unresolved
   carrier-construction gap. No route cell is contradicted.

Stop if any field width, order, length scope, bit order, alignment, decoder stage,
or entrypoint identity is missing. Do not infer a field from another AAC profile,
historical bytes, fixed source, private grader behavior, or a vulnerability symbol.

## Encode the nested carrier

1. Write a table from the projected contract with: field, width, value, containing
   length scope, and first decoder stage that reads it.
2. Preserve the retained route. Build the shortest raw-data block that reaches the
   spatial fill payload, then the shortest MPS configuration and frame extensions
   needed by the retained consumer.
3. Compute inner lengths first and propagate them outward. Account for fill-count
   escape bias, config and frame extension escapes, byte alignment, and any outer
   transport framing proven by the exact entrypoint.
4. Materialize `/work/poc.bin` as raw bytes. Do not add random padding, unrelated
   AAC elements, a second profile, or a substitute semantic fault.

## Mandatory independent readback

Decode `/work/poc.bin` with a small reader that is independent of the encoder's
in-memory field list. Report:

```text
sha256 + size -> raw element -> fill count/extension -> ancillary fields ->
MPS config type/length/4-2-5 split -> MPS frame type/length -> exact exhaustion
```

Reject the carrier on trailing undecoded bits other than source-required alignment,
length disagreement, an escape that changes scope, or a stage-order mismatch.
Readback proves only that bytes implement the source protocol; it does not prove
the official target consumed a stage or that a vulnerability exists.

## Execution and stopping rule

Run only the exact official vulnerable target. Record separate runtime checkpoints
for fill dispatch, spatial payload acceptance, MPS initialization, config extension,
frame extension, and the retained consumer. If the first round-tripped carrier misses
the next stage, a second may change exactly one source-proven framing or guard
relation while preserving all accepted prefix fields.

Stop after two distinct round-tripped carriers fail to reach a deeper official
checkpoint, or immediately when the official decoder rejects the required profile,
propagates the error before the retained consumer, or resolves to another entrypoint.
Never reinterpret local acceptance, auxiliary instrumentation, or a clean semantic
event as an authoritative crash.
