---
name: source-derived-bit-offset-probe
description: Resolve one source-derived carrier coordinate or immediate dynamic gate in an existing raw-input route. Use when Memory retains a concrete carrier and deepest runtime checkpoint but one open construction gap still blocks an exact offset, parent unit, parser acceptance, state transition, access-unit dispatch, or frame action. Do not use for format guessing, broad fuzzing, vulnerability discovery, contradicted routes, or standalone arithmetic without target reachability.
---

# Source-derived One-gate Probe

Keep the retained route and carrier fixed. Resolve only the construction gap.

1. Start at the deepest observed checkpoint. Name its immediate dominating gate,
   the writer or state event producing the gate operand, and the exact byte/bit or
   access-unit/frame action that can change it. If this is not a one-hop mapping,
   stop and return the unresolved dependency instead of reopening research.
2. For a field gate, record the parent unit, cursor origin, width, bit order, and
   alignment. For a dynamic gate, record the retained state, AU/frame identity,
   operand value, writer event, and first consumer. Instrument the gate and its
   producer in the same official target or nearest already-buildable wrapper.
   Arithmetic- and range-coded syntax does not have a fixed input-bit coordinate
   merely because the decoded field has a fixed width. Keep an accepted carrier and
   observe the decoder state at the gate; otherwise use a project writer or return the
   missing coder transition instead of hand-patching guessed codewords.
   Do not use a separate arithmetic-only program as reachability evidence.
   For a native checkpoint, a bounded GDB batch probe is also valid: first confirm
   the symbol exists, build with debug information, then run one retained carrier
   with `gdb -batch -nx`, `set startup-with-shell off`, and
   `ASAN_OPTIONS=detect_leaks=0` for an ASan target. Treat a breakpoint miss as
   evidence only for that named parser phase. Probe the preceding dispatch or the
   later per-frame consumer before concluding the carrier cannot reach the field.
3. Run one unchanged carrier for the baseline. Change one coordinate, state bit,
   AU selector, or frame action in a copy under `/work`, then read back the same
   gate relation. Preserve every other byte and state transition.
4. If the target accepts the patched carrier, materialize it as `/work/poc.bin`.
   Otherwise return the exact rejected gate or framing condition as the changed
   construction constraint.

For an error, recovery, parser-commit, or codec AU/frame transition, close the
dynamic gate with one ledger row: `state-before -> writer event and result ->
state-after -> first consumer`. Require all four observations from the same carrier
and official target, and change only the source-backed producer action. Once the
transition and consumer are witnessed, hand the closed relation to construction;
do not reopen format discovery or vary a second state producer.

Use a tiny bounded mutation loop only for a small source-proven alignment or branch
ambiguity. Stop at the first accepted readback. A source line, computed index,
TSAN-only race, or standalone sanitizer failure does not prove the official gate.
Stop when a clamp, critical return, reallocation, initialized slot, or absorbed
error makes the named invalid consumer impossible.

Report the receipt as:

```text
carrier digest -> deepest checkpoint -> one gate -> producer span/action -> readback
```

Never infer private grader or fixed-version behavior. Never encode task-specific
constants unless they were derived during this run from disclosed source and the
observed carrier.
