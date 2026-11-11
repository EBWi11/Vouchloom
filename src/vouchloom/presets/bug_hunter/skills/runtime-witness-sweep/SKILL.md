---
name: runtime-witness-sweep
description: Run one bounded single-variable sweep over an already constructed raw artifact using one existing bound executable and one explicit runtime witness. Use only after a clean vulnerable-target run leaves one source-backed scalar field, bitfield, or repeated-padding threshold as the earliest unproved row. Do not use for discovery, multiple variables, format guessing, builds, instrumentation repair, broad fuzzing, or choosing a vulnerability condition.
---

# Sweep One Runtime Witness

Use `/usr/local/bin/bug-hunter-witness-sweep` only for the active attempt
contract. Keep the carrier, target, and semantic route fixed.

Write one JSON plan containing:

- one existing `source` artifact and a new absolute `output` path;
- one `operation`: `write_uint`, `set_bits`, `write_ascii_uint`,
  `append_repeat`, or `insert_repeat`;
- unique explicit `values` or one inclusive `range` with at most 512 cases;
- one argument-vector `command` whose exact `{artifact}` element is replaced;
- one `match`: bounded exit codes, one literal `output_contains` witness, or both.

Use this exact plan shape; operation names belong in `operation.op`:

```json
{
  "source": "/work/prior.poc.bin",
  "output": "/work/poc.bin",
  "operation": {"op": "write_uint", "offset": 12, "width": 4, "endian": "little"},
  "range": {"start": 1, "stop": 64, "step": 1},
  "command": ["/work/target", "{artifact}"],
  "match": {"exit_codes": [1], "output_contains": "checkpoint", "mode": "all"}
}
```

Run the tool once with `--plan /tmp/witness-plan.json`. It never invokes a
shell, never builds a target, and stops at the first matching case or the total
time bound. If it reports `matched: true`, independently read back the changed
field, retain its receipt, and return `/work/poc.bin`. The match proves only the
named checkpoint; bind it to the corresponding Memory row.

If no case matches, do not emit an artifact. Record the tested range and leave
the downstream route intact; move the proof ladder to the earliest unproved row.
Never add a second variable, broaden the range, change the carrier, or reinterpret
an unrelated diagnostic inside this skill.
