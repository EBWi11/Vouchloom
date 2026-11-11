---
name: source-backed-byte-construction
description: Deterministically assemble or patch one source-proven raw-input carrier. Use only after Core has bound the harness and retained a concrete fixture or an evidence-backed byte layout requiring exact bytes, repetition, integer fields, bitfields, lengths, CRC32, ASCII offsets, 32-bit word sums, spans, or zlib replacement. Do not use for discovery, format guessing, broad mutation, or choosing vulnerability constraints.
---

# Exact Byte Construction

Use `/usr/local/bin/bug-hunter-byte-patch` for fixed byte offsets. Use
`/usr/local/bin/bug-hunter-bitstream-build` for sequential bit fields, alignment,
nested length-delimited blocks, or one source-backed bit-span replacement. These
tools assemble bytes; they do not choose the layout or vulnerability constraint.

Write one small plan; offsets and half-open ranges apply after preceding edits:

```json
{
  "initial_size": 64,
  "output": "/work/poc.bin",
  "operations": [
    {"op": "write_uint", "offset": 8, "width": 4, "endian": "little", "value": "0x1000"}
  ]
}
```

Choose exactly one initial carrier: `source`, `initial_hex`, or `initial_size`.
Run the selected tool with `--plan /tmp/plan.json`, verify its JSON receipt, then
verify the planned size, offsets, and decoded fields locally.
Supported operations: `append_hex`,
`append_repeat`, `write_hex`, `insert_hex`, `replace_hex`, `insert_repeat`,
`write_uint`, `set_bits`, `write_length`, `write_crc32`, `write_ascii_uint`,
`write_word_sum32`, and `replace_zlib`.

For a sequential bitstream, write ordered `fields` with `type: field`, `bytes`,
`align`, or `block`. A block may declare a leading `length_field`; the builder
derives its bit or byte value from the encoded child content. To patch a fixture,
provide `source` and one half-open `replace` bit range. Keep the replacement width
unchanged unless the source-backed contract explicitly requires `resize: true`.
Treat the builder's field ranges and values as the independent readback receipt.

## Construction-ready closure

Close construction only after one table binds the carrier or fixture span, every
ordered field width and byte/bit order, alignment, directly dependent length or
checksum, and the named first consumer. When that table has no open coordinate,
stop reading source and designing variants. In the next shell action, write the
final `/work/poc.bin` and independently decode the same fields and dependencies.
Return one contradicted relation as a construction gap; after a consistent receipt,
stop. Do not rebuild a round-tripped artifact merely to shrink it, change its digest,
or explore another representation.

If Core retains a same-artifact runtime receipt for the named earliest invalid
consumer, preserve that artifact and report the construction receipt. Do not trade
an exact sink for a later crash. This skill never infers target execution from a
builder or readback receipt.

For a source-proven FuzzedDataProvider call order, declare its front-byte,
back-integral-range, and remaining-reservoir operations in JSON. Give each
`front_bytes` its exact `raw_hex`, each `back_integral_range` its source-proven
`min`, `max`, `type_width`, and decoded `value`, and `remaining_bytes` exactly
one of `raw_hex`, `source`, or `fill_byte` plus `width`. Then run:

```text
python /codex-home/skills/source-backed-byte-construction/scripts/build_fdp_reservoir.py --schema <schema> --output /work/poc.bin
```

The builder computes the provider's actual range-dependent integral width,
encodes it little-endian, reverses tail fields by consumption order, writes the
artifact atomically, and prints the replay receipt. Do not hand-order or
byte-swap those tail fields. For readback of an existing artifact only, run:

```text
python /codex-home/skills/source-backed-byte-construction/scripts/read_fdp_reservoir.py <artifact> --schema <schema>
```

Treat either output only as a reservoir span/value receipt; the scripts neither
search values nor select constraints.

Enter this skill only when Core's construction contract supplies the complete
sequential layout or one exact half-open byte or bit span. If neither is established,
do not build; return the missing parent unit, range, width, bit order, branch, or
alignment as a precise construction gap.

Prefer one edit to a real fixture. Assemble from zero only when the construction
contract contains the exact layout. When Core provides `/work/prior.poc.bin`, use it
only as the plan's `source`. First name the relation from
`construction_contract.must_satisfy`, then encode that relation and report the same
byte or action -> decoded value -> guard relation in `changed_constraint`. Never copy
or return the prior file unchanged.

In an artifact-only stage, the first shell call must create the final,
non-placeholder `/work/poc.bin`; do not inspect more source first. Core accepts a
valid persisted file receipt as terminal, so combine creation and any essential
local readback in that command. Stop after one valid receipt or one contradicted
constraint; never vary unrelated fields. A receipt proves construction only, not
reachability or vulnerability. Run a local harness only when an executable
harness is already available; never build or repair one solely for validation.
