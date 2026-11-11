---
name: libxml2-api-bytecode-carrier
description: Encode and independently decode one source-derived libxml2 API-fuzzer operation program. Use only when Core has uniquely bound the current libxml2 API opcode harness and one remaining construction gap blocks an otherwise source-backed route. Do not use for raw XML, HTML, reader, push-parser, XPath, XSLT, ambiguous targets, or vulnerability discovery.
---

# Libxml2 API Bytecode Carrier

Construct one minimal operation program for the exact checked-in API harness. This
skill converts a source-proven operation sequence into bytes; it does not choose a
new vulnerability route or infer an input grammar from a task description.

## Fail-closed admission

Before writing bytes, verify all of the following from the current disclosed source:

1. Core's current-source contract proves a byte cursor initializer, an
   input-exhaustion loop, one-byte opcode reads, a finite enum and switch dispatch,
   typed register files, operand readers, and termination behavior. Names and paths
   alone are not protocol evidence.
2. The bound harness input is that operation program, not a raw document, reader,
   push, HTML, XPath, or XSLT stream. An XML string may still be a source-proven
   operand of an API opcode.
3. The retained route names one source-backed operation sequence and construction is
   its only unresolved gap.

Stop and return the precise missing contract if an opcode is conditional or unknown,
an operand width is ambiguous, multiple decoders or targets remain possible, the
slot type cannot be proven, or the harness input contract itself is raw XML.
Never fill a gap using historical PoC bytes, another task, fixed source, or private
grader behavior.

## Encode one program

1. Record a compact table for the selected sequence: operation name, current enum
   value, operand width and endian, input slot types, output slot, and first guard.
2. Preserve the existing route and choose the shortest sequence that creates the
   required objects and reaches the named operation. Do not add unrelated API calls,
   broad mutations, random padding, or alternate vulnerability predicates.
3. Encode the program as `/work/poc.bin`. Derive every byte from the table and the
   current harness decoder. If the harness has an explicit terminator or reset, encode
   it exactly once where the decoder requires it.

## Mandatory independent readback

Decode `/work/poc.bin` with a small independent reader derived from the same current
source contract, but do not reuse the encoder's in-memory operation list as the
result. Verify:

- every opcode and operand boundary;
- decoded integer values and byte order;
- slot reads and writes, including type expectations;
- exact termination with no trailing undecoded bytes; and
- the first guard the decoded final operation would encounter if executed.

Report one receipt in this form:

```text
sha256 + size -> decoded operations and operands -> slot transitions -> first guard
```

A construction receipt proves only that the decoder consumed and round-tripped the
API program. “Accepted” means decoder consumption, not that the consumer ran or the
task is vulnerable.

## Execution and stopping rule

Run the official vulnerable target only when Core has already bound that exact
target. Keep its runtime result separate from local decoder readback. If the first
program is accepted but misses the retained operation, a second program may change
only one independently justified slot or operation-order relation. Stop after two
distinct, round-tripped programs remain authoritative-clean or fail to reach a
deeper retained checkpoint. Do not pivot to raw XML or another harness family.
