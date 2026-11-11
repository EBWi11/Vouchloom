---
name: c-cpp-targeted-static-triage
description: Resolve one narrow C/C++ source property for the active attempt contract. Use only when Core has already bound one harness route, prior execution has not crashed, and must_satisfy names an initialization, bounds, size, lifetime, allocation, or ownership uncertainty. Do not use for discovery, first-pass source reading, broad scans, parser reconstruction, or build repair.
---

# Targeted Static Check

Treat `active_attempt_contract.must_satisfy` as the only question. If it does not
name a static property, skip this skill and continue normal source work.
For a Core evidence-arbitration turn whose public task claim explicitly names an
allocation failure or uninitialized value, use that named failure contract as
the single static question; do not replace it with a nearby safe allocation or
an unrelated downstream fault.

## Workflow

1. Name the one harness-reachable translation unit and preserve its real flags.
2. For an explicitly stated uninitialized-value task, audit one consumer operand
   before using a scanner:
   - treat initialization as storage provenance, not a byte pattern: bytes copied
     from the raw input are initialized even when nonzero, random, or located in
     logical padding, so they cannot stand in for sanitizer poison;
   - start from the exact expression read at the named sink;
   - follow the value backward through every field copy, constructor argument,
     wrapper, and alias to the earliest storage-defining write;
   - treat `destination = source` as a value-flow edge, not proof that `source`
     was initialized;
   - treat a call with an output pointer or reference the same way: follow the
     callee's field writes on each return and check whether the caller consumes the
     output while ignoring, replacing, or postponing its status result;
   - enumerate the predecessor exits that reach the copy, including lookup miss,
     partial decode, allocation failure, and early return, and require a dominating
     initializer or write on every one;
   - include allocations hidden inside macros and callees: after each such helper,
     couple its status or parser-state transition to every return value and output
     parameter before the caller advances or consumes them;
   - do not use an ASan-clean run, an explicit-value carrier, or a partial inventory
     of common constructors as negative proof; close every harness-reachable
     producer or use an equivalent MemorySanitizer execution for that exact route;
   - stop after the first source-visible path that can reach the read without such
     a write, and turn that path condition into the next input constraint.
3. For an explicitly stated allocation-failure task, audit every may-allocate
   operation inside the one named function before declaring the premise absent:
   - include direct allocators and resizers, but also parser/decoder macros and
     callees that can grow an input buffer or set an error state;
   - for each operation, couple its return value or parser-state transition to
     every scalar output, length, cursor advance, and caller-visible result used
     afterward;
   - a checked direct allocation or resize does not close the question while a
     transitive grow/fill helper can fail and leave another output undefined;
   - stop at the first unchecked failure-to-output edge and convert its public
     parser state or input boundary into the next construction constraint.
4. Otherwise run at most one suitable analyzer:
   - compile database: `clang-tidy -checks='-*,clang-analyzer-*' -p BUILD FILE`;
   - reproducible build: wrap its smallest target with `scan-build`;
   - single translation unit: use `clang --analyze` with its real flags;
   - use Cppcheck only as a quick independent check.
5. Keep only a finding that answers `must_satisfy` on the bound call path.
6. Convert it into one concrete input constraint, then return to construction.

Stop after one usable finding, one build-environment failure, or one clean result.
Never broaden scope or repair the project merely to make a scanner run. Scanner
output is supporting evidence, not reachability, a vulnerability, or a PoC.
