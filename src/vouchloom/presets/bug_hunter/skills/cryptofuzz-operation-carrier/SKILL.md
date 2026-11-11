---
name: cryptofuzz-operation-carrier
description: Build and inspect the public Cryptofuzz binary Datasource envelope for operation-based targets such as cryptofuzz, cryptofuzz-sp-math, and library builds that embed Cryptofuzz with a forced module. Use when the bound runtime target is a Cryptofuzz executable and disclosed source or public framework definitions establish the operation and component field order. Do not use for a library's direct API fuzzer, TLS transcript, or when the operation payload schema is still unknown.
---

# Cryptofuzz operation carrier

Treat the Cryptofuzz driver as part of the input format. Do not transfer a
direct library fuzzer's controls or guess small enum values for operations.

## Public framing contract

On the x86 OSS-Fuzz builds, every Datasource read is framed as
`length:u32le || value[length]`, including fixed-width scalars. A fixed-width
read clamps the declared length to the C++ type width but still consumes the
four-byte prefix. The top-level stream is:

```text
frame(operation_id:u64le)
frame(serialized_operation_payload)
repeat {
  frame(modifier_bytes)
  frame(module_id:u64le)
  frame(continue:u8)
}
```

The final continuation is false. Operation and module identifiers are FNV-1a
64-bit hashes of `Cryptofuzz/Operation/<name>` and
`Cryptofuzz/Module/<name>`. A forced-module build still consumes the framed
module id before overriding its value.

The operation payload has its own Datasource starting at byte zero. `Buffer`
and decimal `Bignum` components are nested frames; `Type`, integers, and booleans
are also nested framed scalars. Bind their order from the applicable public or
disclosed `operations.h` constructor. Do not add an invented common header:
driver controls after the payload belong to modifier/module iteration, not to
the operation object.

Each execution modifier is another fresh Datasource. Prefer structured
`modifier_fields` over hand-written `modifier_hex` when public module source
binds its reads. A boolean modifier is therefore
`length:u32le(1) || value:u8`, not one bare byte. When the selected module is
`wolfCrypt-OpenSSL` and the operation is `HMAC`, read
[references/wolfcrypt-openssl.md](references/wolfcrypt-openssl.md).

## wolfCrypt backend binding

Treat each built Cryptofuzz executable as a separate runtime identity. Some
public OSS-Fuzz recipes build `cryptofuzz-sp-math-all` from wolfSSL configured
with `--enable-sp-math-all`, and also build `cryptofuzz-disable-fastmath` from a
separate wolfSSL tree configured with `--disable-fastmath`. Verify that mapping
in the checked-in recipe. For an SP-math-all build, trace the `mp_*` alias layer
into `sp_int.h` and `sp_int.c`, including `SP_WORD_SIZE`; for another build,
bind its generated options and selected implementation rather than transferring
the SP-math relation from the neighboring executable.

A clean execution on one of these targets does not arbitrate a source relation
that belongs to the other backend. Preserve the carrier schema, correct the
target/backend binding from the disclosed build, and only then revise operand
geometry or operation choice.

Keep a multiprecision integer's mathematical value separate from its internal
representation. Operations named `clamp` or `canonicalize` commonly trim zero
most-significant limbs and update the logical used-limb count; they are not
modular reduction. Track sign, used limbs, allocated capacity, digit width, and
limb contents through the selected backend. Before declaring a source change
numerically inert, inspect representation-sensitive consumers such as radix or
base conversion, byte-size calculation, serialization, export, and comparison.
Compare both the numeric result and the canonical representation those consumers
observe.

## Workflow

1. Verify the bound executable is Cryptofuzz and identify its build revision,
   enabled operation, forced module, architecture, and applicable public driver
   schema. Stop if only a library source function is known.
2. Write one JSON schema. For a `DH_Derive` constructor whose public order is
   prime, base, public value, private value, the generic shape is:

   ```json
   {
     "operation": "DH_Derive",
     "payload_fields": [
       {"type": "bignum", "value": "23"},
       {"type": "bignum", "value": "5"},
       {"type": "bignum", "value": "8"},
       {"type": "bignum", "value": "3"}
     ],
     "executions": [{"module": "wolfCrypt", "modifier_fields": []}]
   }
   ```

   `HMAC` uses the public constructor order `Cleartext`, `DigestType`, then
   `SymmetricCipher`, whose nested order is IV, key, and cipher type:

   ```json
   {
     "operation": "HMAC",
     "payload_fields": [
       {"type": "buffer", "value": "00"},
       {"type": "digest", "value": "SHA1"},
       {"type": "buffer", "value": ""},
       {"type": "buffer", "value": "00"},
       {"type": "cipher", "value": "AES_128_CBC"}
     ],
     "executions": [{"module": "wolfCrypt", "modifier_fields": []}]
   }
   ```

   The public `BignumCalc` binary constructor has used one symbolic `CalcOp`
   followed by four decimal `Bignum` components since the operation was
   introduced. Treat that order as the framework contract, not an illustrative
   field choice. Encode the operation name with `calcop`; do not substitute an
   enum position or reopen field-order variants merely because an external
   Cryptofuzz checkout is not vendored with the target project:

   ```json
   {
     "operation": "BignumCalc",
     "payload_fields": [
       {"type": "calcop", "value": "Add"},
       {"type": "bignum", "value": "2"},
       {"type": "bignum", "value": "3"},
       {"type": "bignum", "value": "0"},
       {"type": "bignum", "value": "0"}
     ],
     "executions": [{"module": "wolfCrypt", "modifier_fields": []}]
   }
   ```

   These examples document framework serialization only; select values from
   the task's source-backed constraint. Supported field types are `bignum`,
   `buffer`, `utf8`, `bool`, symbolic `calcop`, `digest`, and `cipher`, raw `type`,
   `u8/u16/u32/u64`, and `i8/i16/i32/i64`. For a source-proven nested
   component not covered by these primitives, provide its already serialized
   bytes as `payload_hex`; do not guess its layout.
3. Build atomically and inspect the same bytes:

   ```sh
   python /codex-home/skills/cryptofuzz-operation-carrier/scripts/cryptofuzz_carrier.py \
     build /work/schema.json /work/poc.bin
   python /codex-home/skills/cryptofuzz-operation-carrier/scripts/cryptofuzz_carrier.py \
     inspect /work/poc.bin --schema /work/schema.json
   ```

4. Require `operation_id_matches=true`, `executions_match=true`, the intended
   decoded payload fields, one false final continuation, and no trailing bytes.
   This is a construction receipt only. Core's bound vulnerable execution is
   still the authority for reachability and the fault.

An unresolved target build macro does not change this carrier framing. Once
Core has bound the Cryptofuzz target and public operation schema, materialize
one canonical carrier and let the unchanged target arbitrate the macro-dependent
fault. Do not rebuild with added backend or word-size macros before that first
execution.

If the public driver revision or operation constructor cannot be bound, return
that as the construction gap. Do not sweep operation IDs, module IDs, field
orders, or unrelated envelope variants.
