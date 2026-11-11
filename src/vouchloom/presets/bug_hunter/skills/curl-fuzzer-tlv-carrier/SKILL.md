---
name: curl-fuzzer-tlv-carrier
description: Build, inspect, and deterministically materialize the public curl-fuzzer transfer-harness TLV carrier, including source-derived FTP control/data state plans. Use for curl_fuzzer and curl_fuzzer_* transfer targets whose raw input is the curl/curl-fuzzer big-endian TLV stream, especially when the project archive contains curl but not the external harness source. Do not use for direct fuzz_url, fuzz_fnmatch, fuzz_doh, or fuzz_bufq targets.
---

# curl-fuzzer TLV carrier

Treat the harness wrapper as part of the input format. Do not guess TLV ids or
encode arbitrary `CURLOPT_*` numbers as TLV types.

## Public carrier contract

Each record is `type:u16be || length:u32be || value[length]`. A truncated
header, an overlong value, or an unknown type rejects the stream before the
transfer. String TLVs carry raw bytes; the harness allocates its own trailing
NUL. Integer TLVs require exactly four big-endian value bytes.

The common ids below are stable in the public curl-fuzzer harness from at least
2019 through April 2024:

- `URL=1`, `RESPONSE0=2`, `USERNAME=3`, `PASSWORD=4`, `POSTFIELDS=5`,
  `HEADER=6`, `COOKIE=7`, `UPLOAD1=8`, `RANGE=9`, `CUSTOMREQUEST=10`.
- `MAIL_RECIPIENT=11`, `MAIL_FROM=12`, `MIME_PART=13`,
  `MIME_PART_NAME=14`, `MIME_PART_DATA=15`, `HTTPAUTH=16`.
- `RESPONSE1..RESPONSE10=17..26`, `OPTHEADER=27`, `NOBODY=28`,
  `FOLLOWLOCATION=29`, `ACCEPTENCODING=30`.
- `SECOND_RESPONSE0=31`, `SECOND_RESPONSE1=32`, `WILDCARDMATCH=33`.

Later public additions are append-only in the inspected versions. The bundled
tool also names the current public string and integer option ranges, including
`AWS_SIGV4=158`, but use a later id only when the task's build date, build
recipe, or disclosed wrapper supports it. In particular, a curl option with no
named TLV in the applicable public table is not controllable merely by placing
its numeric `CURLOPT_*` value in the type field.

`HEADER` and `MAIL_RECIPIENT` may repeat and append. Response records bind
numbered mock-socket slots. `RESPONSE0` is available when the first socket
connects; later responses are supplied as the socket becomes readable.
`SECOND_RESPONSE*` drives the second mock socket used by protocols such as FTP.
String and u32 option TLVs are singleton inputs; repeating one makes the public
harness reject the carrier rather than applying last-wins semantics.

## Workflow

1. Bind the exact target name from a Core runtime receipt. Load this carrier
   contract as soon as a transfer-harness target is bound, even when the first
   open gap is still the external wrapper or raw input boundary. Stop if it is a
   direct helper target rather than the transfer harness.
2. Inspect every available carrier before mutation:

   ```sh
   python /codex-home/skills/curl-fuzzer-tlv-carrier/scripts/curl_fuzzer_tlv.py inspect /work/prior.poc.bin
   ```

3. Construct the smallest complete transaction. Preserve protocol state across
   `RESPONSE*` slots and keep control/data sockets distinct. Example syntax:

   ```sh
   python /codex-home/skills/curl-fuzzer-tlv-carrier/scripts/curl_fuzzer_tlv.py build /work/poc.bin \
     --record URL utf8 'ftp://127.0.0.1/file' \
     --record RESPONSE0 hex '3232302072656164790d0a'
   ```

   Kinds are `utf8`, `hex`, `u32`, and `file`. Repeat `--record` to preserve
   record order.
4. Inspect the written artifact again. Require the intended names, lengths,
   response-slot order, `all_types_known=true`, and `all_records_valid=true`
   before executing it. `MIME_PART_NAME` and `MIME_PART_DATA` are nested records
   inside a `MIME_PART` value, not top-level records.
5. Run the Core-bound target. A local curl build or a hand-written socket driver
   is diagnostic only; it does not replace the official wrapper, option set, or
   mock-socket behavior.

## FTP state-machine check

For the exact `curl_fuzzer_ftp` target, do not treat syntactically valid replies
as a complete transaction. Read the applicable public harness and vulnerable
protocol source, then write one JSON plan that classifies every primary response
record exactly once:

```json
{
  "target": "curl_fuzzer_ftp",
  "protocol": "ftp",
  "control_steps": [
    {"record": "RESPONSE0", "phase": "greeting"},
    {"record": "RESPONSE1", "phase": "setup"},
    {"record": "RESPONSE2", "phase": "passive-ready"},
    {"record": "RESPONSE3", "phase": "transfer"}
  ],
  "data_record": "SECOND_RESPONSE0"
}
```

For a source-backed FTP wildcard route, a separate tool-free parameter extractor
receives only the retained Level 1 construction items. It returns one exact
pattern already present in a named construction item. Core verifies that
byte-for-byte grounding, supplies the canonical public FTP LIST state machine,
materializes the TLV, reads it back, and independently reruns `validate-ftp`.
Do not rebuild a direct helper, re-prove the sink, or continue broad source
navigation.

The deterministic wildcard command interface is:

```sh
python /codex-home/skills/curl-fuzzer-tlv-carrier/scripts/curl_fuzzer_tlv.py \
  materialize-ftp-wildcard /work/poc.bin /work/ftp-plan.json \
  --pattern 'name[abc]'
```

The example illustrates the parameter boundary only; it is not a task recipe.
The extractor may choose a pattern only when a current construction item states
it exactly. Invalid, ungrounded, or incomplete parameters leave no accepted
carrier. For non-wildcard FTP routes, continue using the general `materialize-ftp`
interface with a source-derived plan instead of this canonical LIST transaction.

Allowed phases are `greeting`, `setup`, `epsv-rejected`, `passive-ready`, and
`transfer`. Use the deterministic checker after the TLV readback:

```sh
python /codex-home/skills/curl-fuzzer-tlv-carrier/scripts/curl_fuzzer_tlv.py \
  validate-ftp /work/poc.bin /work/ftp-plan.json
```

The checker requires contiguous response slots, a 220 greeting, login and path
setup, transfer-mode setup after passive readiness, a non-empty second socket,
and a transfer preliminary reply followed by completion. In the public 2017
two-socket wrapper, an EPSV-only success is not a bound endpoint: the first
socket is a Unix socket pair, so the FTP state machine has no numeric control
peer address from which to form the EPSV data endpoint. Use the published
EPSV-rejection to PASV fallback (or the public `FTP_USE_EPSV=0` option) and a
valid numeric PASV tuple. The wrapper assigns the first opened socket to the
primary response array and the second opened socket to the secondary array;
its open-socket callback ignores the requested address and marks the socket
pair already connected. The canonical transaction relies only on that
module-level endpoint and ordinal mapping; another wrapper or socket callback
requires fresh source-backed proof. Do not cycle reply strings.

Choose URL paths, data rows, options, and protocol branches only from the
current Level 1 claim and disclosed vulnerable source. The checker supplies no
fixture, mutation, vulnerability predicate, or trigger value.

If the task requires a transfer option absent from the public wrapper, record
that harness reachability gap and rotate only to another source-backed producer
inside the same target. Do not sweep unknown type ids.
