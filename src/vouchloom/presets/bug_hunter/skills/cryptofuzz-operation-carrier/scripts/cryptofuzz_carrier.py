#!/usr/bin/env python3
"""Build and inspect public Cryptofuzz Datasource operation carriers."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
from pathlib import Path
from typing import Any

_FNV_OFFSET = 0xCBF29CE484222325
_FNV_PRIME = 0x100000001B3
_SCALARS: dict[str, tuple[str, int]] = {
    "u8": ("<B", 1),
    "u16": ("<H", 2),
    "u32": ("<I", 4),
    "u64": ("<Q", 8),
    "i8": ("<b", 1),
    "i16": ("<h", 2),
    "i32": ("<i", 4),
    "i64": ("<q", 8),
    "type": ("<Q", 8),
}
_SYMBOLIC_IDS = {
    "calcop": "CalcOp",
    "cipher": "Cipher",
    "digest": "Digest",
}


def fnv1a64(value: str) -> int:
    result = _FNV_OFFSET
    for byte in value.encode("utf-8"):
        result ^= byte
        result = (result * _FNV_PRIME) & 0xFFFFFFFFFFFFFFFF
    return result


def operation_id(name: str) -> int:
    return fnv1a64(f"Cryptofuzz/Operation/{name}")


def module_id(name: str) -> int:
    return fnv1a64(f"Cryptofuzz/Module/{name}")


def frame(value: bytes) -> bytes:
    if len(value) > 0xFFFFFFFF:
        raise ValueError("Cryptofuzz frame exceeds uint32 length")
    return struct.pack("<I", len(value)) + value


def _hex(value: Any, *, label: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a hexadecimal string")
    try:
        return bytes.fromhex(value)
    except ValueError as error:
        raise ValueError(f"{label} is not valid hexadecimal") from error


def _field_bytes(field: dict[str, Any]) -> bytes:
    kind = field.get("type")
    value = field.get("value")
    if kind == "bignum":
        if not isinstance(value, str) or re.fullmatch(r"-?[0-9]+", value) is None:
            raise ValueError("bignum value must be an ASCII decimal integer")
        raw = value.encode("ascii")
    elif kind == "buffer":
        raw = _hex(value, label="buffer value")
    elif kind == "utf8":
        if not isinstance(value, str):
            raise ValueError("utf8 value must be a string")
        raw = value.encode("utf-8")
    elif kind == "bool":
        if not isinstance(value, bool):
            raise ValueError("bool value must be true or false")
        raw = bytes([int(value)])
    elif kind in _SYMBOLIC_IDS:
        if not isinstance(value, str) or not value:
            raise ValueError(f"{kind} value must be a non-empty public name")
        raw = struct.pack("<Q", fnv1a64(f"Cryptofuzz/{_SYMBOLIC_IDS[kind]}/{value}"))
    elif kind in _SCALARS:
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError(f"{kind} value must be an integer")
        fmt, _ = _SCALARS[kind]
        try:
            raw = struct.pack(fmt, value)
        except struct.error as error:
            raise ValueError(f"{kind} value is out of range") from error
    else:
        raise ValueError(f"unsupported Cryptofuzz field type {kind!r}")
    return frame(raw)


def _schema_payload(schema: dict[str, Any]) -> bytes:
    fields = schema.get("payload_fields")
    payload_hex = schema.get("payload_hex")
    if fields is not None and payload_hex is not None:
        raise ValueError("choose payload_fields or payload_hex, not both")
    if payload_hex is not None:
        payload = _hex(payload_hex, label="payload_hex")
    else:
        if not isinstance(fields, list):
            raise ValueError("payload_fields must be a list")
        if not all(isinstance(item, dict) for item in fields):
            raise ValueError("each payload_fields item must be an object")
        payload = b"".join(_field_bytes(item) for item in fields)
    if not payload:
        raise ValueError("Cryptofuzz operation payload must contain at least one byte")
    return payload


def _execution_modifier(execution: dict[str, Any]) -> bytes:
    fields = execution.get("modifier_fields")
    modifier_hex = execution.get("modifier_hex")
    if fields is not None and modifier_hex is not None:
        raise ValueError("choose modifier_fields or modifier_hex, not both")
    if fields is not None:
        if not isinstance(fields, list) or not all(
            isinstance(item, dict) for item in fields
        ):
            raise ValueError("modifier_fields must be a list of objects")
        return b"".join(_field_bytes(item) for item in fields)
    return _hex(modifier_hex or "", label="modifier_hex")


def build_schema(schema: dict[str, Any]) -> bytes:
    operation = schema.get("operation")
    executions = schema.get("executions")
    if not isinstance(operation, str) or not operation:
        raise ValueError("operation must be a non-empty public Cryptofuzz name")
    if not isinstance(executions, list) or not executions:
        raise ValueError("executions must contain at least one module execution")

    payload = _schema_payload(schema)
    result = bytearray()
    result += frame(struct.pack("<Q", operation_id(operation)))
    result += frame(payload)
    for index, execution in enumerate(executions):
        if not isinstance(execution, dict):
            raise ValueError("each execution must be an object")
        module = execution.get("module")
        if not isinstance(module, str) or not module:
            raise ValueError("execution.module must be a non-empty public module name")
        modifier = _execution_modifier(execution)
        result += frame(modifier)
        result += frame(struct.pack("<Q", module_id(module)))
        result += frame(bytes([index + 1 < len(executions)]))
    return bytes(result)


def _take_frame(data: bytes, offset: int, *, label: str) -> tuple[bytes, int]:
    if len(data) - offset < 4:
        raise ValueError(f"{label} is missing its uint32 length")
    length = struct.unpack_from("<I", data, offset)[0]
    start = offset + 4
    end = start + length
    if end > len(data):
        raise ValueError(
            f"{label} declares {length} bytes with only {len(data) - start} available"
        )
    return data[start:end], end


def _decode_payload(
    payload: bytes, fields: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    decoded: list[dict[str, Any]] = []
    offset = 0
    for index, field in enumerate(fields):
        kind = field.get("type")
        raw, offset = _take_frame(payload, offset, label=f"payload field {index}")
        item: dict[str, Any] = {"index": index, "type": kind, "length": len(raw)}
        if kind in {"bignum", "utf8"}:
            try:
                item["value"] = raw.decode("ascii" if kind == "bignum" else "utf-8")
            except UnicodeDecodeError as error:
                raise ValueError(
                    f"payload field {index} is not valid {kind}"
                ) from error
        elif kind == "buffer":
            item["hex"] = raw.hex()
        elif kind == "bool":
            if len(raw) != 1:
                raise ValueError(f"payload bool field {index} is not one byte")
            item["value"] = bool(raw[0] % 2)
        elif kind in _SYMBOLIC_IDS:
            if len(raw) != 8:
                raise ValueError(f"payload {kind} field {index} is not eight bytes")
            item["value"] = field.get("value")
            item["id"] = struct.unpack("<Q", raw)[0]
        elif kind in _SCALARS:
            fmt, width = _SCALARS[kind]
            if len(raw) != width:
                actual = len(raw)
                raise ValueError(
                    f"payload {kind} field {index} is {actual} bytes, expected {width}"
                )
            item["value"] = struct.unpack(fmt, raw)[0]
        else:
            raise ValueError(f"unsupported Cryptofuzz field type {kind!r}")
        decoded.append(item)
    if offset != len(payload):
        raise ValueError(
            f"payload has {len(payload) - offset} unclaimed trailing bytes"
        )
    return decoded


def inspect_bytes(data: bytes, schema: dict[str, Any] | None = None) -> dict[str, Any]:
    offset = 0
    operation_raw, offset = _take_frame(data, offset, label="operation id")
    if len(operation_raw) != 8:
        raise ValueError("operation id frame must contain exactly eight bytes")
    observed_operation_id = struct.unpack("<Q", operation_raw)[0]
    payload, offset = _take_frame(data, offset, label="operation payload")
    if not payload:
        raise ValueError("operation payload is empty")

    executions: list[dict[str, Any]] = []
    terminated = False
    while offset < len(data):
        modifier, offset = _take_frame(data, offset, label="execution modifier")
        module_raw, offset = _take_frame(data, offset, label="execution module id")
        if len(module_raw) != 8:
            raise ValueError(
                "execution module id frame must contain exactly eight bytes"
            )
        continuation, offset = _take_frame(data, offset, label="execution continuation")
        if len(continuation) != 1:
            raise ValueError(
                "execution continuation frame must contain exactly one byte"
            )
        keep_going = bool(continuation[0] % 2)
        executions.append(
            {
                "module_id": struct.unpack("<Q", module_raw)[0],
                "modifier_hex": modifier.hex(),
                "continue": keep_going,
            }
        )
        if not keep_going:
            terminated = True
            break
    if not executions:
        raise ValueError("carrier has no module execution")
    if not terminated:
        raise ValueError("execution list has no false continuation terminator")
    if offset != len(data):
        raise ValueError(f"carrier has {len(data) - offset} bytes after termination")

    receipt: dict[str, Any] = {
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "operation_id": observed_operation_id,
        "payload_size": len(payload),
        "executions": executions,
        "canonical_frames": True,
    }
    if schema is not None:
        operation = schema.get("operation")
        expected_executions = schema.get("executions")
        if not isinstance(operation, str) or not isinstance(expected_executions, list):
            raise ValueError("schema requires operation and executions")
        receipt["operation"] = operation
        receipt["operation_id_matches"] = observed_operation_id == operation_id(
            operation
        )
        if "payload_fields" in schema:
            fields = schema["payload_fields"]
            if not isinstance(fields, list) or not all(
                isinstance(item, dict) for item in fields
            ):
                raise ValueError("payload_fields must be a list of objects")
            receipt["payload_fields"] = _decode_payload(payload, fields)
        elif "payload_hex" in schema:
            receipt["payload_hex_matches"] = payload == _hex(
                schema["payload_hex"], label="payload_hex"
            )
        if len(expected_executions) != len(executions):
            receipt["executions_match"] = False
        else:
            for expected, observed in zip(expected_executions, executions, strict=True):
                if isinstance(expected, dict) and "modifier_fields" in expected:
                    fields = expected["modifier_fields"]
                    if not isinstance(fields, list) or not all(
                        isinstance(item, dict) for item in fields
                    ):
                        raise ValueError("modifier_fields must be a list of objects")
                    observed["modifier_fields"] = _decode_payload(
                        bytes.fromhex(observed["modifier_hex"]), fields
                    )
            receipt["executions_match"] = all(
                isinstance(expected, dict)
                and isinstance(expected.get("module"), str)
                and observed["module_id"] == module_id(expected["module"])
                and observed["modifier_hex"] == _execution_modifier(expected).hex()
                for expected, observed in zip(
                    expected_executions, executions, strict=True
                )
            )
    return receipt


def _load_schema(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("schema root must be an object")
    return value


def _write_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(data)
    temporary.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build")
    build.add_argument("schema", type=Path)
    build.add_argument("output", type=Path)
    inspect = subparsers.add_parser("inspect")
    inspect.add_argument("artifact", type=Path)
    inspect.add_argument("--schema", type=Path)
    args = parser.parse_args()

    if args.command == "build":
        schema = _load_schema(args.schema)
        content = build_schema(schema)
        _write_atomic(args.output, content)
        receipt = inspect_bytes(content, schema)
        receipt["output"] = str(args.output)
    else:
        schema = _load_schema(args.schema) if args.schema is not None else None
        receipt = inspect_bytes(args.artifact.read_bytes(), schema)
        receipt["artifact"] = str(args.artifact)
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
