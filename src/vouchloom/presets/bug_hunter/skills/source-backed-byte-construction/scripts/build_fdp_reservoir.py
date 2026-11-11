#!/usr/bin/env python3
"""Build and replay one declared FuzzedDataProvider reservoir schema."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from read_fdp_reservoir import replay_schema

MAX_ARTIFACT_BYTES = 10 * 1024 * 1024


def _count(value: Any, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")
    return value


def _integer(value: Any, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{name} must be an integer")
    return value


def _raw_hex(value: Any, name: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a hexadecimal string")
    try:
        return bytes.fromhex(value)
    except ValueError as error:
        raise ValueError(f"{name} must be valid hexadecimal") from error


def _remaining_payload(operation: dict[str, Any], name: str) -> bytes:
    choices = [key for key in ("raw_hex", "source", "fill_byte") if key in operation]
    if len(choices) != 1:
        raise ValueError(
            f"{name} must declare exactly one of raw_hex, source, or fill_byte"
        )
    choice = choices[0]
    if choice == "raw_hex":
        return _raw_hex(operation[choice], f"{name}.raw_hex")
    if choice == "source":
        source = operation[choice]
        if not isinstance(source, str) or not source:
            raise ValueError(f"{name}.source must be a non-empty path")
        return Path(source).read_bytes()
    fill = _integer(operation[choice], f"{name}.fill_byte")
    width = _count(operation.get("width"), f"{name}.width")
    if not 0 <= fill <= 0xFF:
        raise ValueError(f"{name}.fill_byte must fit one byte")
    return bytes([fill]) * width


def assemble_schema(schema: dict[str, Any]) -> tuple[bytes, dict[str, Any]]:
    """Assemble canonical front, reservoir, and reversed tail bytes."""

    operations = schema.get("operations")
    if not isinstance(operations, list):
        raise ValueError("schema.operations must be a list")
    front_parts: list[bytes] = []
    back_parts: list[bytes] = []
    remaining: bytes | None = None
    expected: dict[str, tuple[str, Any]] = {}
    names: set[str] = set()

    for index, operation in enumerate(operations):
        if not isinstance(operation, dict):
            raise ValueError(f"operation {index} must be an object")
        name = operation.get("name")
        if not isinstance(name, str) or not name or name in names:
            raise ValueError(f"operation {index} needs a unique non-empty name")
        names.add(name)
        op = operation.get("op")
        if op == "front_bytes":
            width = _count(operation.get("width"), f"{name}.width")
            raw = _raw_hex(operation.get("raw_hex"), f"{name}.raw_hex")
            if len(raw) != width:
                raise ValueError(
                    f"{name}.raw_hex has {len(raw)} bytes, expected {width}"
                )
            front_parts.append(raw)
            expected[name] = ("raw_hex", raw.hex())
        elif op == "back_integral_range":
            minimum = _integer(operation.get("min"), f"{name}.min")
            maximum = _integer(operation.get("max"), f"{name}.max")
            value = _integer(operation.get("value"), f"{name}.value")
            type_width = _count(operation.get("type_width"), f"{name}.type_width")
            if maximum < minimum or not minimum <= value <= maximum:
                raise ValueError(f"{name} has an invalid range or value")
            if type_width not in {1, 2, 4, 8}:
                raise ValueError(f"{name}.type_width must be 1, 2, 4, or 8")
            value_range = maximum - minimum
            if value_range > (1 << (type_width * 8)) - 1:
                raise ValueError(f"{name} range does not fit its declared type width")
            width = min(type_width, (value_range.bit_length() + 7) // 8)
            raw = (value - minimum).to_bytes(width, "little")
            back_parts.append(raw)
            expected[name] = ("value", value)
        elif op == "remaining_bytes":
            if remaining is not None:
                raise ValueError(
                    "schema may declare only one remaining_bytes operation"
                )
            remaining = _remaining_payload(operation, name)
            expected[name] = ("raw_hex", remaining.hex())
        else:
            raise ValueError(f"operation {name!r} has unsupported op {op!r}")

    data = b"".join(front_parts) + (remaining or b"") + b"".join(reversed(back_parts))
    if not data or len(data) > MAX_ARTIFACT_BYTES:
        raise ValueError(
            f"assembled artifact must contain 1..{MAX_ARTIFACT_BYTES} bytes"
        )
    receipt = replay_schema(data, schema)
    by_name = {item["name"]: item for item in receipt["operations"]}
    for name, (field, value) in expected.items():
        item = by_name[name]
        if item.get("complete") is False or item.get(field) != value:
            raise ValueError(f"assembled artifact failed readback for {name}")
    if receipt["remaining_span"][0] != receipt["remaining_span"][1]:
        raise ValueError("assembled artifact leaves undeclared reservoir bytes")
    return data, receipt


def build_schema(schema: dict[str, Any], output: Path) -> dict[str, Any]:
    """Atomically write the assembled bytes and return their replay receipt."""

    data, receipt = assemble_schema(schema)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + ".tmp")
    temporary.write_bytes(data)
    temporary.replace(output)
    return {
        **receipt,
        "output": str(output),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--schema", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        schema = json.loads(args.schema.read_text(encoding="utf-8"))
        result = build_schema(schema, args.output)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        parser.error(str(error))
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
