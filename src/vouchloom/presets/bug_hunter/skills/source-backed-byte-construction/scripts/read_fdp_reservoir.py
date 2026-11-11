#!/usr/bin/env python3
"""Replay a declared head/tail FuzzedDataProvider consumption schema."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


def _count(value: Any, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")
    return value


def _integer(value: Any, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{name} must be an integer")
    return value


def _take_front(
    data: bytes, low: int, high: int, count: int
) -> tuple[bytes, list[int]]:
    consumed = min(count, high - low)
    return data[low : low + consumed], [low, low + consumed]


def _take_back(data: bytes, low: int, high: int, count: int) -> tuple[bytes, list[int]]:
    consumed = min(count, high - low)
    return data[high - consumed : high], [high - consumed, high]


def replay_schema(data: bytes, schema: dict[str, Any]) -> dict[str, Any]:
    operations = schema.get("operations")
    if not isinstance(operations, list):
        raise ValueError("schema.operations must be a list")
    low = 0
    high = len(data)
    receipt: list[dict[str, Any]] = []
    names: set[str] = set()
    for index, operation in enumerate(operations):
        if not isinstance(operation, dict):
            raise ValueError(f"operation {index} must be an object")
        op = operation.get("op")
        name = operation.get("name")
        if not isinstance(name, str) or not name or name in names:
            raise ValueError(f"operation {index} needs a unique non-empty name")
        names.add(name)
        before = [low, high]
        if op == "front_bytes":
            width = _count(operation.get("width"), f"{name}.width")
            raw, span = _take_front(data, low, high, width)
            low += len(raw)
            item: dict[str, Any] = {
                "name": name,
                "op": op,
                "edge": "front",
                "span": span,
                "raw_hex": raw.hex(),
                "requested_width": width,
                "consumed_width": len(raw),
                "complete": len(raw) == width,
            }
        elif op == "back_integral_range":
            minimum = _integer(operation.get("min"), f"{name}.min")
            maximum = _integer(operation.get("max"), f"{name}.max")
            type_width = _count(operation.get("type_width"), f"{name}.type_width")
            if maximum < minimum or type_width not in {1, 2, 4, 8}:
                raise ValueError(f"{name} has an invalid range or type width")
            value_range = maximum - minimum
            if value_range > (1 << (type_width * 8)) - 1:
                raise ValueError(f"{name} range does not fit its declared type width")
            width = min(type_width, (value_range.bit_length() + 7) // 8)
            raw, span = _take_back(data, low, high, width)
            high -= len(raw)
            raw_value = int.from_bytes(raw, "little")
            value = (
                minimum if value_range == 0 else minimum + raw_value % (value_range + 1)
            )
            item = {
                "name": name,
                "op": op,
                "edge": "back",
                "span": span,
                "raw_hex": raw.hex(),
                "raw_value": raw_value,
                "value": value,
                "range": [minimum, maximum],
                "requested_width": width,
                "consumed_width": len(raw),
                "complete": len(raw) == width,
            }
        elif op == "remaining_bytes":
            raw, span = _take_front(data, low, high, high - low)
            low = high
            item = {
                "name": name,
                "op": op,
                "edge": "front",
                "span": span,
                "raw_hex": raw.hex(),
            }
        else:
            raise ValueError(f"operation {name!r} has unsupported op {op!r}")
        item["reservoir_before"] = before
        item["reservoir_after"] = [low, high]
        receipt.append(item)
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "operations": receipt,
        "remaining_span": [low, high],
        "remaining_hex": data[low:high].hex(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--schema", required=True, type=Path)
    args = parser.parse_args()
    try:
        data = args.artifact.read_bytes()
        schema = json.loads(args.schema.read_text(encoding="utf-8"))
        result = replay_schema(data, schema)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        parser.error(str(error))
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
