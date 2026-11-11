#!/usr/bin/env python3
"""Apply a bounded deterministic JSON byte-patch plan."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import zlib
from pathlib import Path
from typing import Any

MAX_ARTIFACT_BYTES = 10 * 1024 * 1024
MAX_OPERATIONS = 128


def _integer(value: Any, name: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError as error:
            raise ValueError(f"{name} is not a valid integer") from error
    raise ValueError(f"{name} must be an integer or integer string")


def _nonnegative(value: Any, name: str) -> int:
    result = _integer(value, name)
    if result < 0:
        raise ValueError(f"{name} must be nonnegative")
    return result


def _hex_bytes(value: Any, name: str = "data_hex") -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a hex string")
    try:
        return bytes.fromhex(value)
    except ValueError as error:
        raise ValueError(f"{name} is not valid hexadecimal") from error


def _span(operation: dict[str, Any], size: int) -> tuple[int, int]:
    start = _nonnegative(operation.get("start"), "start")
    end = _nonnegative(operation.get("end"), "end")
    if start > end or end > size:
        raise ValueError(f"invalid half-open range [{start}, {end}) for size {size}")
    return start, end


def _endian(operation: dict[str, Any]) -> str:
    endian = operation.get("endian")
    if endian not in {"little", "big"}:
        raise ValueError("endian must be little or big")
    return str(endian)


def _write(buffer: bytearray, offset: int, content: bytes) -> None:
    end = offset + len(content)
    if offset < 0 or end > len(buffer):
        raise ValueError(
            f"write range [{offset}, {end}) exceeds artifact size {len(buffer)}"
        )
    buffer[offset:end] = content


def _encoded_uint(value: int, width: int, endian: str) -> bytes:
    if width < 1 or width > 16:
        raise ValueError("integer width must be between 1 and 16 bytes")
    if value < 0 or value >= 1 << (8 * width):
        raise ValueError(f"unsigned value does not fit {width} bytes")
    return value.to_bytes(width, endian)


def _apply(buffer: bytearray, operation: dict[str, Any]) -> None:
    name = operation.get("op")
    if name == "append_hex":
        buffer.extend(_hex_bytes(operation.get("data_hex")))
        return
    if name == "append_repeat":
        count = _nonnegative(operation.get("count"), "count")
        pattern = _hex_bytes(operation.get("data_hex"))
        if not pattern or count < 1:
            raise ValueError("append_repeat requires nonempty data and positive count")
        if len(pattern) * count > MAX_ARTIFACT_BYTES - len(buffer):
            raise ValueError("repeated append exceeds the artifact limit")
        buffer.extend(pattern * count)
        return
    if name == "write_hex":
        _write(
            buffer,
            _nonnegative(operation.get("offset"), "offset"),
            _hex_bytes(operation.get("data_hex")),
        )
        return
    if name == "insert_hex":
        offset = _nonnegative(operation.get("offset"), "offset")
        if offset > len(buffer):
            raise ValueError("insert offset exceeds artifact size")
        buffer[offset:offset] = _hex_bytes(operation.get("data_hex"))
        return
    if name == "insert_repeat":
        offset = _nonnegative(operation.get("offset"), "offset")
        count = _nonnegative(operation.get("count"), "count")
        if offset > len(buffer):
            raise ValueError("insert offset exceeds artifact size")
        pattern = _hex_bytes(operation.get("data_hex"))
        if not pattern or count < 1:
            raise ValueError("insert_repeat requires nonempty data and positive count")
        if len(pattern) * count > MAX_ARTIFACT_BYTES - len(buffer):
            raise ValueError("repeated insertion exceeds the artifact limit")
        buffer[offset:offset] = pattern * count
        return
    if name == "replace_hex":
        start, end = _span(operation, len(buffer))
        buffer[start:end] = _hex_bytes(operation.get("data_hex"))
        return
    if name == "write_uint":
        offset = _nonnegative(operation.get("offset"), "offset")
        width = _nonnegative(operation.get("width"), "width")
        value = _nonnegative(operation.get("value"), "value")
        _write(buffer, offset, _encoded_uint(value, width, _endian(operation)))
        return
    if name == "set_bits":
        offset = _nonnegative(operation.get("offset"), "offset")
        width = _nonnegative(operation.get("width"), "width")
        endian = _endian(operation)
        bit_offset = _nonnegative(operation.get("bit_offset"), "bit_offset")
        bit_width = _nonnegative(operation.get("bit_width"), "bit_width")
        field_value = _nonnegative(operation.get("value"), "value")
        if bit_width < 1 or bit_offset + bit_width > 8 * width:
            raise ValueError("bit range is outside the integer field")
        if field_value >= 1 << bit_width:
            raise ValueError("bitfield value does not fit bit_width")
        current_bytes = bytes(buffer[offset : offset + width])
        if len(current_bytes) != width:
            raise ValueError("bitfield range exceeds artifact size")
        current = int.from_bytes(current_bytes, endian)
        mask = ((1 << bit_width) - 1) << bit_offset
        updated = (current & ~mask) | (field_value << bit_offset)
        _write(buffer, offset, _encoded_uint(updated, width, endian))
        return
    if name in {"write_length", "write_crc32"}:
        offset = _nonnegative(operation.get("offset"), "offset")
        start, end = _span(operation, len(buffer))
        endian = _endian(operation)
        if name == "write_length":
            width = _nonnegative(operation.get("width"), "width")
            value = end - start
        else:
            width = 4
            value = zlib.crc32(buffer[start:end]) & 0xFFFFFFFF
        _write(buffer, offset, _encoded_uint(value, width, endian))
        return
    if name == "write_ascii_uint":
        offset = _nonnegative(operation.get("offset"), "offset")
        width = _nonnegative(operation.get("width"), "width")
        value = _nonnegative(operation.get("value"), "value")
        pad = operation.get("pad", "0")
        if not isinstance(pad, str) or len(pad) != 1 or not pad.isascii():
            raise ValueError("pad must be one ASCII character")
        encoded = str(value).rjust(width, pad).encode("ascii")
        if len(encoded) != width:
            raise ValueError("ASCII integer does not fit width")
        _write(buffer, offset, encoded)
        return
    if name == "write_word_sum32":
        offset = _nonnegative(operation.get("offset"), "offset")
        start, end = _span(operation, len(buffer))
        endian = _endian(operation)
        content = bytes(buffer[start:end])
        content += bytes((-len(content)) % 4)
        value = (
            sum(
                int.from_bytes(content[index : index + 4], endian)
                for index in range(0, len(content), 4)
            )
            & 0xFFFFFFFF
        )
        if operation.get("complement_to") is not None:
            target = _nonnegative(operation.get("complement_to"), "complement_to")
            if target > 0xFFFFFFFF:
                raise ValueError("complement_to exceeds 32 bits")
            value = (target - value) & 0xFFFFFFFF
        _write(buffer, offset, _encoded_uint(value, 4, endian))
        return
    if name == "replace_zlib":
        start, end = _span(operation, len(buffer))
        level = _integer(operation.get("level", 9), "level")
        if not -1 <= level <= 9:
            raise ValueError("zlib level must be between -1 and 9")
        buffer[start:end] = zlib.compress(_hex_bytes(operation.get("data_hex")), level)
        return
    raise ValueError(f"unsupported operation: {name!r}")


def apply_plan(plan: dict[str, Any]) -> dict[str, Any]:
    output = Path(str(plan.get("output", "")))
    operations = plan.get("operations")
    source_value = plan.get("source")
    initial_hex = plan.get("initial_hex")
    initial_size = plan.get("initial_size")
    initial_choices = sum(
        item is not None for item in (source_value, initial_hex, initial_size)
    )
    if initial_choices != 1:
        raise ValueError("provide exactly one of source, initial_hex, or initial_size")
    if not output.is_absolute():
        raise ValueError("output must be an absolute path")
    if not isinstance(operations, list) or not operations:
        raise ValueError("operations must be a nonempty list")
    if len(operations) > MAX_OPERATIONS:
        raise ValueError(f"operation count exceeds {MAX_OPERATIONS}")
    if source_value is not None:
        source = Path(str(source_value))
        if not source.is_file():
            raise ValueError(f"source is not a readable file: {source}")
        content = source.read_bytes()
        source_receipt: str | None = str(source)
    elif initial_hex is not None:
        content = _hex_bytes(initial_hex, "initial_hex")
        source_receipt = None
    else:
        size = _nonnegative(initial_size, "initial_size")
        if size > MAX_ARTIFACT_BYTES:
            raise ValueError("initial_size exceeds the artifact limit")
        content = bytes(size)
        source_receipt = None
    if len(content) > MAX_ARTIFACT_BYTES:
        raise ValueError("initial content exceeds the artifact limit")
    buffer = bytearray(content)
    applied: list[str] = []
    for index, operation in enumerate(operations):
        if not isinstance(operation, dict):
            raise ValueError(f"operation {index} must be an object")
        _apply(buffer, operation)
        if not buffer or len(buffer) > MAX_ARTIFACT_BYTES:
            raise ValueError("result size is empty or exceeds the artifact limit")
        applied.append(str(operation.get("op")))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(buffer)
    return {
        "source": source_receipt,
        "output": str(output),
        "size": len(buffer),
        "sha256": hashlib.sha256(buffer).hexdigest(),
        "operations": applied,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        plan = json.loads(arguments.plan.read_text(encoding="utf-8"))
        if not isinstance(plan, dict):
            raise ValueError("plan must be a JSON object")
        receipt = apply_plan(plan)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(json.dumps({"error": str(error)}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
