#!/usr/bin/env python3
"""Build or splice one bounded sequential bitstream from a JSON plan."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_ARTIFACT_BYTES = 10 * 1024 * 1024
MAX_NODES = 256
MAX_DEPTH = 8


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


def _name(value: Any, field: str = "name") -> str:
    if not isinstance(value, str) or not value or len(value) > 80:
        raise ValueError(f"{field} must be a nonempty string of at most 80 characters")
    if not value.isascii():
        raise ValueError(f"{field} must be ASCII")
    return value


def _hex_bytes(value: Any, name: str = "data_hex") -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a hex string")
    try:
        return bytes.fromhex(value)
    except ValueError as error:
        raise ValueError(f"{name} is not valid hexadecimal") from error


def _byte_bits(content: bytes, bit_order: str) -> list[int]:
    shifts = range(7, -1, -1) if bit_order == "msb0" else range(8)
    return [(byte >> shift) & 1 for byte in content for shift in shifts]


def _value_bits(value: int, width: int, bit_order: str) -> list[int]:
    if width < 1 or width > 64:
        raise ValueError("field width must be between 1 and 64 bits")
    if value < 0 or value >= 1 << width:
        raise ValueError(f"field value does not fit {width} bits")
    shifts = range(width - 1, -1, -1) if bit_order == "msb0" else range(width)
    return [(value >> shift) & 1 for shift in shifts]


def _bits_value(bits: list[int], bit_order: str) -> int:
    if bit_order == "msb0":
        value = 0
        for bit in bits:
            value = (value << 1) | bit
        return value
    return sum(bit << index for index, bit in enumerate(bits))


def _bits_bytes(bits: list[int], bit_order: str) -> bytes:
    if len(bits) % 8:
        raise ValueError("final bitstream must be byte-aligned")
    output = bytearray()
    for start in range(0, len(bits), 8):
        chunk = bits[start : start + 8]
        output.append(_bits_value(chunk, bit_order))
    return bytes(output)


@dataclass(frozen=True)
class _Field:
    name: str
    start_bit: int
    end_bit: int
    intended_value: int
    derived_from: str | None = None


class _Builder:
    def __init__(self, bit_order: str) -> None:
        self.bit_order = bit_order
        self.node_count = 0

    def render(
        self,
        nodes: Any,
        *,
        start_bit: int = 0,
        depth: int = 0,
        namespace: str = "",
    ) -> tuple[list[int], list[_Field]]:
        if depth > MAX_DEPTH:
            raise ValueError(f"bitstream nesting exceeds {MAX_DEPTH}")
        if not isinstance(nodes, list) or not nodes:
            raise ValueError("fields must be a nonempty list")
        bits: list[int] = []
        fields: list[_Field] = []
        for node in nodes:
            self.node_count += 1
            if self.node_count > MAX_NODES:
                raise ValueError(f"bitstream node count exceeds {MAX_NODES}")
            if not isinstance(node, dict):
                raise ValueError("each bitstream node must be an object")
            node_type = node.get("type")
            absolute_start = start_bit + len(bits)
            if node_type == "field":
                local_name = _name(node.get("name"))
                width = _nonnegative(node.get("width"), "width")
                value = _nonnegative(node.get("value"), "value")
                encoded = _value_bits(value, width, self.bit_order)
                bits.extend(encoded)
                fields.append(
                    _Field(
                        name=f"{namespace}{local_name}",
                        start_bit=absolute_start,
                        end_bit=absolute_start + width,
                        intended_value=value,
                    )
                )
                continue
            if node_type == "bytes":
                _name(node.get("name"))
                content = _hex_bytes(node.get("data_hex"))
                bits.extend(_byte_bits(content, self.bit_order))
                continue
            if node_type == "align":
                boundary = _nonnegative(node.get("boundary", 8), "boundary")
                fill = _nonnegative(node.get("value", 0), "value")
                if boundary < 1 or boundary > 64 or fill not in {0, 1}:
                    raise ValueError(
                        "alignment boundary must be 1..64 and value 0 or 1"
                    )
                padding = (-absolute_start) % boundary
                bits.extend([fill] * padding)
                continue
            if node_type == "block":
                block_name = _name(node.get("name"))
                child_namespace = f"{namespace}{block_name}."
                length_spec = node.get("length_field")
                length_width = 0
                if length_spec is not None:
                    if not isinstance(length_spec, dict):
                        raise ValueError("length_field must be an object")
                    length_width = _nonnegative(length_spec.get("width"), "width")
                child_bits, child_fields = self.render(
                    node.get("fields"),
                    start_bit=absolute_start + length_width,
                    depth=depth + 1,
                    namespace=child_namespace,
                )
                if length_spec is not None:
                    unit = length_spec.get("unit", "bytes")
                    if unit == "bytes":
                        if len(child_bits) % 8:
                            raise ValueError(
                                "a byte length field requires byte-aligned "
                                "block content"
                            )
                        length_value = len(child_bits) // 8
                    elif unit == "bits":
                        length_value = len(child_bits)
                    else:
                        raise ValueError("length_field unit must be bits or bytes")
                    length_value += _integer(length_spec.get("add", 0), "add")
                    if length_value < 0:
                        raise ValueError("derived length must be nonnegative")
                    encoded_length = _value_bits(
                        length_value, length_width, self.bit_order
                    )
                    bits.extend(encoded_length)
                    length_name = _name(length_spec.get("name"), "length_field.name")
                    fields.append(
                        _Field(
                            name=f"{child_namespace}{length_name}",
                            start_bit=absolute_start,
                            end_bit=absolute_start + length_width,
                            intended_value=length_value,
                            derived_from=f"{child_namespace}content",
                        )
                    )
                bits.extend(child_bits)
                fields.extend(child_fields)
                continue
            raise ValueError(f"unsupported bitstream node type: {node_type!r}")
        return bits, fields


def _readback(
    content: bytes,
    fields: list[_Field],
    bit_order: str,
) -> list[dict[str, Any]]:
    bits = _byte_bits(content, bit_order)
    receipt: list[dict[str, Any]] = []
    for field in fields:
        actual = _bits_value(bits[field.start_bit : field.end_bit], bit_order)
        if actual != field.intended_value:
            raise ValueError(f"readback mismatch for field {field.name}")
        item: dict[str, Any] = {
            "name": field.name,
            "start_bit": field.start_bit,
            "end_bit": field.end_bit,
            "width": field.end_bit - field.start_bit,
            "value": actual,
        }
        if field.derived_from is not None:
            item["derived_from"] = field.derived_from
        receipt.append(item)
    return receipt


def apply_plan(plan: dict[str, Any]) -> dict[str, Any]:
    output = Path(str(plan.get("output", "")))
    if not output.is_absolute():
        raise ValueError("output must be an absolute path")
    bit_order = plan.get("bit_order", "msb0")
    if bit_order not in {"msb0", "lsb0"}:
        raise ValueError("bit_order must be msb0 or lsb0")

    source_value = plan.get("source")
    replace = plan.get("replace")
    if (source_value is None) != (replace is None):
        raise ValueError("source and replace must be provided together")
    builder = _Builder(str(bit_order))
    built_bits, fields = builder.render(plan.get("fields"))
    source_receipt: str | None = None
    if source_value is not None:
        source = Path(str(source_value))
        if not source.is_file():
            raise ValueError(f"source is not a readable file: {source}")
        if not isinstance(replace, dict):
            raise ValueError("replace must be an object")
        start_bit = _nonnegative(replace.get("start_bit"), "start_bit")
        end_bit = _nonnegative(replace.get("end_bit"), "end_bit")
        source_bits = _byte_bits(source.read_bytes(), str(bit_order))
        if start_bit > end_bit or end_bit > len(source_bits):
            raise ValueError("replace range is outside the source bitstream")
        fixed_width = replace.get("resize", False) is not True
        if fixed_width and len(built_bits) != end_bit - start_bit:
            raise ValueError(
                "replacement width differs; set replace.resize=true explicitly"
            )
        fields = [
            _Field(
                name=field.name,
                start_bit=field.start_bit + start_bit,
                end_bit=field.end_bit + start_bit,
                intended_value=field.intended_value,
                derived_from=field.derived_from,
            )
            for field in fields
        ]
        final_bits = source_bits[:start_bit] + built_bits + source_bits[end_bit:]
        source_receipt = str(source)
    else:
        final_bits = built_bits
    content = _bits_bytes(final_bits, str(bit_order))
    if not content or len(content) > MAX_ARTIFACT_BYTES:
        raise ValueError("result size is empty or exceeds the artifact limit")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(content)
    return {
        "source": source_receipt,
        "output": str(output),
        "size": len(content),
        "bit_length": len(final_bits),
        "bit_order": bit_order,
        "sha256": hashlib.sha256(content).hexdigest(),
        "fields": _readback(output.read_bytes(), fields, str(bit_order)),
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
