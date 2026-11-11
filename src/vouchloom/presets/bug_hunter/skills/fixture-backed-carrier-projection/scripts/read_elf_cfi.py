#!/usr/bin/env python3
"""Read ELF section and DWARF CFI record boundaries without modifying input."""

from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path
from typing import Any


def _uint(data: bytes, offset: int, width: int, endian: str) -> int:
    end = offset + width
    if offset < 0 or end > len(data):
        raise ValueError(f"integer [{offset}, {end}) exceeds file size {len(data)}")
    return int.from_bytes(data[offset:end], endian)


def _uleb(data: bytes, offset: int, end: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while offset < end:
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, offset
        shift += 7
        if shift > 70:
            break
    raise ValueError("unterminated ULEB128")


def _sleb(data: bytes, offset: int, end: int) -> tuple[int, int]:
    value = 0
    shift = 0
    byte = 0
    while offset < end:
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            if shift < 64 and byte & 0x40:
                value |= -(1 << shift)
            return value, offset
        if shift > 70:
            break
    raise ValueError("unterminated SLEB128")


def _cstring(data: bytes, offset: int, end: int) -> tuple[str, int]:
    nul = data.find(b"\0", offset, end)
    if nul < 0:
        raise ValueError("unterminated augmentation string")
    return data[offset:nul].decode("ascii", errors="backslashreplace"), nul + 1


def _section_headers(data: bytes) -> tuple[str, list[dict[str, Any]]]:
    if len(data) < 16 or data[:4] != b"\x7fELF":
        raise ValueError("input is not an ELF object")
    elf_class = data[4]
    encoding = data[5]
    if elf_class not in {1, 2} or encoding not in {1, 2}:
        raise ValueError("unsupported ELF class or byte order")
    endian = "little" if encoding == 1 else "big"
    prefix = "<" if endian == "little" else ">"
    if elf_class == 1:
        if len(data) < 52:
            raise ValueError("truncated ELF32 header")
        shoff = _uint(data, 32, 4, endian)
        shentsize = _uint(data, 46, 2, endian)
        shnum = _uint(data, 48, 2, endian)
        shstrndx = _uint(data, 50, 2, endian)
        minimum_size = 40
        fmt = prefix + "IIIIIIIIII"
    else:
        if len(data) < 64:
            raise ValueError("truncated ELF64 header")
        shoff = _uint(data, 40, 8, endian)
        shentsize = _uint(data, 58, 2, endian)
        shnum = _uint(data, 60, 2, endian)
        shstrndx = _uint(data, 62, 2, endian)
        minimum_size = 64
        fmt = prefix + "IIQQQQIIQQ"
    if shentsize < minimum_size or shoff + shentsize > len(data):
        raise ValueError("invalid ELF section-header table")

    first = struct.unpack_from(fmt, data, shoff)
    if shnum == 0:
        shnum = first[5]
    if shstrndx == 0xFFFF:
        shstrndx = first[6]
    if shnum <= 0 or shnum > (len(data) - shoff) // shentsize:
        raise ValueError("section-header count exceeds the file")
    if shstrndx >= shnum:
        raise ValueError("section-name table index exceeds the section count")

    headers: list[dict[str, Any]] = []
    for index in range(shnum):
        values = struct.unpack_from(fmt, data, shoff + index * shentsize)
        headers.append(
            {
                "index": index,
                "name_offset": values[0],
                "type": values[1],
                "offset": values[4],
                "size": values[5],
                "link": values[6],
            }
        )
    names = headers[shstrndx]
    names_end = names["offset"] + names["size"]
    if names_end > len(data):
        raise ValueError("section-name table exceeds the file")
    table = data[names["offset"] : names_end]
    for header in headers:
        start = header["name_offset"]
        if start >= len(table):
            name = "<invalid-name>"
        else:
            nul = table.find(b"\0", start)
            if nul < 0:
                nul = len(table)
            name = table[start:nul].decode("ascii", errors="backslashreplace")
        header["name"] = name
        if header["offset"] + header["size"] > len(data):
            raise ValueError(f"section {name!r} exceeds the file")
    return endian, headers


def _parse_cie(
    data: bytes, payload: int, record_end: int, id_width: int
) -> dict[str, Any]:
    cursor = payload + id_width
    if cursor >= record_end:
        raise ValueError("CIE has no version")
    version = data[cursor]
    augmentation, cursor = _cstring(data, cursor + 1, record_end)
    address_size = None
    segment_selector_size = None
    if version >= 4:
        if cursor + 2 > record_end:
            raise ValueError("CIE has no address or segment-selector size")
        address_size = data[cursor]
        segment_selector_size = data[cursor + 1]
        cursor += 2
    code_alignment, cursor = _uleb(data, cursor, record_end)
    data_alignment, cursor = _sleb(data, cursor, record_end)
    if version == 1:
        if cursor >= record_end:
            raise ValueError("CIE has no return-address register")
        return_register = data[cursor]
        cursor += 1
    else:
        return_register, cursor = _uleb(data, cursor, record_end)
    result: dict[str, Any] = {
        "version": version,
        "augmentation": augmentation,
        "code_alignment": code_alignment,
        "data_alignment": data_alignment,
        "return_register": return_register,
    }
    if address_size is not None:
        result["address_size"] = address_size
        result["segment_selector_size"] = segment_selector_size
    if augmentation.startswith("z"):
        declared, data_start = _uleb(data, cursor, record_end)
        available = record_end - data_start
        result["augmentation_data"] = {
            "declared_size": declared,
            "available_size": available,
            "span": [data_start, min(record_end, data_start + declared)],
            "complete": declared <= available,
        }
    return result


def _cfi_records(
    data: bytes, section: dict[str, Any], endian: str
) -> list[dict[str, Any]]:
    section_start = section["offset"]
    section_end = section_start + section["size"]
    cursor = section_start
    records: list[dict[str, Any]] = []
    while cursor < section_end:
        record_start = cursor
        if section_end - cursor < 4:
            records.append(
                {
                    "span": [record_start, section_end],
                    "complete": False,
                    "error": "truncated initial length",
                }
            )
            break
        initial_length = _uint(data, cursor, 4, endian)
        cursor += 4
        if initial_length == 0:
            records.append({"span": [record_start, cursor], "terminator": True})
            continue
        if initial_length == 0xFFFFFFFF:
            if section_end - cursor < 8:
                records.append(
                    {
                        "span": [record_start, section_end],
                        "complete": False,
                        "error": "truncated 64-bit length",
                    }
                )
                break
            declared = _uint(data, cursor, 8, endian)
            cursor += 8
            id_width = 8
            length_form = 64
        else:
            declared = initial_length
            id_width = 4
            length_form = 32
        record_end = cursor + declared
        item: dict[str, Any] = {
            "span": [record_start, min(record_end, section_end)],
            "declared_size": declared,
            "available_size": section_end - cursor,
            "length_form": length_form,
            "complete": record_end <= section_end and declared >= id_width,
        }
        if not item["complete"]:
            item["error"] = "record length exceeds section or omits the CIE/FDE id"
            records.append(item)
            break
        record_id = _uint(data, cursor, id_width, endian)
        is_cie = (
            record_id == 0
            if section["name"] == ".eh_frame"
            else record_id == (1 << (id_width * 8)) - 1
        )
        item.update({"kind": "CIE" if is_cie else "FDE", "cie_reference": record_id})
        if is_cie:
            try:
                item["cie"] = _parse_cie(data, cursor, record_end, id_width)
                augmentation_data = item["cie"].get("augmentation_data")
                if augmentation_data and not augmentation_data["complete"]:
                    item["complete"] = False
                    item["error"] = "augmentation data exceeds its CIE record"
            except ValueError as error:
                item["complete"] = False
                item["error"] = str(error)
        records.append(item)
        cursor = record_end
    return records


def inspect_elf_cfi(path: Path, selected: set[str] | None = None) -> dict[str, Any]:
    data = path.read_bytes()
    endian, headers = _section_headers(data)
    wanted = selected or {".debug_frame", ".eh_frame"}
    sections = []
    for header in headers:
        if header["name"] not in wanted:
            continue
        sections.append(
            {
                "name": header["name"],
                "index": header["index"],
                "span": [header["offset"], header["offset"] + header["size"]],
                "size": header["size"],
                "records": _cfi_records(data, header, endian),
            }
        )
    return {
        "file": str(path),
        "size": len(data),
        "endian": endian,
        "sections": sections,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path)
    parser.add_argument(
        "--section", action="append", choices=[".debug_frame", ".eh_frame"]
    )
    args = parser.parse_args()
    try:
        result = inspect_elf_cfi(args.file, set(args.section) if args.section else None)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
