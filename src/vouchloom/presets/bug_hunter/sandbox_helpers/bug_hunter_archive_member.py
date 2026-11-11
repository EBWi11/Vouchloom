#!/usr/bin/env python3
"""Safely inspect and materialize one bounded ZIP member."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import stat
import sys
import zipfile
from pathlib import Path, PurePosixPath

MAX_MEMBERS = 4096
MAX_LISTED_MEMBERS = 128
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024


def _safe_path(info: zipfile.ZipInfo) -> bool:
    path = PurePosixPath(info.filename)
    return (
        bool(info.filename)
        and "\\" not in info.filename
        and not path.is_absolute()
        and ".." not in path.parts
        and not any(":" in part for part in path.parts)
        and not (info.flag_bits & 0x1)
    )


def _safe_member(info: zipfile.ZipInfo) -> bool:
    mode = (info.external_attr >> 16) & 0xFFFF
    return (
        _safe_path(info)
        and not info.is_dir()
        and not stat.S_ISLNK(mode)
        and 0 <= info.file_size <= MAX_MEMBER_BYTES
    )


def _safe_entry(info: zipfile.ZipInfo) -> bool:
    mode = (info.external_attr >> 16) & 0xFFFF
    return (
        _safe_path(info)
        and not stat.S_ISLNK(mode)
        and (info.is_dir() or 0 <= info.file_size <= MAX_MEMBER_BYTES)
    )


def _members(archive: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    members = archive.infolist()
    if len(members) > MAX_MEMBERS:
        raise ValueError(f"archive member count exceeds {MAX_MEMBERS}")
    if sum(max(0, item.file_size) for item in members) > MAX_TOTAL_BYTES:
        raise ValueError("archive expanded size exceeds the configured limit")
    return members


def _exact_member(members: list[zipfile.ZipInfo], member_name: str) -> zipfile.ZipInfo:
    matches = [item for item in members if item.filename == member_name]
    if len(matches) != 1 or not _safe_member(matches[0]):
        raise ValueError("member is missing, duplicated, encrypted, or unsafe")
    return matches[0]


def _write_output(path: Path, content: bytes) -> dict[str, object]:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return {
        "output": str(path),
        "size": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
    }


def _file_receipt(path: Path) -> dict[str, object]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    return {"output": str(path), "size": size, "sha256": digest.hexdigest()}


def list_members(path: Path) -> dict[str, object]:
    with zipfile.ZipFile(path) as archive:
        members = _members(archive)
    safe = [item for item in members if _safe_member(item)]
    return {
        "archive": str(path),
        "safe_member_count": len(safe),
        "total_member_count": len(members),
        "truncated": len(safe) > MAX_LISTED_MEMBERS,
        "members": [
            {
                "name": item.filename,
                "size": item.file_size,
                "compressed_size": item.compress_size,
                "crc32": f"{item.CRC:08x}",
            }
            for item in safe[:MAX_LISTED_MEMBERS]
        ],
    }


def extract_member(path: Path, member_name: str, output: Path) -> dict[str, object]:
    with zipfile.ZipFile(path) as archive:
        member = _exact_member(_members(archive), member_name)
        content = archive.read(member)
    if len(content) != member.file_size:
        raise ValueError("member size changed while reading")
    return {
        "archive": str(path),
        "member": member_name,
        **_write_output(output, content),
    }


def replace_member(
    path: Path, member_name: str, replacement: Path, output: Path
) -> dict[str, object]:
    content = replacement.read_bytes()
    if len(content) > MAX_MEMBER_BYTES:
        raise ValueError("replacement exceeds the member size limit")
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path) as source:
        members = _members(source)
        target = _exact_member(members, member_name)
        if any(not _safe_entry(item) for item in members):
            raise ValueError("archive contains an unsafe entry")
        if output.resolve() == path.resolve():
            raise ValueError("output archive must differ from the source archive")
        with zipfile.ZipFile(output, "w", allowZip64=True) as destination:
            for item in members:
                copied = zipfile.ZipInfo(item.filename, item.date_time)
                copied.compress_type = item.compress_type
                copied.comment = item.comment
                copied.extra = item.extra
                copied.internal_attr = item.internal_attr
                copied.external_attr = item.external_attr
                copied.create_system = item.create_system
                copied.flag_bits = item.flag_bits & ~0x1
                if item.is_dir():
                    destination.writestr(copied, b"")
                elif item.filename == target.filename:
                    destination.writestr(copied, content)
                else:
                    with (
                        source.open(item) as reader,
                        destination.open(copied, "w", force_zip64=True) as writer,
                    ):
                        shutil.copyfileobj(reader, writer, length=1024 * 1024)
    receipt = _file_receipt(output)
    return {
        "archive": str(path),
        "member": member_name,
        "replacement_size": len(content),
        **receipt,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    list_parser = commands.add_parser("list")
    list_parser.add_argument("archive", type=Path)
    extract_parser = commands.add_parser("extract")
    extract_parser.add_argument("archive", type=Path)
    extract_parser.add_argument("member")
    extract_parser.add_argument("output", type=Path)
    replace_parser = commands.add_parser("replace")
    replace_parser.add_argument("archive", type=Path)
    replace_parser.add_argument("member")
    replace_parser.add_argument("replacement", type=Path)
    replace_parser.add_argument("output", type=Path)
    arguments = parser.parse_args()
    try:
        if arguments.command == "list":
            receipt = list_members(arguments.archive)
        elif arguments.command == "extract":
            receipt = extract_member(
                arguments.archive, arguments.member, arguments.output
            )
        else:
            receipt = replace_member(
                arguments.archive,
                arguments.member,
                arguments.replacement,
                arguments.output,
            )
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError) as error:
        print(json.dumps({"error": str(error)}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
