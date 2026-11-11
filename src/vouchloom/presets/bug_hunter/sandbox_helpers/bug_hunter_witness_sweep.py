#!/usr/bin/env python3
"""Sweep one bounded artifact field against one existing runtime witness."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

MAX_ARTIFACT_BYTES = 10 * 1024 * 1024
MAX_CASES = 512
MAX_CASE_OUTPUT_BYTES = 1024 * 1024
MAX_TOTAL_SECONDS = 85


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


def _positive_seconds(value: Any, name: str, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a number")
    result = float(value)
    if result <= 0 or result > maximum:
        raise ValueError(f"{name} must be positive and at most {maximum:g}")
    return result


def _hex_bytes(value: Any, name: str = "data_hex") -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a hex string")
    try:
        return bytes.fromhex(value)
    except ValueError as error:
        raise ValueError(f"{name} is not valid hexadecimal") from error


def _endian(operation: dict[str, Any]) -> str:
    endian = operation.get("endian")
    if endian not in {"little", "big"}:
        raise ValueError("endian must be little or big")
    return str(endian)


def _encoded_uint(value: int, width: int, endian: str) -> bytes:
    if width < 1 or width > 16:
        raise ValueError("integer width must be between 1 and 16 bytes")
    if value < 0 or value >= 1 << (8 * width):
        raise ValueError(f"unsigned value does not fit {width} bytes")
    return value.to_bytes(width, endian)


def _write(buffer: bytearray, offset: int, content: bytes) -> None:
    end = offset + len(content)
    if offset < 0 or end > len(buffer):
        raise ValueError(f"write range [{offset}, {end}) exceeds artifact size")
    buffer[offset:end] = content


def _mutate(source: bytes, operation: dict[str, Any], value: int) -> bytes:
    buffer = bytearray(source)
    name = operation.get("op")
    if name == "write_uint":
        _write(
            buffer,
            _nonnegative(operation.get("offset"), "offset"),
            _encoded_uint(
                value,
                _nonnegative(operation.get("width"), "width"),
                _endian(operation),
            ),
        )
    elif name == "set_bits":
        offset = _nonnegative(operation.get("offset"), "offset")
        width = _nonnegative(operation.get("width"), "width")
        bit_offset = _nonnegative(operation.get("bit_offset"), "bit_offset")
        bit_width = _nonnegative(operation.get("bit_width"), "bit_width")
        if bit_width < 1 or bit_offset + bit_width > 8 * width:
            raise ValueError("bit range is outside the integer field")
        if value >= 1 << bit_width:
            raise ValueError("sweep value does not fit bit_width")
        endian = _endian(operation)
        current_bytes = bytes(buffer[offset : offset + width])
        if len(current_bytes) != width:
            raise ValueError("bitfield range exceeds artifact size")
        current = int.from_bytes(current_bytes, endian)
        mask = ((1 << bit_width) - 1) << bit_offset
        updated = (current & ~mask) | (value << bit_offset)
        _write(buffer, offset, _encoded_uint(updated, width, endian))
    elif name == "write_ascii_uint":
        offset = _nonnegative(operation.get("offset"), "offset")
        width = _nonnegative(operation.get("width"), "width")
        pad = operation.get("pad", "0")
        if not isinstance(pad, str) or len(pad) != 1 or not pad.isascii():
            raise ValueError("pad must be one ASCII character")
        encoded = str(value).rjust(width, pad).encode("ascii")
        if len(encoded) != width:
            raise ValueError("ASCII integer does not fit width")
        _write(buffer, offset, encoded)
    elif name in {"append_repeat", "insert_repeat"}:
        pattern = _hex_bytes(operation.get("data_hex"))
        if not pattern or value < 1:
            raise ValueError("repeat sweep requires nonempty data and positive values")
        repeated = pattern * value
        if name == "append_repeat":
            buffer.extend(repeated)
        else:
            offset = _nonnegative(operation.get("offset"), "offset")
            if offset > len(buffer):
                raise ValueError("insert offset exceeds artifact size")
            buffer[offset:offset] = repeated
    else:
        raise ValueError(f"unsupported sweep operation: {name!r}")
    if not buffer or len(buffer) > MAX_ARTIFACT_BYTES:
        raise ValueError("candidate size is empty or exceeds the artifact limit")
    return bytes(buffer)


def _values(plan: dict[str, Any]) -> list[int]:
    explicit = plan.get("values")
    range_spec = plan.get("range")
    if (explicit is None) == (range_spec is None):
        raise ValueError("provide exactly one of values or range")
    if explicit is not None:
        if not isinstance(explicit, list) or not explicit:
            raise ValueError("values must be a nonempty list")
        values = [_nonnegative(value, "value") for value in explicit]
    else:
        if not isinstance(range_spec, dict):
            raise ValueError("range must be an object")
        start = _nonnegative(range_spec.get("start"), "range.start")
        stop = _nonnegative(range_spec.get("stop"), "range.stop")
        step = _nonnegative(range_spec.get("step", 1), "range.step")
        if step < 1 or start > stop:
            raise ValueError("range requires positive step and start <= stop")
        values = list(range(start, stop + 1, step))
    if len(values) > MAX_CASES:
        raise ValueError(f"sweep case count exceeds {MAX_CASES}")
    if len(values) != len(set(values)):
        raise ValueError("sweep values must be unique")
    return values


def _command(plan: dict[str, Any], artifact: Path) -> list[str]:
    command = plan.get("command")
    if (
        not isinstance(command, list)
        or not 1 <= len(command) <= 16
        or any(not isinstance(item, str) or not item for item in command)
    ):
        raise ValueError("command must contain 1..16 nonempty string arguments")
    if command.count("{artifact}") != 1:
        raise ValueError("command must contain one exact {artifact} argument")
    executable = Path(command[0])
    if not executable.is_absolute() or not executable.is_file():
        raise ValueError("command executable must be an existing absolute file")
    if not os.access(executable, os.X_OK):
        raise ValueError("command executable is not executable")
    return [str(artifact) if item == "{artifact}" else item for item in command]


def _environment(plan: dict[str, Any]) -> dict[str, str]:
    configured = plan.get("env", {})
    if not isinstance(configured, dict) or len(configured) > 16:
        raise ValueError("env must be an object with at most 16 entries")
    environment = dict(os.environ)
    for key, value in configured.items():
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", str(key)) is None:
            raise ValueError("env keys must be normalized identifiers")
        if not isinstance(value, str) or len(value) > 500 or "\x00" in value:
            raise ValueError("env values must be bounded strings")
        environment[str(key)] = value
    return environment


def _match_config(plan: dict[str, Any]) -> tuple[set[int], str | None, str]:
    match = plan.get("match")
    if not isinstance(match, dict):
        raise ValueError("match must be an object")
    exit_values = match.get("exit_codes", [])
    if (
        not isinstance(exit_values, list)
        or len(exit_values) > 16
        or any(
            isinstance(item, bool) or not isinstance(item, int) for item in exit_values
        )
    ):
        raise ValueError("match.exit_codes must be a bounded integer list")
    output_contains = match.get("output_contains")
    if output_contains is not None and (
        not isinstance(output_contains, str) or not 1 <= len(output_contains) <= 256
    ):
        raise ValueError("match.output_contains must be 1..256 characters")
    if not exit_values and output_contains is None:
        raise ValueError("match requires exit_codes or output_contains")
    mode = match.get("mode", "all")
    if mode not in {"any", "all"}:
        raise ValueError("match.mode must be any or all")
    return set(exit_values), output_contains, str(mode)


def _terminate(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


def _run_case(
    command: list[str],
    environment: dict[str, str],
    log_path: Path,
    *,
    case_deadline: float,
    total_deadline: float,
) -> tuple[int | None, bool, bool, bytes]:
    timed_out = False
    output_limited = False
    with log_path.open("wb") as log:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            env=environment,
            start_new_session=True,
        )
        while process.poll() is None:
            now = time.monotonic()
            if now >= case_deadline or now >= total_deadline:
                timed_out = True
                _terminate(process)
                break
            if os.fstat(log.fileno()).st_size > MAX_CASE_OUTPUT_BYTES:
                output_limited = True
                _terminate(process)
                break
            time.sleep(0.01)
        exit_code = process.returncode
    content = log_path.read_bytes()[:MAX_CASE_OUTPUT_BYTES]
    return exit_code, timed_out, output_limited, content


def _matched(
    exit_code: int | None,
    output: bytes,
    exit_codes: set[int],
    output_contains: str | None,
    mode: str,
) -> bool:
    checks: list[bool] = []
    if exit_codes:
        checks.append(exit_code in exit_codes)
    if output_contains is not None:
        rendered = output.decode("utf-8", errors="replace")
        checks.append(output_contains in rendered)
    return all(checks) if mode == "all" else any(checks)


def apply_plan(plan: dict[str, Any]) -> dict[str, Any]:
    source = Path(str(plan.get("source", "")))
    output = Path(str(plan.get("output", "")))
    if not source.is_file() or source.is_symlink():
        raise ValueError("source must be a readable regular file")
    if not output.is_absolute() or output.exists() or output == source:
        raise ValueError("output must be a new absolute path distinct from source")
    source_content = source.read_bytes()
    if not source_content or len(source_content) > MAX_ARTIFACT_BYTES:
        raise ValueError("source size is empty or exceeds the artifact limit")
    operation = plan.get("operation")
    if not isinstance(operation, dict):
        raise ValueError("operation must be an object")
    values = _values(plan)
    exit_codes, output_contains, mode = _match_config(plan)
    case_timeout = _positive_seconds(
        plan.get("case_timeout_sec", 2), "case_timeout_sec", 10
    )
    total_timeout = _positive_seconds(
        plan.get("total_timeout_sec", 60),
        "total_timeout_sec",
        MAX_TOTAL_SECONDS,
    )
    environment = _environment(plan)
    started = time.monotonic()
    total_deadline = started + total_timeout
    cases: list[dict[str, Any]] = []
    last_preview = ""
    with tempfile.TemporaryDirectory(prefix="bug-hunter-witness-") as temporary:
        root = Path(temporary)
        for index, value in enumerate(values):
            if time.monotonic() >= total_deadline:
                break
            candidate = root / f"candidate-{index:04d}.bin"
            candidate.write_bytes(_mutate(source_content, operation, value))
            command = _command(plan, candidate)
            log_path = root / f"case-{index:04d}.log"
            exit_code, timed_out, output_limited, case_output = _run_case(
                command,
                environment,
                log_path,
                case_deadline=min(total_deadline, time.monotonic() + case_timeout),
                total_deadline=total_deadline,
            )
            witness = _matched(
                exit_code, case_output, exit_codes, output_contains, mode
            )
            last_preview = case_output.decode("utf-8", errors="replace")[-500:]
            cases.append(
                {
                    "value": value,
                    "exit_code": exit_code,
                    "timed_out": timed_out,
                    "output_limited": output_limited,
                    "matched": witness,
                    "artifact_sha256": hashlib.sha256(
                        candidate.read_bytes()
                    ).hexdigest(),
                    "output_sha256": hashlib.sha256(case_output).hexdigest(),
                }
            )
            if witness:
                output.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(candidate, output)
                content = output.read_bytes()
                return {
                    "matched": True,
                    "matched_value": value,
                    "source": str(source),
                    "output": str(output),
                    "size": len(content),
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "tested": len(cases),
                    "elapsed_sec": round(time.monotonic() - started, 3),
                    "cases": cases,
                    "matched_output_preview": last_preview,
                }
    return {
        "matched": False,
        "source": str(source),
        "output": None,
        "tested": len(cases),
        "elapsed_sec": round(time.monotonic() - started, 3),
        "cases": cases,
        "last_output_preview": last_preview,
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
