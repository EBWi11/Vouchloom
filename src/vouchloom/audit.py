"""Mandatory, redacted, hash-linked stage event chains and deterministic audit ZIPs.

Directly generalizes bug_hunter's cybergym_debug.py and cybergym_audit.py so
every state transition, Worker turn, Observer breakout, and RL replay has a
tamper-evident cryptographic trail.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import zipfile
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel

DEBUG_EVENT_SCHEMA = "vouchloom-debug-event/1.0"
AUDIT_BUNDLE_SCHEMA = "vouchloom-task-audit/1.0"
_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)

_REDACTED_KEYS = frozenset(
    {
        "access_token",
        "api_key",
        "api_key_value",
        "authorization",
        "cookie",
        "id_token",
        "password",
        "reasoning_content",
        "refresh_token",
        "secret",
        "set-cookie",
        "x-api-key",
    }
)


def redact_sensitive(value: Any) -> Any:
    """Recursively scrub credentials, hidden reasoning, and raw byte blobs."""

    if isinstance(value, BaseModel):
        return redact_sensitive(value.model_dump(mode="json"))
    if isinstance(value, dict):
        return {
            str(key): (
                "[redacted]"
                if str(key).casefold() in _REDACTED_KEYS
                else redact_sensitive(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact_sensitive(item) for item in value]
    if isinstance(value, bytes):
        return {
            "bytes": len(value),
            "sha256": hashlib.sha256(value).hexdigest(),
            "encoding": "omitted-from-debug-record",
        }
    return value


def _last_record_hash(debug_dir: Path) -> str | None:
    paths = sorted(
        debug_dir.glob("[0-9]*-*.json"),
        key=lambda path: int(path.name.split("-", 1)[0]),
    )
    if not paths:
        return None
    try:
        value = json.loads(paths[-1].read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid debug chain tail: {paths[-1]}") from error
    digest = value.get("record_sha256")
    if not isinstance(digest, str) or len(digest) != 64:
        raise ValueError(f"invalid debug tail digest: {paths[-1]}")
    base = {key: item for key, item in value.items() if key != "record_sha256"}
    expected = hashlib.sha256(
        json.dumps(
            base,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    if expected != digest:
        raise ValueError(f"debug tail digest mismatch: {paths[-1]}")
    return digest


def write_debug_event(
    debug_dir: Path | None,
    *,
    stage: str,
    event: str,
    payload: Any,
) -> Path | None:
    """Append one numbered, redacted, hash-linked JSON event atomically."""

    if debug_dir is None:
        return None
    debug_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    prior_hash = _last_record_hash(debug_dir)
    base_record = {
        "schema_version": DEBUG_EVENT_SCHEMA,
        "created_at": datetime.now(UTC).isoformat(),
        "stage": stage,
        "event": event,
        "previous_record_sha256": prior_hash,
        "payload": redact_sensitive(payload),
    }
    record_sha256 = hashlib.sha256(
        json.dumps(
            base_record,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    record = {**base_record, "record_sha256": record_sha256}
    encoded = (
        json.dumps(record, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")

    safe_stage = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in stage)[:80]
    safe_event = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in event)[:80]
    existing = [
        int(path.name.split("-", 1)[0])
        for path in debug_dir.glob("[0-9]*-*.json")
        if path.name.split("-", 1)[0].isdigit()
    ]
    first_seq = max(existing, default=0) + 1
    for seq in range(first_seq, 100_000):
        path = debug_dir / f"{seq:04d}-{safe_stage}-{safe_event}.json"
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            continue
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        return path
    raise RuntimeError(f"debug event sequence exhausted: {debug_dir}")


def verify_debug_chain(debug_dir: Path) -> dict[str, Any]:
    """Verify contiguous numbering and SHA-256 hash-linking across all debug events."""

    if not debug_dir.exists():
        return {
            "schema_version": DEBUG_EVENT_SCHEMA,
            "record_count": 0,
            "head_record_sha256": None,
            "tail_record_sha256": None,
        }
    paths = sorted(
        debug_dir.glob("[0-9]*-*.json"),
        key=lambda path: int(path.name.split("-", 1)[0]),
    )
    prior: str | None = None
    head: str | None = None
    for expected_seq, path in enumerate(paths, start=1):
        try:
            seq = int(path.name.split("-", 1)[0])
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError) as error:
            raise ValueError(f"invalid debug record: {path}") from error
        if seq != expected_seq:
            raise ValueError(
                f"non-contiguous debug sequence: expected {expected_seq}, found {seq}"
            )
        if value.get("schema_version") != DEBUG_EVENT_SCHEMA:
            raise ValueError(f"invalid debug schema: {path}")
        if value.get("previous_record_sha256") != prior:
            raise ValueError(f"debug chain link mismatch: {path}")
        digest = value.get("record_sha256")
        if not isinstance(digest, str) or len(digest) != 64:
            raise ValueError(f"invalid debug record digest: {path}")
        base = {key: item for key, item in value.items() if key != "record_sha256"}
        expected = hashlib.sha256(
            json.dumps(
                base,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
        if expected != digest:
            raise ValueError(f"debug record digest mismatch: {path}")
        if head is None:
            head = digest
        prior = digest
    return {
        "schema_version": DEBUG_EVENT_SCHEMA,
        "record_count": len(paths),
        "head_record_sha256": head,
        "tail_record_sha256": prior,
    }


def _json_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            redact_sensitive(value),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _atomic_bytes(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        with suppress(OSError):
            os.unlink(tmp)


def write_task_audit_bundle(
    task_dir: Path,
    *,
    task_id: str,
    outcome_label: str,
    state_payload: dict[str, Any],
    blackboard_path: Path | None = None,
    artifacts: dict[str, bytes] | None = None,
) -> Path:
    """Atomically write a deterministic ZIP + .sha256 sidecar for a task run."""

    resolved_dir = task_dir.expanduser().resolve()
    resolved_dir.mkdir(parents=True, exist_ok=True)
    debug_dir = resolved_dir / "debug"
    chain_summary = verify_debug_chain(debug_dir)

    entries: dict[str, bytes] = {
        "state/task-run.json": _json_bytes(state_payload),
    }
    if blackboard_path is not None and blackboard_path.is_file():
        entries["state/blackboard.json"] = blackboard_path.read_bytes()

    if artifacts:
        for rel_name, raw in sorted(artifacts.items()):
            clean_name = rel_name.lstrip("/")
            entries[f"artifacts/{clean_name}"] = raw

    if debug_dir.is_dir():
        for path in sorted(
            debug_dir.glob("[0-9]*-*.json"),
            key=lambda item: int(item.name.split("-", 1)[0]),
        ):
            entries[f"debug/{path.name}"] = path.read_bytes()

    entries["manifest.json"] = _json_bytes(
        {
            "schema_version": AUDIT_BUNDLE_SCHEMA,
            "task_id": task_id,
            "outcome_label": outcome_label,
            "debug_chain": chain_summary,
        }
    )
    entries["integrity.json"] = _json_bytes(
        {
            "schema_version": AUDIT_BUNDLE_SCHEMA,
            "files": [
                {
                    "path": name,
                    "bytes": len(content),
                    "sha256": hashlib.sha256(content).hexdigest(),
                }
                for name, content in sorted(entries.items())
            ],
        }
    )

    safe_task = re.sub(r"[^A-Za-z0-9._-]+", "_", task_id).strip("._") or "task"
    safe_outcome = re.sub(r"[^A-Za-z0-9._-]+", "-", outcome_label).strip("-") or "done"
    zip_name = f"{safe_task}-{safe_outcome}.zip"
    output = resolved_dir / zip_name

    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w+b",
            prefix=".audit-",
            suffix=".zip.tmp",
            dir=resolved_dir,
            delete=False,
        ) as stream:
            tmp_path = Path(stream.name)
        with zipfile.ZipFile(
            tmp_path,
            mode="w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
        ) as archive:
            for name, content in sorted(entries.items()):
                info = zipfile.ZipInfo(name, date_time=_ZIP_TIMESTAMP)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3
                info.external_attr = 0o100600 << 16
                archive.writestr(info, content, compress_type=zipfile.ZIP_DEFLATED)
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, output)
        tmp_path = None
    finally:
        if tmp_path is not None:
            with suppress(OSError):
                tmp_path.unlink()

    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    _atomic_bytes(
        resolved_dir / f"{zip_name}.sha256",
        f"{digest}  {zip_name}\n".encode("ascii"),
    )
    return output
