#!/usr/bin/env python3
"""Build and inspect public curl-fuzzer big-endian TLV carriers."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

TYPE_NAMES = {
    1: "URL",
    2: "RESPONSE0",
    3: "USERNAME",
    4: "PASSWORD",
    5: "POSTFIELDS",
    6: "HEADER",
    7: "COOKIE",
    8: "UPLOAD1",
    9: "RANGE",
    10: "CUSTOMREQUEST",
    11: "MAIL_RECIPIENT",
    12: "MAIL_FROM",
    13: "MIME_PART",
    14: "MIME_PART_NAME",
    15: "MIME_PART_DATA",
    16: "HTTPAUTH",
    17: "RESPONSE1",
    18: "RESPONSE2",
    19: "RESPONSE3",
    20: "RESPONSE4",
    21: "RESPONSE5",
    22: "RESPONSE6",
    23: "RESPONSE7",
    24: "RESPONSE8",
    25: "RESPONSE9",
    26: "RESPONSE10",
    27: "OPTHEADER",
    28: "NOBODY",
    29: "FOLLOWLOCATION",
    30: "ACCEPTENCODING",
    31: "SECOND_RESPONSE0",
    32: "SECOND_RESPONSE1",
    33: "WILDCARDMATCH",
    34: "RTSP_REQUEST",
    35: "RTSP_SESSION_ID",
    36: "RTSP_STREAM_URI",
    37: "RTSP_TRANSPORT",
    38: "RTSP_CLIENT_CSEQ",
    39: "MAIL_AUTH",
    40: "HTTP_VERSION",
    41: "DOH_URL",
    42: "LOGIN_OPTIONS",
    43: "XOAUTH2_BEARER",
    44: "USERPWD",
    45: "USERAGENT",
    46: "NETRC",
    47: "SSH_HOST_PUBLIC_KEY_SHA256",
    48: "POST",
    49: "WS_OPTIONS",
    50: "CONNECT_ONLY",
    51: "HSTS",
    52: "HTTPPOSTBODY",
    53: "PROXY",
    54: "PROXYTYPE",
    100: "PROXYUSERPWD",
    101: "REFERER",
    102: "FTPPORT",
    103: "SSLCERT",
    104: "KEYPASSWD",
    105: "INTERFACE",
    106: "KRBLEVEL",
    107: "CAINFO",
    108: "SSL_CIPHER_LIST",
    109: "SSLCERTTYPE",
    110: "SSLKEY",
    111: "SSLKEYTYPE",
    112: "SSLENGINE",
    113: "CAPATH",
    114: "FTP_ACCOUNT",
    115: "COOKIELIST",
    116: "FTP_ALTERNATIVE_TO_USER",
    117: "SSH_PUBLIC_KEYFILE",
    118: "SSH_PRIVATE_KEYFILE",
    119: "SSH_HOST_PUBLIC_KEY_MD5",
    120: "ISSUERCERT",
    121: "PROXYUSERNAME",
    122: "PROXYPASSWORD",
    123: "NOPROXY",
    124: "SSH_KNOWNHOSTS",
    125: "TLSAUTH_USERNAME",
    126: "TLSAUTH_PASSWORD",
    127: "TLSAUTH_TYPE",
    128: "DNS_SERVERS",
    129: "DNS_INTERFACE",
    130: "DNS_LOCAL_IP4",
    131: "DNS_LOCAL_IP6",
    132: "PINNEDPUBLICKEY",
    133: "UNIX_SOCKET_PATH",
    134: "PROXY_SERVICE_NAME",
    135: "SERVICE_NAME",
    136: "DEFAULT_PROTOCOL",
    137: "PROXY_CAINFO",
    138: "PROXY_CAPATH",
    139: "PROXY_TLSAUTH_USERNAME",
    140: "PROXY_TLSAUTH_PASSWORD",
    141: "PROXY_TLSAUTH_TYPE",
    142: "PROXY_SSLCERT",
    143: "PROXY_SSLCERTTYPE",
    144: "PROXY_SSLKEY",
    145: "PROXY_SSLKEYTYPE",
    146: "PROXY_KEYPASSWD",
    147: "PROXY_SSL_CIPHER_LIST",
    148: "PROXY_CRLFILE",
    149: "PRE_PROXY",
    150: "PROXY_PINNEDPUBLICKEY",
    151: "ABSTRACT_UNIX_SOCKET",
    152: "REQUEST_TARGET",
    153: "TLS13_CIPHERS",
    154: "PROXY_TLS13_CIPHERS",
    155: "SASL_AUTHZID",
    156: "PROXY_ISSUERCERT",
    157: "SSL_EC_CURVES",
    158: "AWS_SIGV4",
    159: "REDIR_PROTOCOLS_STR",
    160: "HAPROXY_CLIENT_IP",
    161: "ECH",
    200: "PORT",
    201: "LOW_SPEED_LIMIT",
    202: "LOW_SPEED_TIME",
    203: "RESUME_FROM",
    204: "TIMEVALUE",
    205: "NOPROGRESS",
    206: "FAILONERROR",
    207: "DIRLISTONLY",
    208: "APPEND",
    209: "TRANSFERTEXT",
    210: "AUTOREFERER",
    211: "PROXYPORT",
    212: "POSTFIELDSIZE",
    213: "HTTPPROXYTUNNEL",
    214: "SSL_VERIFYPEER",
    215: "MAXREDIRS",
    216: "FILETIME",
    217: "MAXCONNECTS",
    218: "FRESH_CONNECT",
    219: "FORBID_REUSE",
    220: "CONNECTTIMEOUT",
    221: "HTTPGET",
    222: "SSL_VERIFYHOST",
    223: "FTP_USE_EPSV",
    224: "SSLENGINE_DEFAULT",
    225: "DNS_CACHE_TIMEOUT",
    226: "COOKIESESSION",
    227: "BUFFERSIZE",
    228: "NOSIGNAL",
    229: "UNRESTRICTED_AUTH",
    230: "FTP_USE_EPRT",
    231: "FTP_CREATE_MISSING_DIRS",
    232: "MAXFILESIZE",
    233: "TCP_NODELAY",
    234: "IGNORE_CONTENT_LENGTH",
    235: "FTP_SKIP_PASV_IP",
    236: "LOCALPORT",
    237: "LOCALPORTRANGE",
    238: "SSL_SESSIONID_CACHE",
    239: "FTP_SSL_CCC",
    240: "CONNECTTIMEOUT_MS",
    241: "HTTP_TRANSFER_DECODING",
    242: "HTTP_CONTENT_DECODING",
    243: "NEW_FILE_PERMS",
    244: "NEW_DIRECTORY_PERMS",
    245: "PROXY_TRANSFER_MODE",
    246: "ADDRESS_SCOPE",
    247: "CERTINFO",
    248: "TFTP_BLKSIZE",
    249: "SOCKS5_GSSAPI_NEC",
    250: "FTP_USE_PRET",
    251: "RTSP_SERVER_CSEQ",
    252: "TRANSFER_ENCODING",
    253: "ACCEPTTIMEOUT_MS",
    254: "TCP_KEEPALIVE",
    255: "TCP_KEEPIDLE",
    256: "TCP_KEEPINTVL",
    257: "SASL_IR",
    258: "SSL_ENABLE_ALPN",
    259: "EXPECT_100_TIMEOUT_MS",
    260: "SSL_VERIFYSTATUS",
    261: "SSL_FALSESTART",
    262: "PATH_AS_IS",
    263: "PIPEWAIT",
    264: "STREAM_WEIGHT",
    265: "TFTP_NO_OPTIONS",
    266: "TCP_FASTOPEN",
    267: "KEEP_SENDING_ON_ERROR",
    268: "PROXY_SSL_VERIFYPEER",
    269: "PROXY_SSL_VERIFYHOST",
    270: "PROXY_SSL_OPTIONS",
    271: "SUPPRESS_CONNECT_HEADERS",
    272: "SOCKS5_AUTH",
    273: "SSH_COMPRESSION",
    274: "HAPPY_EYEBALLS_TIMEOUT_MS",
    275: "HAPROXYPROTOCOL",
    276: "DNS_SHUFFLE_ADDRESSES",
    277: "DISALLOW_USERNAME_IN_URL",
    278: "UPLOAD_BUFFERSIZE",
    279: "UPKEEP_INTERVAL_MS",
    280: "HTTP09_ALLOWED",
    281: "ALTSVC_CTRL",
    282: "MAXAGE_CONN",
    283: "MAIL_RCPT_ALLOWFAILS",
    284: "HSTS_CTRL",
    285: "DOH_SSL_VERIFYPEER",
    286: "DOH_SSL_VERIFYHOST",
    287: "DOH_SSL_VERIFYSTATUS",
    288: "MAXLIFETIME_CONN",
    289: "MIME_OPTIONS",
    290: "CA_CACHE_TIMEOUT",
    291: "QUICK_EXIT",
    292: "SERVER_RESPONSE_TIMEOUT_MS",
    293: "TCP_KEEPCNT",
    300: "SSLVERSION",
    301: "TIMECONDITION",
    302: "PROXYAUTH",
    303: "IPRESOLVE",
    304: "USE_SSL",
    305: "FTPSSLAUTH",
    306: "FTP_FILEMETHOD",
    307: "SSH_AUTH_TYPES",
    308: "POSTREDIR",
    309: "GSSAPI_DELEGATION",
    310: "SSL_OPTIONS",
    311: "HEADEROPT",
    312: "PROXY_SSLVERSION",
    320: "RESUME_FROM_LARGE",
    321: "MAXFILESIZE_LARGE",
    322: "POSTFIELDSIZE_LARGE",
    323: "MAX_SEND_SPEED_LARGE",
    324: "MAX_RECV_SPEED_LARGE",
    325: "TIMEVALUE_LARGE",
}
TYPE_IDS = {name: type_id for type_id, name in TYPE_NAMES.items()}
U32_TYPES = {
    "HTTPAUTH",
    "OPTHEADER",
    "NOBODY",
    "FOLLOWLOCATION",
    "WILDCARDMATCH",
    "RTSP_REQUEST",
    "RTSP_CLIENT_CSEQ",
    "HTTP_VERSION",
    "NETRC",
    "POST",
    "WS_OPTIONS",
    "CONNECT_ONLY",
    "PROXYTYPE",
    *(TYPE_NAMES[type_id] for type_id in range(200, 294) if type_id != 212),
    *(TYPE_NAMES[type_id] for type_id in range(300, 313)),
    "RESUME_FROM_LARGE",
    "MAXFILESIZE_LARGE",
    "MAX_SEND_SPEED_LARGE",
    "MAX_RECV_SPEED_LARGE",
    "TIMEVALUE_LARGE",
}
REPEATABLE_TYPES = {
    "HEADER",
    "MAIL_RECIPIENT",
    "MIME_PART",
    *(f"RESPONSE{index}" for index in range(11)),
    "SECOND_RESPONSE0",
    "SECOND_RESPONSE1",
}
NESTED_ONLY_TYPES = {"MIME_PART_NAME", "MIME_PART_DATA"}
UNSUPPORTED_TYPES = {"HSTS", "POSTFIELDSIZE", "POSTFIELDSIZE_LARGE"}
FTP_CONTROL_RECORDS = {f"RESPONSE{index}": index for index in range(11)}
FTP_DATA_RECORDS = {"SECOND_RESPONSE0", "SECOND_RESPONSE1"}
FTP_SEMANTIC_SINGLETONS = {
    "URL",
    "FTP_USE_EPSV",
    "WILDCARDMATCH",
    *FTP_CONTROL_RECORDS,
    *FTP_DATA_RECORDS,
}
FTP_PLAN_PHASES = {
    "greeting",
    "setup",
    "epsv-rejected",
    "passive-ready",
    "transfer",
}


def _type_id(value: str) -> int:
    normalized = value.strip().upper().replace("TLV_TYPE_", "")
    if normalized in TYPE_IDS:
        return TYPE_IDS[normalized]
    try:
        parsed = int(value, 0)
    except ValueError as error:
        raise ValueError(f"unknown curl-fuzzer TLV type {value!r}") from error
    if parsed not in TYPE_NAMES:
        raise ValueError(f"unknown curl-fuzzer TLV type {parsed}")
    return parsed


def _value_bytes(kind: str, value: str, *, type_name: str) -> bytes:
    if kind == "utf8":
        return value.encode("utf-8")
    if kind == "hex":
        try:
            return bytes.fromhex(value)
        except ValueError as error:
            raise ValueError(f"invalid hex value for {type_name}") from error
    if kind == "u32":
        if type_name not in U32_TYPES:
            raise ValueError(f"{type_name} is not a public u32 TLV")
        try:
            integer = int(value, 0)
        except ValueError as error:
            raise ValueError(f"invalid u32 value for {type_name}") from error
        if not 0 <= integer <= 0xFFFFFFFF:
            raise ValueError(f"u32 value for {type_name} is out of range")
        return integer.to_bytes(4, "big")
    if kind == "file":
        return Path(value).read_bytes()
    raise ValueError(f"unsupported value kind {kind!r}")


def build_records(specs: list[list[str]]) -> tuple[bytes, list[dict[str, Any]]]:
    content = bytearray()
    receipt: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, (raw_type, kind, raw_value) in enumerate(specs):
        type_id = _type_id(raw_type)
        type_name = TYPE_NAMES[type_id]
        if type_name in NESTED_ONLY_TYPES:
            raise ValueError(f"{type_name} is valid only inside a MIME_PART value")
        if type_name in UNSUPPORTED_TYPES:
            raise ValueError(f"{type_name} is named but rejected by the public harness")
        if type_name in seen and type_name not in REPEATABLE_TYPES:
            raise ValueError(f"singleton TLV {type_name} is repeated")
        value = _value_bytes(kind, raw_value, type_name=type_name)
        if len(value) > 0xFFFFFFFF:
            raise ValueError(f"value for {type_name} exceeds u32 length")
        offset = len(content)
        content += type_id.to_bytes(2, "big")
        content += len(value).to_bytes(4, "big")
        content += value
        seen.add(type_name)
        receipt.append(
            {
                "index": index,
                "offset": offset,
                "type": type_id,
                "name": type_name,
                "length": len(value),
                "value_sha256": hashlib.sha256(value).hexdigest(),
            }
        )
    return bytes(content), receipt


def inspect_bytes(data: bytes) -> dict[str, Any]:
    cursor = 0
    records: list[dict[str, Any]] = []
    while cursor < len(data):
        if len(data) - cursor < 6:
            raise ValueError(f"truncated TLV header at offset {cursor}")
        start = cursor
        type_id = int.from_bytes(data[cursor : cursor + 2], "big")
        length = int.from_bytes(data[cursor + 2 : cursor + 6], "big")
        cursor += 6
        end = cursor + length
        if end > len(data):
            raise ValueError(
                f"TLV at offset {start} declares {length} bytes with "
                f"only {len(data) - cursor} remaining"
            )
        value = data[cursor:end]
        name = TYPE_NAMES.get(type_id)
        valid_top_level = name is not None and name not in (
            NESTED_ONLY_TYPES | UNSUPPORTED_TYPES
        )
        preview = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in value[:80])
        item: dict[str, Any] = {
            "index": len(records),
            "offset": start,
            "type": type_id,
            "name": name,
            "known": name is not None,
            "valid_top_level": valid_top_level,
            "length": length,
            "value_hex": value[:128].hex(),
            "value_ascii_preview": preview,
            "value_sha256": hashlib.sha256(value).hexdigest(),
        }
        if length == 4:
            item["u32be"] = int.from_bytes(value, "big")
        records.append(item)
        cursor = end
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "record_count": len(records),
        "all_types_known": all(item["known"] for item in records),
        "all_records_valid": all(item["valid_top_level"] for item in records),
        "records": records,
    }


def _record_values(data: bytes) -> list[tuple[str, bytes]]:
    inspection = inspect_bytes(data)
    records: list[tuple[str, bytes]] = []
    cursor = 0
    for item in inspection["records"]:
        name = item["name"]
        if not isinstance(name, str) or not item["valid_top_level"]:
            raise ValueError(f"invalid top-level TLV at offset {item['offset']}")
        length = item["length"]
        value_start = cursor + 6
        value_end = value_start + length
        records.append((name, data[value_start:value_end]))
        cursor = value_end
    return records


def _ftp_reply_codes(value: bytes, *, record: str) -> list[int]:
    codes = [
        int(match.group(1))
        for match in re.finditer(rb"(?:^|\r?\n)([1-5][0-9]{2})(?:[ -])", value)
    ]
    if not codes:
        raise ValueError(f"{record} has no complete FTP reply line")
    return codes


def _valid_epsv_reply(value: bytes) -> bool:
    match = re.search(rb"\(\|\|\|([0-9]{1,5})\|\)", value)
    return match is not None and 1 <= int(match.group(1)) <= 65535


def _valid_pasv_reply(value: bytes) -> bool:
    match = re.search(
        rb"\(([0-9]{1,3}),([0-9]{1,3}),([0-9]{1,3}),"
        rb"([0-9]{1,3}),([0-9]{1,3}),([0-9]{1,3})\)",
        value,
    )
    if match is None:
        return False
    octets = [int(part) for part in match.groups()]
    return (
        all(part <= 255 for part in octets) and 0 < octets[4] * 256 + octets[5] <= 65535
    )


def validate_ftp_plan(data: bytes, plan: dict[str, Any]) -> dict[str, Any]:
    """Validate one source-derived FTP transfer plan against a TLV carrier."""

    expected_keys = {"target", "protocol", "control_steps", "data_record"}
    if set(plan) != expected_keys:
        raise ValueError(
            "FTP plan must contain only target, protocol, control_steps, "
            "and data_record"
        )
    if plan["target"] != "curl_fuzzer_ftp":
        raise ValueError("FTP plan requires the exact curl_fuzzer_ftp target")
    if plan["protocol"] != "ftp":
        raise ValueError("FTP plan protocol must be ftp")

    raw_steps = plan["control_steps"]
    if not isinstance(raw_steps, list) or not 1 <= len(raw_steps) <= 11:
        raise ValueError("FTP plan requires between 1 and 11 control steps")
    steps: list[tuple[str, str]] = []
    for index, raw_step in enumerate(raw_steps):
        if not isinstance(raw_step, dict) or set(raw_step) != {"record", "phase"}:
            raise ValueError(f"control step {index} must contain only record and phase")
        record = raw_step["record"]
        phase = raw_step["phase"]
        if not isinstance(record, str) or record not in FTP_CONTROL_RECORDS:
            raise ValueError(f"control step {index} names a non-control response")
        if not isinstance(phase, str) or phase not in FTP_PLAN_PHASES:
            raise ValueError(f"control step {index} has unknown phase {phase!r}")
        steps.append((record, phase))
    step_records = [record for record, _ in steps]
    if len(set(step_records)) != len(step_records):
        raise ValueError("FTP plan repeats a control response record")
    if [FTP_CONTROL_RECORDS[item] for item in step_records] != sorted(
        FTP_CONTROL_RECORDS[item] for item in step_records
    ):
        raise ValueError("FTP control steps are not ordered by response slot")
    if step_records != [f"RESPONSE{index}" for index in range(len(step_records))]:
        raise ValueError("FTP control steps must use contiguous response slots")

    data_record = plan["data_record"]
    if not isinstance(data_record, str) or data_record not in FTP_DATA_RECORDS:
        raise ValueError("FTP data_record must name a SECOND_RESPONSE slot")

    parsed = _record_values(data)
    values: dict[str, bytes] = {}
    for name, value in parsed:
        if name in values and name in FTP_SEMANTIC_SINGLETONS:
            raise ValueError(f"FTP carrier repeats semantic record {name}")
        values[name] = value
    url = values.get("URL")
    if url is None or not url.lower().startswith((b"ftp://", b"ftps://")):
        raise ValueError("FTP carrier requires an ftp or ftps URL")
    carrier_controls = {name for name in values if name in FTP_CONTROL_RECORDS}
    if carrier_controls != set(step_records):
        raise ValueError("FTP plan must classify every control response exactly once")
    if data_record not in values or not values[data_record]:
        raise ValueError("FTP plan requires a non-empty second-socket response")

    phase_records: dict[str, list[str]] = {}
    reply_codes: dict[str, list[int]] = {}
    for record, phase in steps:
        phase_records.setdefault(phase, []).append(record)
        reply_codes[record] = _ftp_reply_codes(values[record], record=record)
    if phase_records.get("greeting") != [step_records[0]]:
        raise ValueError("FTP plan requires exactly one first greeting step")
    if reply_codes[step_records[0]][0] != 220:
        raise ValueError("FTP greeting must begin with reply 220")
    passive_records = phase_records.get("passive-ready", [])
    if len(passive_records) != 1:
        raise ValueError("FTP plan requires exactly one passive-ready step")
    passive_record = passive_records[0]
    passive_index = step_records.index(passive_record)
    passive_codes = reply_codes[passive_record]
    passive_code = next((code for code in passive_codes if code in {227, 229}), None)
    if passive_code is None:
        raise ValueError("passive-ready must contain reply 227 or 229")
    if passive_code == 229 and not _valid_epsv_reply(values[passive_record]):
        raise ValueError("EPSV reply does not contain a valid port tuple")
    if passive_code == 229:
        raise ValueError(
            "curl_fuzzer_ftp cannot bind its second mock socket from an EPSV-only "
            "reply; use the published EPSV-rejection to PASV fallback"
        )
    if passive_code == 227 and not _valid_pasv_reply(values[passive_record]):
        raise ValueError("PASV reply does not contain a valid address and port tuple")

    rejected_records = phase_records.get("epsv-rejected", [])
    if len(rejected_records) > 1:
        raise ValueError("FTP plan permits at most one epsv-rejected step")
    epsv_disabled = values.get("FTP_USE_EPSV") == (0).to_bytes(4, "big")
    if passive_code == 227 and not epsv_disabled:
        if not rejected_records:
            raise ValueError(
                "PASV fallback requires an EPSV rejection or FTP_USE_EPSV=0"
            )
        rejected_record = rejected_records[0]
        if FTP_CONTROL_RECORDS[rejected_record] >= FTP_CONTROL_RECORDS[passive_record]:
            raise ValueError("EPSV rejection must precede PASV readiness")
        if not any(code // 100 in {4, 5} for code in reply_codes[rejected_record]):
            raise ValueError("epsv-rejected must contain a 4xx or 5xx reply")
    elif passive_code == 229 and rejected_records:
        raise ValueError("an EPSV-ready plan cannot also reject EPSV")

    transfer_records = phase_records.get("transfer", [])
    if not transfer_records:
        raise ValueError("FTP plan requires at least one transfer step")
    transfer_codes = [
        code for record in transfer_records for code in reply_codes[record]
    ]
    preliminary_index = next(
        (index for index, code in enumerate(transfer_codes) if code // 100 == 1),
        None,
    )
    if preliminary_index is None or not any(
        code // 100 == 2 for code in transfer_codes[preliminary_index + 1 :]
    ):
        raise ValueError(
            "FTP transfer requires a 1xx reply followed by a 2xx completion"
        )
    first_transfer_index = min(step_records.index(item) for item in transfer_records)
    if first_transfer_index <= passive_index:
        raise ValueError("FTP transfer must follow passive readiness")
    setup_indices = [
        step_records.index(item) for item in phase_records.get("setup", [])
    ]
    if len([index for index in setup_indices if index < passive_index]) < 3:
        raise ValueError(
            "FTP plan requires login and path setup before passive readiness"
        )
    if not any(passive_index < index < first_transfer_index for index in setup_indices):
        raise ValueError(
            "FTP plan requires transfer-mode setup after passive readiness"
        )
    for record in phase_records.get("setup", []):
        if not all(code // 100 in {2, 3} for code in reply_codes[record]):
            raise ValueError("FTP setup steps require 2xx or 3xx replies")

    return {
        "target": plan["target"],
        "protocol": plan["protocol"],
        "carrier_sha256": hashlib.sha256(data).hexdigest(),
        "control_steps": [
            {"record": record, "phase": phase, "reply_codes": reply_codes[record]}
            for record, phase in steps
        ],
        "passive_mode": "epsv" if passive_code == 229 else "pasv",
        "data_record": data_record,
        "data_length": len(values[data_record]),
        "endpoint_binding_complete": True,
        "response_topology_complete": True,
    }


def _atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(dir=path.parent, delete=False)
    temporary = Path(handle.name)
    try:
        with handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def materialize_ftp(
    specs: list[list[str]], plan: dict[str, Any]
) -> tuple[bytes, dict[str, Any]]:
    """Build one TLV carrier and validate its complete FTP response topology."""

    content, build_receipt = build_records(specs)
    inspection = inspect_bytes(content)
    validation = validate_ftp_plan(content, plan)
    return content, {
        "carrier": {
            "sha256": inspection["sha256"],
            "size": inspection["size"],
            "record_count": inspection["record_count"],
            "all_types_known": inspection["all_types_known"],
            "all_records_valid": inspection["all_records_valid"],
        },
        "build_records": build_receipt,
        "ftp_validation": validation,
    }


def ftp_wildcard_transaction(
    pattern: str,
) -> tuple[list[list[str]], dict[str, Any]]:
    """Return one canonical public FTP LIST transaction for a wildcard pattern."""

    if not pattern or len(pattern) > 256:
        raise ValueError("FTP wildcard pattern must contain 1 through 256 characters")
    if any(character in pattern for character in "/\x00\r\n"):
        raise ValueError("FTP wildcard pattern must be one URL path component")
    records = [
        ["URL", "utf8", f"ftp://127.0.0.1/files/{pattern}"],
        ["WILDCARDMATCH", "u32", "1"],
        ["RESPONSE0", "utf8", "220 Hello!\n"],
        ["RESPONSE1", "utf8", "200 Sure\n"],
        ["RESPONSE2", "utf8", "200 Sure\n"],
        ["RESPONSE3", "utf8", "200 Sure\n"],
        ["RESPONSE4", "utf8", "400 Sure\n"],
        [
            "RESPONSE5",
            "utf8",
            "227 Entering Passive Mode (213,229,112,130,216,4)\n",
        ],
        ["RESPONSE6", "utf8", "200 Sure\n"],
        [
            "RESPONSE7",
            "utf8",
            "150 Success\r\n226 Everything sent\r\n",
        ],
        ["RESPONSE8", "utf8", "200 Sure\n"],
        [
            "SECOND_RESPONSE0",
            "utf8",
            "-rw-r--r-- 1 user group 1 Jan 01 00:00 file\r\n",
        ],
    ]
    plan = {
        "target": "curl_fuzzer_ftp",
        "protocol": "ftp",
        "control_steps": [
            {"record": "RESPONSE0", "phase": "greeting"},
            {"record": "RESPONSE1", "phase": "setup"},
            {"record": "RESPONSE2", "phase": "setup"},
            {"record": "RESPONSE3", "phase": "setup"},
            {"record": "RESPONSE4", "phase": "epsv-rejected"},
            {"record": "RESPONSE5", "phase": "passive-ready"},
            {"record": "RESPONSE6", "phase": "setup"},
            {"record": "RESPONSE7", "phase": "transfer"},
            {"record": "RESPONSE8", "phase": "setup"},
        ],
        "data_record": "SECOND_RESPONSE0",
    }
    return records, plan


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    inspect_parser = subparsers.add_parser("inspect")
    inspect_parser.add_argument("artifact", type=Path)
    build_parser = subparsers.add_parser("build")
    build_parser.add_argument("output", type=Path)
    build_parser.add_argument(
        "--record",
        action="append",
        nargs=3,
        metavar=("TYPE", "KIND", "VALUE"),
        required=True,
    )
    ftp_parser = subparsers.add_parser("validate-ftp")
    ftp_parser.add_argument("artifact", type=Path)
    ftp_parser.add_argument("plan", type=Path)
    materialize_ftp_parser = subparsers.add_parser("materialize-ftp")
    materialize_ftp_parser.add_argument("output", type=Path)
    materialize_ftp_parser.add_argument("plan", type=Path)
    materialize_ftp_parser.add_argument(
        "--record",
        action="append",
        nargs=3,
        metavar=("TYPE", "KIND", "VALUE"),
        required=True,
    )
    wildcard_parser = subparsers.add_parser("materialize-ftp-wildcard")
    wildcard_parser.add_argument("output", type=Path)
    wildcard_parser.add_argument("plan", type=Path)
    wildcard_parser.add_argument("--pattern", required=True)
    args = parser.parse_args()
    try:
        if args.command == "inspect":
            result = inspect_bytes(args.artifact.read_bytes())
        elif args.command == "build":
            content, records = build_records(args.record)
            _atomic_write(args.output, content)
            result = inspect_bytes(content)
            result["output"] = str(args.output)
            result["build_records"] = records
        elif args.command == "validate-ftp":
            raw_plan = json.loads(args.plan.read_text(encoding="utf-8"))
            if not isinstance(raw_plan, dict):
                raise ValueError("FTP plan must be a JSON object")
            result = validate_ftp_plan(args.artifact.read_bytes(), raw_plan)
        elif args.command == "materialize-ftp":
            raw_plan = json.loads(args.plan.read_text(encoding="utf-8"))
            if not isinstance(raw_plan, dict):
                raise ValueError("FTP plan must be a JSON object")
            content, result = materialize_ftp(args.record, raw_plan)
            _atomic_write(args.output, content)
            result["output"] = str(args.output)
        else:
            records, plan = ftp_wildcard_transaction(args.pattern)
            content, result = materialize_ftp(records, plan)
            encoded_plan = (json.dumps(plan, sort_keys=True, indent=2) + "\n").encode()
            _atomic_write(args.plan, encoded_plan)
            _atomic_write(args.output, content)
            result["output"] = str(args.output)
            result["plan"] = str(args.plan)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
