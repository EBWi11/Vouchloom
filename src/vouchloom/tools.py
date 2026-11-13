"""Web tooling for Vouchloom: scope policy, structured HTTP gateway, guarded sandbox.

Adds a named-tool path next to ``sandbox_shell`` so agents can issue structured
HTTP requests (method/url/headers/body as JSON arguments — no shell quoting)
that land in the same CommandReceipt evidence chain as shell commands, plus a
fail-closed scope policy shared by the gateway and the sandbox.

Limitations (deliberate, "simple first" version):
- ``ScopeGuardedSandbox`` inspects http(s) URLs embedded in command text only;
  bare ``nc host port`` style targets are not parsed. Strong isolation still
  requires network-level containment; this layer is the first gate.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

from vouchloom.receipts import CommandReceipt
from vouchloom.runtime import LocalDirectorySandbox, ToolGateway

_URL_RE = re.compile(r"https?://[A-Za-z0-9._~:-]+(?::\d{1,5})?(?:/[^\s\"'`<>]*)?")

MAX_RESPONSE_BODY_BYTES = 8_000
HTTP_TIMEOUT_SECONDS = 30.0


class ScopePolicy:
    """Fail-closed allowlist of hosts/ports an agent may interact with."""

    def __init__(
        self,
        *,
        allowed_hosts: set[str],
        allowed_ports: set[int] | None = None,
    ) -> None:
        self.allowed_hosts = {h.lower() for h in allowed_hosts}
        self.allowed_ports = allowed_ports

    def check_url(self, url: str) -> str | None:
        """Return a violation reason, or None when the URL is in scope."""
        try:
            parts = urlsplit(url)
        except ValueError:
            return f"unparseable url: {url[:120]}"
        host = (parts.hostname or "").lower()
        if parts.scheme not in ("http", "https"):
            return f"scheme not permitted: {parts.scheme!r}"
        if not host:
            return "url has no host"
        if host not in self.allowed_hosts:
            return f"host not in scope allowlist: {host}"
        if self.allowed_ports is not None and parts.port is not None:
            if parts.port not in self.allowed_ports:
                return f"port not in scope allowlist: {parts.port}"
        return None

    def check_target(self, target: str) -> str | None:
        """Bare-host form of check_url for tool targets (nmap-style).

        Accepts ``host``, ``host:port``, ``host/path`` and CIDR notation;
        anything with a scheme is delegated to ``check_url``. IPv6 literals
        are not special-cased (pentest scopes are exact-name allowlists).
        """
        value = target.strip()
        if not value:
            return "empty target"
        if "://" in value:
            return self.check_url(value)
        name = value.rsplit("@", 1)[-1].split("/", 1)[0]
        if name.startswith("["):  # [v6]:port
            name = name[1:].split("]", 1)[0].lower()
        else:
            name = name.split(":", 1)[0].lower()
        if not name:
            return f"unparseable target: {target[:120]}"
        if name not in self.allowed_hosts:
            return f"host not in scope allowlist: {name}"
        return None

    def command_violations(self, command: str) -> list[str]:
        """Extract http(s) URLs from a shell command and check each one."""
        reasons: list[str] = []
        for match in _URL_RE.finditer(command):
            reason = self.check_url(match.group(0).rstrip(".,;)"))
            if reason is not None:
                reasons.append(reason)
        return reasons


HTTP_REQUEST_TOOL_SCHEMA: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "http_request",
        "description": (
            "Issue one HTTP request to an in-scope target and return the "
            "status, headers and (truncated) body as structured JSON."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "method": {
                    "type": "string",
                    "enum": [
                        "GET", "POST", "PUT", "PATCH",
                        "DELETE", "HEAD", "OPTIONS",
                    ],
                },
                "url": {"type": "string", "description": "Absolute http(s) URL."},
                "headers": {
                    "type": "object",
                    "additionalProperties": {"type": "string"},
                },
                "body": {"type": "string", "description": "Raw request body."},
                "follow_redirects": {"type": "boolean"},
            },
            "required": ["method", "url"],
            "additionalProperties": False,
        },
    },
}

# Generic discovery list: docs/spec endpoints, common API and app prefixes,
# admin/auth entry points, server management faces, sensitive files and
# static roots. Deliberately application-agnostic — context roots that the
# landing page does not link (apps mounted off /) surface here via
# /manager, /console, /api style prefixes, and cookie/link extraction is
# the agent's job on top of these leads.
DEFAULT_DISCOVERY_PATHS: list[str] = [
    "/robots.txt", "/sitemap.xml", "/openapi.json", "/swagger.json",
    "/v2/api-docs", "/docs", "/redoc", "/graphql",
    "/api", "/api/v1", "/rest", "/actuator", "/health", "/metrics", "/status",
    "/admin", "/login", "/signin", "/register", "/signup", "/auth", "/console",
    "/manager", "/host-manager", "/manager/html", "/examples", "/javadoc",
    "/.git/HEAD", "/.env", "/backup.zip", "/server-status",
    "/static", "/assets", "/public", "/uploads", "/js", "/files",
    # High-frequency application context roots (standard pentest wordlist
    # entries): when an app is mounted off /, these are where it lives.
    "/app", "/application", "/main", "/web", "/portal", "/demo", "/sample",
    "/test", "/v2", "/old", "/swagger-ui.html", "/h2-console",
    "/WebGoat", "/webwolf", "/petclinic", "/jenkins", "/grafana", "/kibana",
    "/solr", "/nexus", "/sonarqube", "/jira", "/confluence",
]

MAX_PROBE_PATHS = 96

PROBE_PATHS_TOOL_SCHEMA: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "probe_paths",
        "description": (
            "Batch-probe paths on one in-scope base URL with GET requests "
            "and return only the leads: entries whose status is NOT 404, "
            "each with status, content-type, redirect location and a short "
            "body head. Omit 'paths' to use the built-in generic discovery "
            "list (docs/spec endpoints, API prefixes, admin/auth faces, "
            "server management paths, sensitive files)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "base_url": {
                    "type": "string",
                    "description": "Absolute http(s) base URL without a path.",
                },
                "paths": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Paths to probe, e.g. ['/api', '/admin'].",
                },
            },
            "required": ["base_url"],
            "additionalProperties": False,
        },
    },
}


class HttpRequestGateway(ToolGateway):
    """Structured HTTP tool: request/response land in the receipt chain.

    Every call becomes a ``CommandReceipt`` whose ``command`` field is the
    canonical JSON of the request — deterministic, replayable, and free of
    shell-quoting hazards (SQLi payloads quote freely).
    """

    def __init__(
        self, *, policy: ScopePolicy, timeout_seconds: float = HTTP_TIMEOUT_SECONDS
    ) -> None:
        self.policy = policy
        self._client = httpx.AsyncClient(
            timeout=timeout_seconds,
            follow_redirects=False,
        )

    def tool_schemas(self) -> list[dict[str, Any]]:
        return [HTTP_REQUEST_TOOL_SCHEMA, PROBE_PATHS_TOOL_SCHEMA]

    async def execute(
        self, name: str, arguments: dict[str, Any], *, sequence: int
    ) -> CommandReceipt:
        started = time.monotonic_ns()
        if name == "probe_paths":
            return await self._execute_probe_paths(
                arguments, sequence=sequence, started=started
            )
        if name != "http_request":
            return self._receipt(
                sequence,
                json.dumps({"tool": name}, sort_keys=True),
                f"unknown tool: {name}",
                127,
                started,
            )
        method = str(arguments.get("method") or "GET").upper()
        url = str(arguments.get("url") or "")
        headers = {
            str(k): str(v)
            for k, v in (arguments.get("headers") or {}).items()
            if isinstance(v, str)
        }
        body = arguments.get("body")
        body = body if isinstance(body, str) else None
        follow = bool(arguments.get("follow_redirects", False))
        command = json.dumps(
            {"method": method, "url": url, "headers": headers, "body": body},
            sort_keys=True,
            ensure_ascii=False,
        )
        violation = self.policy.check_url(url)
        if violation is not None:
            return self._receipt(
                sequence, command, f"scope violation: {violation}", 126, started
            )
        try:
            resp = await self._client.request(
                method,
                url,
                headers=headers or None,
                content=body,
                follow_redirects=follow,
            )
        except httpx.TimeoutException:
            return self._receipt(
                sequence, command, "http request timed out", 124, started
            )
        except httpx.HTTPError as err:
            return self._receipt(
                sequence, command, f"http transport error: {err}", 4, started
            )
        out = {
            "status_code": resp.status_code,
            "reason": resp.reason_phrase,
            "headers": dict(resp.headers),
            "body": resp.text[:MAX_RESPONSE_BODY_BYTES],
            "body_truncated": len(resp.text) > MAX_RESPONSE_BODY_BYTES,
        }
        output = json.dumps(out, ensure_ascii=False)
        return self._receipt(sequence, command, output, 0, started)

    async def _execute_probe_paths(
        self,
        arguments: dict[str, Any],
        *,
        sequence: int,
        started: int,
    ) -> CommandReceipt:
        base_url = str(arguments.get("base_url") or "").rstrip("/")
        raw_paths = arguments.get("paths")
        paths = (
            [str(p) for p in raw_paths if isinstance(raw_paths, list)]
            if isinstance(raw_paths, list)
            else list(DEFAULT_DISCOVERY_PATHS)
        )
        paths = [
            p if p.startswith("/") else f"/{p}" for p in paths[:MAX_PROBE_PATHS]
        ]
        command = json.dumps(
            {"tool": "probe_paths", "base_url": base_url, "paths": paths},
            ensure_ascii=False,
        )
        violation = self.policy.check_url(f"{base_url}/")
        if violation is not None or not paths:
            return self._receipt(
                sequence,
                command,
                f"scope violation: {violation}" if violation else "no paths to probe",
                126,
                started,
                tool_name="probe_paths",
            )

        async def _probe_one(path: str) -> tuple[str, httpx.Response | None, str | None]:
            try:
                resp = await self._client.get(base_url + path)
                return path, resp, None
            except httpx.HTTPError as err:
                return path, None, str(err)

        probed = await asyncio.gather(*(_probe_one(p) for p in paths))
        leads: list[dict[str, Any]] = []
        not_found = 0
        for path, resp, err in probed:
            if err is not None:
                leads.append({"path": path, "error": err[:120]})
                continue
            if resp.status_code == 404:
                not_found += 1
                continue
            leads.append(
                {
                    "path": path,
                    "status": resp.status_code,
                    "content_type": resp.headers.get("content-type", ""),
                    "location": resp.headers.get("location", ""),
                    "body_head": resp.text[:160],
                }
            )
        out = {
            "probed": len(paths),
            "not_found_404": not_found,
            "leads": leads,
        }
        return self._receipt(
            sequence,
            command,
            json.dumps(out, ensure_ascii=False),
            0,
            started,
            tool_name="probe_paths",
        )

    def _receipt(
        self,
        sequence: int,
        command: str,
        output: str,
        exit_code: int,
        started: int,
        *,
        tool_name: str = "http_request",
    ) -> CommandReceipt:
        duration_ms = (time.monotonic_ns() - started) // 1_000_000
        return CommandReceipt.from_execution(
            tool_name=tool_name,
            sequence=sequence,
            command=command,
            output=output,
            exit_code=exit_code,
            duration_ms=duration_ms,
        )

    async def aclose(self) -> None:
        await self._client.aclose()


class ScopeGuardedSandbox(LocalDirectorySandbox):
    """LocalDirectorySandbox that refuses commands referencing out-of-scope URLs.

    Refusal still produces a receipt (exit code 126) so scope events are part
    of the audit trail; the command itself never executes.
    """

    def __init__(
        self,
        work_root: Path,
        *,
        policy: ScopePolicy,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
    ) -> None:
        super().__init__(work_root, cwd=cwd, env=env)
        self.policy = policy

    async def execute_command(
        self, command: str, *, sequence: int, timeout_seconds: float = 120.0
    ) -> CommandReceipt:
        violations = self.policy.command_violations(command)
        if violations:
            return CommandReceipt.from_execution(
                tool_name="sandbox_shell",
                sequence=sequence,
                command=command,
                output="scope violation: " + "; ".join(violations),
                exit_code=126,
            )
        return await super().execute_command(
            command, sequence=sequence, timeout_seconds=timeout_seconds
        )


__all__ = [
    "HTTP_REQUEST_TOOL_SCHEMA",
    "HttpRequestGateway",
    "ScopeGuardedSandbox",
    "ScopePolicy",
]
