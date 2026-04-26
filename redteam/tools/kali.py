"""Kali sandbox tool — FastAPI bridge with scope enforcement.

Sends shell commands to the remote Kali Linux FastAPI server.
Every command is validated against the authorized subnet before execution.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from typing import Any

import httpx

from .base import BaseTool, ToolResult

log = logging.getLogger(__name__)

# Matches IPv4 addresses in command strings
_IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

# Max output returned to the agent — prevents context overflow
_MAX_OUTPUT = 8_000


class KaliExecuteTool(BaseTool):
    name = "kali_execute"
    description = (
        "Execute a shell command in the Kali Linux security testing sandbox. "
        "All standard Kali tools are available (nmap, nikto, gobuster, curl, "
        "whatweb, openssl, enum4linux, hydra, sqlmap, etc.). "
        "Commands are executed against the current subnet under assessment. "
        "Only target IPs within the authorized subnet — others will be blocked. "
        "Use this to probe open services, check authentication, enumerate paths, "
        "fingerprint technologies, and gather exploitation evidence."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "command": {
                "type": "string",
                "description": "Shell command to execute in the Kali sandbox.",
            }
        },
        "required": ["command"],
    }

    def __init__(self, api_url: str, api_token: str, authorized_subnet: str) -> None:
        self._api_url = api_url.rstrip("/")
        self._token = api_token
        self._authorized_network = ipaddress.ip_network(authorized_subnet, strict=False)

    def _check_scope(self, command: str) -> str | None:
        """Return an error string if command targets an out-of-scope IP, else None."""
        for match in _IP_RE.finditer(command):
            ip_str = match.group(1)
            try:
                ip = ipaddress.ip_address(ip_str)
                if ip not in self._authorized_network:
                    return f"BLOCKED: {ip_str} is outside authorized subnet {self._authorized_network}"
            except ValueError:
                continue
        return None

    async def execute(self, arguments: dict[str, Any]) -> ToolResult:
        command = arguments.get("command", "").strip()
        if not command:
            return ToolResult(output="No command provided.", is_error=True)

        scope_error = self._check_scope(command)
        if scope_error:
            log.warning("Scope violation blocked: %s", command)
            return ToolResult(output=scope_error, is_error=True)

        log.info("Kali execute: %s", command)
        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                resp = await client.post(
                    f"{self._api_url}/execute",
                    json={"command": command},
                    headers={"Authorization": f"Bearer {self._token}"},
                )
                resp.raise_for_status()
                data = resp.json()

            if data.get("error"):
                return ToolResult(output=str(data["error"]), is_error=True)

            output = data.get("output", "")
            if len(output) > _MAX_OUTPUT:
                half = _MAX_OUTPUT // 2
                output = (
                    output[:half]
                    + f"\n... [truncated {len(output) - _MAX_OUTPUT} chars] ...\n"
                    + output[-half:]
                )
            return ToolResult(output=output or "(no output)")

        except httpx.HTTPStatusError as exc:
            return ToolResult(output=f"Kali server error {exc.response.status_code}: {exc.response.text[:200]}", is_error=True)
        except Exception as exc:
            return ToolResult(output=f"Kali connection error: {exc}", is_error=True)
