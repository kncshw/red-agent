"""FortiSOAR red team finding ticket creation.

HMAC auth stripped from OpenHarness _fortisoar_helpers.py (MIT License).
Creates a vulnerability ticket enriched with red team exploitation findings.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import time
from datetime import datetime
from typing import Any

import httpx

from .base import BaseTool, ToolResult

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# HMAC auth (copied verbatim from oh-soc-agent — do not modify)
# ---------------------------------------------------------------------------

def _read_key(path: str) -> str:
    with open(path) as f:
        return f.read().strip()


def _hmac_header(method: str, full_url: str, payload: str, private_key: str, public_key: str) -> str:
    if method == "GET":
        payload = public_key
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    payload_bytes = payload.encode() if isinstance(payload, str) else payload
    digest = hashlib.new("sha256")
    digest.update(payload_bytes)
    hashed = digest.hexdigest()
    raw = f"sha256.{method}.{timestamp}.{full_url}.{hashed}"
    sig = hmac.new(private_key.encode(), raw.encode(), hashlib.sha256).hexdigest()
    header_plain = f"sha256;{timestamp};{public_key};{sig}"
    return "CS " + base64.b64encode(header_plain.encode()).decode()


# ---------------------------------------------------------------------------
# Tool
# ---------------------------------------------------------------------------

class FortiSOARCreateTicketTool(BaseTool):
    name = "fortisoar_create_ticket"
    description = (
        "Create a red team finding ticket in FortiSOAR. "
        "Call this once you have completed your Kali investigation and have "
        "gathered sufficient evidence of exploitable services or misconfigurations. "
        "Include all evidence, attack paths, and exploitation steps in your findings."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "subject": {
                "type": "string",
                "description": "Short title for the finding (e.g. 'Unauthenticated Jupyter on 154.52.1.10:8888')",
            },
            "severity": {
                "type": "string",
                "enum": ["Critical", "High", "Medium", "Low"],
                "description": "Severity based on real-world exploitability, not CVSS.",
            },
            "findings": {
                "type": "string",
                "description": (
                    "Full red team assessment: what was found, how it was confirmed "
                    "(include actual command outputs as evidence), attack path, "
                    "and potential impact. Be specific and evidence-based."
                ),
            },
            "affected_hosts": {
                "type": "string",
                "description": "Comma-separated list of affected IP:port pairs.",
            },
        },
        "required": ["subject", "severity", "findings", "affected_hosts"],
    }

    def __init__(
        self,
        fsr_url: str,
        public_key_file: str,
        private_key_file: str,
        verify_ssl: bool = False,
    ) -> None:
        self._url = fsr_url.rstrip("/")
        self._public_key = _read_key(public_key_file)
        self._private_key = _read_key(private_key_file)
        self._verify_ssl = verify_ssl

    async def execute(self, arguments: dict[str, Any]) -> ToolResult:
        payload_dict = {
            "vulnerabilitySubject": arguments["subject"],
            "severity": arguments["severity"],
            "scanResult": arguments["findings"],
            "scanID": arguments["affected_hosts"],
            "vulnerabilityID": f"redteam-{int(time.time())}",
            "cVSS": 0.0,
            "cVENames": "",
            "solution": "",
            "synopsis": "Red team finding — active exploitation evidence",
            "scanDateTime": int(time.time()),
            "description": "[Triaged by oh-red-agent]",
        }

        endpoint = "/api/3/vulnerability_tickets"
        full_url = f"{self._url}{endpoint}"
        body = json.dumps(payload_dict)
        auth = _hmac_header("POST", full_url, body, self._private_key, self._public_key)
        headers = {"Authorization": auth, "Content-Type": "application/json"}

        log.info("Creating FortiSOAR red team ticket: %s", arguments["subject"])
        try:
            async with httpx.AsyncClient(verify=self._verify_ssl, timeout=30.0) as client:
                resp = await client.post(full_url, headers=headers, content=body)
                resp.raise_for_status()
            return ToolResult(output=f"Ticket created: {arguments['subject']} [{arguments['severity']}]")
        except httpx.HTTPStatusError as exc:
            return ToolResult(
                output=f"FortiSOAR error {exc.response.status_code}: {exc.response.text[:300]}",
                is_error=True,
            )
        except Exception as exc:
            return ToolResult(output=f"FortiSOAR connection error: {exc}", is_error=True)
