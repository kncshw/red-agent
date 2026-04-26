"""Kali sandbox FastAPI tool server.

Receives shell commands from oh-red-agent, executes them in the Kali
environment, and returns the output. Bearer token authentication.

Every command is logged for audit purposes.
"""

from __future__ import annotations

import asyncio
import logging
import os
import subprocess
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

TOKEN = os.environ.get("KALI_API_TOKEN", "")
COMMAND_TIMEOUT = int(os.environ.get("COMMAND_TIMEOUT", "120"))
MAX_OUTPUT = int(os.environ.get("MAX_OUTPUT_CHARS", "8000"))

if not TOKEN:
    raise RuntimeError("KALI_API_TOKEN environment variable is required")

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(title="Kali Sandbox", docs_url=None, redoc_url=None)


def _verify_token(request: Request) -> None:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer ") or auth[7:] != TOKEN:
        log.warning("Unauthorized request from %s", request.client.host if request.client else "unknown")
        raise HTTPException(status_code=401, detail="Unauthorized")


class ExecuteRequest(BaseModel):
    command: str


class ExecuteResponse(BaseModel):
    output: str
    exit_code: int
    error: str | None = None


@app.get("/health")
async def health():
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.post("/execute", response_model=ExecuteResponse)
async def execute(request: Request, body: ExecuteRequest):
    _verify_token(request)

    command = body.command.strip()
    if not command:
        raise HTTPException(status_code=400, detail="Empty command")

    client_ip = request.client.host if request.client else "unknown"
    log.info("EXECUTE from=%s cmd=%r", client_ip, command)

    try:
        result = await asyncio.wait_for(
            _run_command(command),
            timeout=COMMAND_TIMEOUT + 5,
        )
        return result
    except asyncio.TimeoutError:
        log.warning("Command timed out: %r", command)
        return ExecuteResponse(
            output="",
            exit_code=-1,
            error=f"Command timed out after {COMMAND_TIMEOUT}s",
        )


async def _run_command(command: str) -> ExecuteResponse:
    try:
        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            executable="/bin/bash",
        )
        try:
            stdout, _ = await asyncio.wait_for(
                proc.communicate(),
                timeout=COMMAND_TIMEOUT,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return ExecuteResponse(
                output="",
                exit_code=-1,
                error=f"Command timed out after {COMMAND_TIMEOUT}s",
            )

        output = stdout.decode("utf-8", errors="replace")

        # Truncate large output — keep first half + last half
        if len(output) > MAX_OUTPUT:
            half = MAX_OUTPUT // 2
            dropped = len(output) - MAX_OUTPUT
            output = (
                output[:half]
                + f"\n... [{dropped} chars truncated] ...\n"
                + output[-half:]
            )

        exit_code = proc.returncode or 0
        log.info("DONE exit_code=%d output_len=%d", exit_code, len(output))
        return ExecuteResponse(output=output, exit_code=exit_code)

    except Exception as exc:
        log.error("Command execution error: %s", exc, exc_info=True)
        return ExecuteResponse(output="", exit_code=-1, error=str(exc))
