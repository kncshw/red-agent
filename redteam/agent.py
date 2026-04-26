"""Red team agent — the core loop.

Outer loop: fetch Kafka findings + NetBox enrichment, then run agent per subnet.
Inner loop: Gemma4 drives Kali tool calls until investigation complete.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from .config import config
from .llm import LLMClient, Message, TextBlock, ToolResultBlock, ToolUseBlock
from .prompt import SYSTEM_PROMPT
from .tools.base import BaseTool, ToolResult
from .tools.fortisoar import FortiSOARCreateTicketTool
from .tools.kali import KaliExecuteTool
from .tools.kafka import consume_subnet_findings
from .tools.netbox import lookup_ip

log = logging.getLogger(__name__)

# Services to skip entirely — not worth red team assessment
SKIP_CERT_PATTERNS = [
    "fortimail", "fortimailcloud",
]


async def _cert_subject(ip: str, kali: "KaliExecuteTool") -> str:
    """Quick cert grab — returns lowercased subject string or empty."""
    result = await kali.execute({
        "command": f"echo | openssl s_client -connect {ip}:443 2>/dev/null | openssl x509 -noout -subject 2>/dev/null"
    })
    return result.output.lower() if result.output else ""


async def _should_skip(ip: str, kali: "KaliExecuteTool") -> bool:
    """Return True if the cert identifies a service we skip."""
    subject = await _cert_subject(ip, kali)
    if not subject:
        return False
    matched = [p for p in SKIP_CERT_PATTERNS if p in subject]
    if matched:
        log.info("SKIPPED %s — cert matches skip pattern: %s (%s)", ip, matched, subject.strip())
        return True
    return False


# ---------------------------------------------------------------------------
# Tool registry
# ---------------------------------------------------------------------------

def build_tools(subnet: str) -> list[BaseTool]:
    tools: list[BaseTool] = []

    tools.append(KaliExecuteTool(
        api_url=config.kali_api_url,
        api_token=config.kali_api_token,
        authorized_subnet=subnet,
    ))

    if config.enable_fortisoar and config.fortisoar_url and config.fortisoar_public_key_file:
        tools.append(FortiSOARCreateTicketTool(
            fsr_url=config.fortisoar_url,
            public_key_file=config.fortisoar_public_key_file,
            private_key_file=config.fortisoar_private_key_file,
            verify_ssl=config.fortisoar_verify_ssl,
        ))

    return tools


# ---------------------------------------------------------------------------
# Agent inner loop
# ---------------------------------------------------------------------------

async def run_agent_for_subnet(subnet: str, findings: dict[str, Any]) -> None:
    """Run Gemma4 red team agent for one subnet."""
    log.info("Starting red team assessment for %s", subnet)

    llm = LLMClient(
        base_url=config.vllm_base_url,
        model=config.vllm_model,
        api_key=config.vllm_api_key,
        temperature=config.vllm_temperature,
        verify_ssl=config.vllm_verify_ssl,
    )
    tools = build_tools(subnet)
    tool_map = {t.name: t for t in tools}
    tool_schemas = [t.to_api_schema() for t in tools]

    # Initial message: hand Gemma4 the pre-processed findings
    initial_content = (
        f"Subnet under assessment: {subnet}\n"
        f"Asset owner: {findings.get('owner', 'unknown')}\n\n"
        f"Nessus findings (JSON):\n{json.dumps(findings, indent=2)}\n\n"
        "Begin your red team assessment. Probe the open services, gather evidence, "
        "and create FortiSOAR tickets for confirmed findings."
    )

    messages: list[Message] = [
        Message(role="user", content=[TextBlock(text=initial_content)])
    ]

    for round_num in range(1, config.max_tool_rounds + 1):
        log.info("[%s] Round %d/%d", subnet, round_num, config.max_tool_rounds)

        response = await llm.call(
            messages=messages,
            system_prompt=SYSTEM_PROMPT,
            tools=tool_schemas,
        )
        messages.append(response)

        tool_uses = [b for b in response.content if isinstance(b, ToolUseBlock)]

        # No tool calls — agent is done
        if not tool_uses:
            text_blocks = [b for b in response.content if isinstance(b, TextBlock)]
            final_text = "".join(b.text for b in text_blocks)
            log.info("[%s] Assessment complete:\n%s", subnet, final_text)
            break

        # Execute all tool calls (parallel where possible)
        tool_results = await asyncio.gather(*[
            _execute_tool(tool_map, tu) for tu in tool_uses
        ])

        # Append tool results as user message
        result_blocks = []
        for tu, result in zip(tool_uses, tool_results):
            log.debug(
                "TOOL RESULT [%s]:\n  input:  %s\n  output: %s\n  error:  %s",
                tu.name,
                json.dumps(tu.input, default=str),
                result.output[:500] if result.output else "(none)",
                result.is_error,
            )
            result_blocks.append(ToolResultBlock(
                tool_use_id=tu.id,
                content=result.output,
                is_error=result.is_error,
            ))
        messages.append(Message(role="user", content=result_blocks))

    else:
        log.warning("[%s] Reached max tool rounds (%d)", subnet, config.max_tool_rounds)


async def _execute_tool(tool_map: dict[str, BaseTool], tu: ToolUseBlock) -> ToolResult:
    tool = tool_map.get(tu.name)
    if tool is None:
        return ToolResult(output=f"Unknown tool: {tu.name}", is_error=True)
    try:
        return await tool.execute(tu.input)
    except Exception as exc:
        log.error("Tool %s failed: %s", tu.name, exc, exc_info=True)
        return ToolResult(output=f"Tool error: {exc}", is_error=True)


# ---------------------------------------------------------------------------
# Outer loop — fetches Kafka findings, enriches with NetBox, runs agent
# ---------------------------------------------------------------------------

async def assess_subnet(subnet: str, target_ip: str | None = None) -> None:
    """Fetch findings from Kafka, enrich with NetBox, run agent."""
    bootstrap = f"{config.kafka_host}:{config.kafka_port}"

    findings = consume_subnet_findings(
        subnet=subnet,
        bootstrap_servers=bootstrap,
        username=config.kafka_username,
        password=config.kafka_password,
        hours=config.kafka_time_window_hours,
    )

    if not findings["vulnerabilities"] and not findings["open_ports"]:
        log.info("No findings for subnet %s — skipping", subnet)
        return

    # Determine which IPs to assess
    all_ips = sorted({
        e["ip"] for e in findings["vulnerabilities"] + findings["open_ports"]
        if e.get("ip")
    })

    if target_ip:
        all_ips = [target_ip] if target_ip in all_ips else []
        if not all_ips:
            log.info("No findings for IP %s — skipping", target_ip)
            return

    log.info("Assessing %d IP(s) in %s (concurrency=%d): %s",
             len(all_ips), subnet, config.concurrent_ips, ", ".join(all_ips))

    # Build per-IP findings list upfront
    all_ip_findings = []
    for ip in all_ips:
        ip_findings = {
            "subnet": subnet,
            "vulnerabilities": [v for v in findings["vulnerabilities"] if v.get("ip") == ip],
            "open_ports":      [p for p in findings["open_ports"]      if p.get("ip") == ip],
        }
        if not ip_findings["vulnerabilities"] and not ip_findings["open_ports"]:
            continue
        if config.netbox_api_url and config.netbox_api_token:
            owner = lookup_ip(ip, config.netbox_api_url, config.netbox_api_token, config.netbox_verify_ssl)
            ip_findings["ip_owners"] = {ip: owner}
            ip_findings["owner"] = owner
        all_ip_findings.append((ip, ip_findings))

    # Run concurrently with semaphore to limit parallel workers
    semaphore = asyncio.Semaphore(config.concurrent_ips)

    async def assess_one(ip: str, ip_findings: dict) -> None:
        async with semaphore:
            # Pre-screen: skip known low-value services
            kali = KaliExecuteTool(
                api_url=config.kali_api_url,
                api_token=config.kali_api_token,
                authorized_subnet=subnet,
            )
            if await _should_skip(ip, kali):
                return
            log.info("--- IP %s: %d vulns, %d open ports ---",
                     ip, len(ip_findings["vulnerabilities"]), len(ip_findings["open_ports"]))
            await run_agent_for_subnet(subnet, ip_findings)

    await asyncio.gather(*[assess_one(ip, f) for ip, f in all_ip_findings])


def assess_subnet_sync(subnet: str, target_ip: str | None = None) -> None:
    asyncio.run(assess_subnet(subnet, target_ip=target_ip))
