#!/usr/bin/env python3
"""oh-red-agent entry point.

Usage:
    # New HTTP probe pipeline (default) — markitdown + LLM identify + consolidated email
    python main.py --subnet 154.52.1.0/24
    python main.py --subnet 154.52.1.0/24 154.52.2.0/24

    # Legacy Gemma4 tool-calling loop
    python main.py --subnet 154.52.1.0/24 --mode agent
    python main.py --subnet 154.52.1.0/24 --ip 154.52.1.28 --mode agent
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from collections import defaultdict

from redteam.config import config
from redteam.tools.kafka import consume_subnet_findings


def setup_logging(debug: bool = False) -> None:
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )
    logging.getLogger("kafka").setLevel(logging.WARNING)


# ---------------------------------------------------------------------------
# New probe pipeline (default)
# ---------------------------------------------------------------------------

async def _run_probe_sweep(subnet: str) -> None:
    from redteam.probes.http_probe import probe_http, consolidate_and_alert, _load_rules
    import redteam.probes.http_probe as m
    m._ESCALATION_RULES = _load_rules()

    log = logging.getLogger(__name__)
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

    # Collect HTTP/S ports per IP
    HTTP_PORTS = {"80", "443", "8080", "8443", "8181", "9090", "9100",
                  "9443", "5601", "1443", "9537"}
    ip_ports: dict[str, set[int]] = defaultdict(set)
    for e in findings["open_ports"]:
        if "http" in str(e.get("service", "")).lower() or str(e.get("port")) in HTTP_PORTS:
            ip_ports[e["ip"]].add(int(e["port"]))

    if not ip_ports:
        log.info("No HTTP/S ports found in %s — skipping", subnet)
        return

    tasks = [(ip, port) for ip, ports in sorted(ip_ports.items()) for port in sorted(ports)]
    log.info("Probe sweep: %d port/IP combos across %d IPs in %s",
             len(tasks), len(ip_ports), subnet)

    sem = asyncio.Semaphore(config.concurrent_ips)
    ip_results: dict[str, list] = defaultdict(list)

    async def run_one(ip: str, port: int) -> None:
        async with sem:
            try:
                result = await probe_http(ip, port, alert=False)
                ip_results[ip].append(result)
                ident = result.identification
                app  = ident.application if ident else "unknown"
                conf = ident.confidence if ident else "-"
                status = "ESCALATE" if result.needs_escalation else "ok"
                log.info("%-22s → %-8s | %-38s | conf=%s",
                         f"{ip}:{port}", status, app, conf)
            except Exception as exc:
                log.error("FAILED %s:%d — %s", ip, port, exc)

    await asyncio.gather(*[run_one(ip, port) for ip, port in tasks])

    # Consolidate and alert per IP
    escalated = 0
    for ip in sorted(ip_results):
        findings_list = [r for r in ip_results[ip] if r.needs_escalation]
        if findings_list:
            escalated += 1
            apps = ", ".join(f"port {r.port} ({r.identification.application if r.identification else '?'})"
                             for r in findings_list)
            log.warning("ESCALATE %s — %s", ip, apps)
            consolidate_and_alert(ip, ip_results[ip])
        else:
            log.info("ok %s", ip)

    log.info("Sweep complete — %d/%d IPs escalated", escalated, len(ip_results))


def run_probe_sweep(subnet: str) -> None:
    asyncio.run(_run_probe_sweep(subnet))


# ---------------------------------------------------------------------------
# Legacy Gemma4 tool-calling loop
# ---------------------------------------------------------------------------

def run_agent(subnet: str, target_ip: str | None = None) -> None:
    from redteam.agent import assess_subnet_sync
    assess_subnet_sync(subnet, target_ip=target_ip)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="oh-red-agent: agentic red team assessment")
    parser.add_argument("--subnet", nargs="+", metavar="CIDR",
                        help="Subnet(s) to assess, e.g. 154.52.1.0/24")
    parser.add_argument("--ip", metavar="IP",
                        help="Limit to a single IP (agent mode only)")
    parser.add_argument("--mode", choices=["probe", "agent"], default="probe",
                        help="probe = new HTTP probe pipeline (default); "
                             "agent = legacy Gemma4 tool-calling loop")
    parser.add_argument("--debug", action="store_true",
                        help="Verbose logging")
    args = parser.parse_args()
    setup_logging(debug=args.debug)

    if not args.subnet:
        parser.print_help()
        sys.exit(1)

    for subnet in args.subnet:
        if args.mode == "probe":
            run_probe_sweep(subnet)
        else:
            run_agent(subnet, target_ip=args.ip)


if __name__ == "__main__":
    main()
