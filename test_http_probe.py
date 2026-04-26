"""Quick test — probe 69.167.115.145:9090 (Prometheus, no auth expected)."""

import asyncio
import logging
from redteam.probes.http_probe import probe_http

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

async def main():
    result = await probe_http("69.167.115.145", 9090)

    print(f"\n=== RESULT ===")
    print(f"URL         : {result.url}")
    print(f"HTTP Status : {result.http_status}")
    if result.identification:
        i = result.identification
        print(f"Application : {i.application} {('v'+i.version) if i.version else ''}")
        print(f"Auth        : {'YES — ' + i.auth_type if i.has_auth else 'NO AUTH'}")
        print(f"Confidence  : {i.confidence}")
        print(f"Evidence    : {i.evidence}")
    print(f"Escalated   : {result.needs_escalation}")

asyncio.run(main())
