"""Kafka subnet findings consumer.

Consumes vulnerability.detected and openport.detected events
for a given subnet from the last N hours.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

log = logging.getLogger(__name__)


def _topic_from_subnet(subnet: str) -> str:
    """Convert '154.52.1.0/24' → 'subnet-154-52-1-0_24'."""
    network = subnet.split("/")[0]
    octets = network.split(".")
    return f"subnet-{octets[0]}-{octets[1]}-{octets[2]}-0_24"


def consume_subnet_findings(
    subnet: str,
    bootstrap_servers: str,
    username: str,
    password: str,
    hours: int = 26,
) -> dict[str, Any]:
    """Consume all vulnerability and open port events for a subnet.

    Returns a structured dict:
    {
        "subnet": "154.52.1.0/24",
        "vulnerabilities": [   # vulnerability.detected events
            {"ip": ..., "port": ..., "plugin": ..., "cvss": ..., "cve": ..., ...}
        ],
        "open_ports": [        # openport.detected events
            {"ip": ..., "port": ..., "service": ...}
        ]
    }
    """
    from kafka import KafkaConsumer
    from kafka.errors import KafkaError

    topic = _topic_from_subnet(subnet)
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    cutoff_ms = int(cutoff.timestamp() * 1000)

    vulnerabilities: list[dict] = []
    open_ports: list[dict] = []

    try:
        consumer = KafkaConsumer(
            topic,
            bootstrap_servers=bootstrap_servers,
            security_protocol="SASL_PLAINTEXT",
            sasl_mechanism="PLAIN",
            sasl_plain_username=username,
            sasl_plain_password=password,
            auto_offset_reset="earliest",
            consumer_timeout_ms=10_000,
            value_deserializer=lambda v: json.loads(v.decode("utf-8")),
            api_version=(2, 0, 0),
            group_id=None,  # no commit — read-only
        )

        # Seek to the time offset
        topic_partitions = consumer.assignment()
        consumer.poll(0)  # trigger partition assignment
        topic_partitions = consumer.assignment()

        offsets = consumer.offsets_for_times(
            {tp: cutoff_ms for tp in topic_partitions}
        )
        for tp, offset_and_ts in offsets.items():
            if offset_and_ts:
                consumer.seek(tp, offset_and_ts.offset)

        for msg in consumer:
            try:
                data = msg.value
                metadata = data.get("metadata", {})
                payload = data.get("payload", {})
                event_type = metadata.get("eventType", "")
                ts_str = metadata.get("timestamp", "")

                # Skip messages older than our window
                if ts_str:
                    try:
                        ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                        if ts < cutoff:
                            continue
                    except ValueError:
                        pass

                if event_type == "vulnerability.detected":
                    vulnerabilities.append({
                        "ip": payload.get("ip"),
                        "ports": payload.get("ports", []),
                        "plugin": payload.get("vulnerabilityID", ""),
                        "name": payload.get("vulnerabilitySubject", ""),
                        "cvss": payload.get("cVSS", 0.0),
                        "cve": payload.get("cVENames", ""),
                        "severity": payload.get("severity", ""),
                        "synopsis": payload.get("synopsis", ""),
                        "solution": payload.get("solution", ""),
                    })

                elif event_type == "openport.detected":
                    open_ports.append({
                        "ip": payload.get("ip"),
                        "port": payload.get("port"),
                        "service": payload.get("service", ""),
                        "protocol": payload.get("protocol", "tcp"),
                    })

            except Exception as exc:
                log.warning("Failed to parse Kafka message: %s", exc)

        consumer.close()

    except KafkaError as exc:
        log.error("Kafka consumer error for %s: %s", subnet, exc)

    log.info(
        "Consumed subnet %s: %d vulns, %d open ports",
        subnet, len(vulnerabilities), len(open_ports),
    )
    return {
        "subnet": subnet,
        "vulnerabilities": vulnerabilities,
        "open_ports": open_ports,
    }
