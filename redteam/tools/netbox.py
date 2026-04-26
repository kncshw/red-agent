"""NetBox IP ownership lookup.

Copied from OpenHarness _netbox_helpers.py (MIT License).
Used by the outer loop to enrich subnet findings before passing to the agent.
"""

from __future__ import annotations

import ipaddress
import logging
import os
from typing import Any

log = logging.getLogger(__name__)

_ip_cache: dict[str, str] = {}
_subnet_cache: dict[str, str | None] = {}


def lookup_ip(ip: str, api_url: str, api_token: str, verify_ssl: bool = False) -> str:
    """Return a human-readable owner/description string for the IP, or 'unknown'."""
    if ip in _ip_cache:
        return _ip_cache[ip]

    if not api_url or not api_token:
        return "NetBox not configured"

    try:
        import pynetbox
        import requests
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        api = pynetbox.api(url=api_url, token=api_token)
        if not verify_ssl:
            session = requests.Session()
            session.verify = False
            api.http_session = session

        # 1. Exact IP match
        ip_obj = api.ipam.ip_addresses.get(address=ip)
        if ip_obj and ip_obj.description:
            result = str(ip_obj.description)
            _ip_cache[ip] = result
            return result

        # 2. Containing subnet (walk /24 → /20 → /16)
        descriptions = []
        for prefix_len in (24, 20, 16):
            try:
                network = ipaddress.ip_network(f"{ip}/{prefix_len}", strict=False)
                subnet_key = f"{network.network_address}/{prefix_len}"
                prefixes = list(api.ipam.prefixes.filter(q=subnet_key))
                for p in prefixes:
                    if p.description:
                        descriptions.append(f"{p}: {p.description}")
            except Exception:
                continue

        if descriptions:
            result = " | ".join(dict.fromkeys(descriptions))
            _ip_cache[ip] = result
            return result

        _ip_cache[ip] = "unknown"
        return "unknown"

    except Exception as exc:
        log.warning("NetBox lookup failed for %s: %s", ip, exc)
        return "NetBox lookup error"
