#!/usr/bin/env python3
"""oh-red-agent entry point.

Usage:
    python main.py --subnet 154.52.1.0/24
    python main.py --subnet 154.52.1.0/24 154.52.2.0/24
    python main.py --all-active   # assess all subnets with findings in Kafka
"""

from __future__ import annotations

import argparse
import logging
import sys

from redteam.agent import assess_subnet_sync
from redteam.config import config


def setup_logging(debug: bool = False) -> None:
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )
    # Keep kafka noise at WARNING even in debug mode
    logging.getLogger("kafka").setLevel(logging.WARNING)


def main() -> None:
    parser = argparse.ArgumentParser(description="oh-red-agent: agentic red team assessment")
    parser.add_argument(
        "--subnet",
        nargs="+",
        metavar="CIDR",
        help="Subnet(s) to assess, e.g. 154.52.1.0/24",
    )
    parser.add_argument(
        "--ip",
        metavar="IP",
        help="Limit assessment to a single IP within the subnet, e.g. 154.52.1.28",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Show full JSON exchange with Gemma4 and tool results",
    )
    args = parser.parse_args()
    setup_logging(debug=args.debug)

    if not args.subnet:
        parser.print_help()
        sys.exit(1)

    for subnet in args.subnet:
        assess_subnet_sync(subnet, target_ip=args.ip)


if __name__ == "__main__":
    main()
