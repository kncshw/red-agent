#!/bin/bash
# Cron: run red team assessment for a specific subnet
# Usage: cron_run_redteam.sh 154.52.1.0/24
# Example crontab: 30 8 * * * /home/bis/oh-red-agent/cron_run_redteam.sh 154.52.1.0/24

set -euo pipefail

SUBNET="${1:-}"
if [ -z "$SUBNET" ]; then
    echo "Usage: $0 <subnet CIDR>"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

source .env 2>/dev/null || true

python main.py --subnet "$SUBNET"
