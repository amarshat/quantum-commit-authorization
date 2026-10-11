#!/usr/bin/env bash
# Reproduce the builder share / persistence / run measurement.
#
# fetch.py pulls block headers from a public archive RPC once; its output
# (builders/data/blocks.csv.gz) is committed, so the analysis runs offline.
# relay_check.py cross-checks the attribution against mev-boost relay records
# and also needs the network; its result is committed in builders/results.
#
#   builders/run.sh            # recompute from committed data (offline)
#   builders/run.sh --refetch  # also re-pull headers and re-run the relay check
set -euo pipefail
cd "$(dirname "$0")/.."

if [ "${1:-}" = "--refetch" ]; then
  python3 builders/fetch.py
  python3 builders/relay_check.py
fi
python3 builders/analyze.py >/dev/null
python3 builders/analyze.py --variant=buildernet_operators >/dev/null
echo "wrote builders/results/"
