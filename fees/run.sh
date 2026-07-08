#!/usr/bin/env bash
# Reproduce the empirical fee-cost result.
#
# fetch.py hits a public archive RPC and is a one-time data-collection step;
# its output (fees/data/basefee.csv.gz) is committed, so you do NOT need to
# refetch to reproduce the analysis. analyze.py is a pure function of the
# committed data plus the committed gas numbers in bench/results, and is what
# CI re-runs to drift-check fees/results.
#
#   fees/run.sh            # recompute analysis from committed data (offline)
#   fees/run.sh --refetch  # also re-pull the base-fee sample (needs network)
set -euo pipefail
cd "$(dirname "$0")/.."

if [ "${1:-}" = "--refetch" ]; then
  python3 fees/fetch.py
fi
python3 fees/analyze.py
