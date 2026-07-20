#!/usr/bin/env bash
# One-command demo: boot a local chain, run the attack suite past every defense
# arm, print the scorecard. Requires only Foundry (anvil, cast, forge) and
# python3 (stdlib only). No pip / npm installs.
set -euo pipefail

cd "$(dirname "$0")"
RPC="http://127.0.0.1:8545"

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing '$1' (install Foundry: https://getfoundry.sh)"; exit 1; }; }
need anvil; need cast; need forge; need python3

forge build >/dev/null

STARTED_ANVIL=0
if ! cast block-number --rpc-url "$RPC" >/dev/null 2>&1; then
  echo "starting anvil..."
  # --hardfork prague is required for the EIP-7702 attack (row G)
  anvil --silent --hardfork prague --port 8545 >out/anvil.log 2>&1 &
  ANVIL_PID=$!
  STARTED_ANVIL=1
  trap '[ "$STARTED_ANVIL" = 1 ] && kill "$ANVIL_PID" 2>/dev/null || true' EXIT
  for _ in $(seq 1 50); do cast block-number --rpc-url "$RPC" >/dev/null 2>&1 && break; sleep 0.1; done
else
  echo "reusing anvil already at $RPC"
fi

python3 -m demo.scorecard
