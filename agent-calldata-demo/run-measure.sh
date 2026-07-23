#!/usr/bin/env bash
# Empirical coverage measurement: run the corpus (synthetic suite on a local
# chain + any real corpus in corpus/real/) past the REAL deployed defenses and
# print the measured matrix. Companion to run.sh, which runs the modeled ladder.
#
# Real defenses are gated on keys (in ../.env or .env, gitignored):
#   ALCHEMY_API_KEY                                            (hosted simulator, free/self-serve)
#   GO_PLUS_APP_KEY / GO_PLUS_APP_SECRET                       (hosted reputation)
#   TENDERLY_ACCESS_KEY / TENDERLY_ACCOUNT / TENDERLY_PROJECT  (hosted simulator; API now paid/gated)
# Rabby is a pure open-rules port and needs no key. Unconfigured defenses are
# skipped, not faked.
set -euo pipefail

cd "$(dirname "$0")"
RPC="http://127.0.0.1:8545"

for envf in ../.env .env; do
  [ -f "$envf" ] && set -a && . "$envf" && set +a
done

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing '$1' (install Foundry: https://getfoundry.sh)"; exit 1; }; }
need anvil; need cast; need forge; need python3

forge build >/dev/null

STARTED_ANVIL=0
if ! cast block-number --rpc-url "$RPC" >/dev/null 2>&1; then
  echo "starting anvil..."
  anvil --silent --hardfork prague --port 8545 >out/anvil.log 2>&1 &
  ANVIL_PID=$!
  STARTED_ANVIL=1
  trap '[ "$STARTED_ANVIL" = 1 ] && kill "$ANVIL_PID" 2>/dev/null || true' EXIT
  for _ in $(seq 1 50); do cast block-number --rpc-url "$RPC" >/dev/null 2>&1 && break; sleep 0.1; done
else
  echo "reusing anvil already at $RPC"
fi

python3 -m demo.measure
