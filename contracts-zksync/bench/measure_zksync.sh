#!/usr/bin/env bash
# Measure the zkSync Era native-AA reveal path from transaction receipts, the
# same receipt-gas discipline as the L1 benches in ../contracts. This drives a
# REAL type-0x71 transaction end to end on anvil-zksync: validateTransaction
# runs in the bootloader and increments the account nonce through the
# NonceHolder system contract (the path the forge --zksync test VM does not
# run), then executeTransaction runs the aging gate and the action. Gas is read
# from the receipt.
#
# The zkSync toolchain (foundry-zksync forge, anvil-zksync) is deliberately kept
# out of the main CI, so this is a standalone local reproducer. Point
# FOUNDRY_ZKSYNC_BIN at your foundry-zksync bin dir if it is not ~/.foundry/bin.
#
# Output: bench/results/qca-zksync-receipts.json and bench/results/env.txt.
set -euo pipefail
cd "$(dirname "$0")/.."

BIN="${FOUNDRY_ZKSYNC_BIN:-$HOME/.foundry/bin}"
FORGE="$BIN/forge"
ANVIL_ZKSYNC="$BIN/anvil-zksync"
PORT="${PORT:-8011}"
RPC="http://127.0.0.1:$PORT"
DEPTHS="${DEPTHS:-8,16,20}"

mkdir -p bench/results

# Rebuild so the measured bytecode matches the committed source. The eravm
# extensions must be on (foundry.toml) or the NonceHolder system call halts.
"$FORGE" build --zksync -q

"$ANVIL_ZKSYNC" --port "$PORT" run > /tmp/anvil-zksync-bench.log 2>&1 &
AZK_PID=$!
trap 'kill $AZK_PID 2>/dev/null' EXIT
until "$BIN/cast" chain-id --rpc-url "$RPC" >/dev/null 2>&1; do sleep 0.2; done

RPC="$RPC" DEPTHS="$DEPTHS" node bench/aa_flow.mjs > bench/results/qca-zksync-receipts.json

{
  echo "forge        $("$FORGE" --version 2>/dev/null | head -1)"
  echo "anvil-zksync $("$ANVIL_ZKSYNC" --version 2>/dev/null | head -1)"
  echo "zksolc       $(grep -oE 'zksolc = \"[^\"]+\"' foundry.toml | head -1)"
  echo "qca          $(git -C .. describe --always --dirty)"
  echo "node         $(node --version)"
} > bench/results/env.txt

echo "wrote bench/results/qca-zksync-receipts.json"
