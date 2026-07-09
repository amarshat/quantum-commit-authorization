#!/usr/bin/env bash
# Measure the ERC-4337 reveal path from transaction receipts, like
# measure_qca.sh. Per depth, three authorization-only reveals: warmup (first
# op, one-time nonce-slot init), steady single op (worst case, one per bundle),
# and a bundle of two (so bundle - single is the amortized marginal per-op).
# Two phases with a real chain-clock advance between them, because the reveal's
# validAfter gate is enforced by the EntryPoint against live time.
#
# Output: bench/results/qca-4337-receipts.json.
set -euo pipefail
cd "$(dirname "$0")/.."

PORT=8548
KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
RPC="http://127.0.0.1:$PORT"

anvil --port "$PORT" --hardfork prague --silent &
ANVIL_PID=$!
trap 'kill $ANVIL_PID 2>/dev/null; rm -f contracts/bench-4337-addrs-*.json' EXIT
until cast block-number --rpc-url "$RPC" >/dev/null 2>&1; do sleep 0.2; done

RUNDIR=contracts/broadcast/Bench4337.s.sol/31337
CAP=$(mktemp -d)
pushd contracts >/dev/null
for DEPTH in 8 16 20; do
    forge script script/Bench4337.s.sol --sig "deployPhase(uint256)" "$DEPTH" \
        --rpc-url "$RPC" --private-key "$KEY" --broadcast --skip-simulation -q
    cast rpc --rpc-url "$RPC" evm_increaseTime 10 >/dev/null
    cast rpc --rpc-url "$RPC" evm_mine >/dev/null
    forge script script/Bench4337.s.sol --sig "revealPhase(uint256)" "$DEPTH" \
        --rpc-url "$RPC" --private-key "$KEY" --broadcast --slow --skip-simulation -q
    # The arg is not in the broadcast filename, so each depth overwrites
    # revealPhase-latest.json; capture it before the next depth runs.
    cp "broadcast/Bench4337.s.sol/31337/revealPhase-latest.json" "$CAP/reveal-$DEPTH.json"
done
popd >/dev/null

CAP="$CAP" python3 - <<'EOF'
import json, os
from pathlib import Path

CAP = os.environ["CAP"]

def phase(sig, depth):
    p = Path(f"{CAP}/reveal-{depth}.json")
    run = json.loads(p.read_text())
    gas = {r["transactionHash"]: int(r["gasUsed"], 16) for r in run["receipts"]}
    status = {r["transactionHash"]: int(r["status"], 16) for r in run["receipts"]}
    for t in run["transactions"]:
        assert status[t["hash"]] == 1, f"{sig} depth {depth}: a tx reverted"
    return run["transactions"], gas

out = {"hardfork": "prague", "depths": {}}
for depth in (8, 16, 20):
    rtx, rgas = phase("revealPhase", depth)
    # revealPhase order: [warmup handleOps, single handleOps, bundle2 handleOps]
    warmup = rgas[rtx[0]["hash"]]
    single = rgas[rtx[1]["hash"]]
    bundle2 = rgas[rtx[2]["hash"]]
    out["depths"][str(depth)] = {
        "warmup_first_op": warmup,   # includes one-time nonce-slot init
        "single_op": single,         # steady state, worst case (1 op/bundle)
        "bundle_of_two": bundle2,    # two ops in one handleOps
        "marginal_per_op": bundle2 - single,  # amortized cost of an added op
        "nonce_init_onetime": warmup - single,
    }

Path("bench/results").mkdir(exist_ok=True)
Path("bench/results/qca-4337-receipts.json").write_text(json.dumps(out, indent=2) + "\n")
print("wrote bench/results/qca-4337-receipts.json")
print(json.dumps(out, indent=2))
EOF
