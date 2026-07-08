#!/usr/bin/env bash
# Measure CommitRevealAccount gas from transaction receipts.
#
# Spins up a fresh anvil, broadcasts the flow in contracts/script/GasBench.s.sol
# as real transactions, and extracts receipt gasUsed into
# bench/results/qca-receipts.json. Receipts are ground truth: intrinsic gas,
# calldata gas and the EIP-7623 floor are all inside gasUsed, so no gas model
# is applied to our side anywhere. CI re-runs this and diffs the JSON.
set -euo pipefail
cd "$(dirname "$0")/.."

PORT=8547
HARDFORK=prague
# anvil's default funded dev key (publicly known, local measurement only)
KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

anvil --port "$PORT" --hardfork "$HARDFORK" --silent &
ANVIL_PID=$!
trap 'kill $ANVIL_PID 2>/dev/null' EXIT
until curl -sf -o /dev/null -X POST -H 'Content-Type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"web3_clientVersion","params":[]}' \
    "http://127.0.0.1:$PORT"; do sleep 0.2; done

# --slow: one transaction per block, so commitments age past minCommitAge.
# --skip-simulation: forge's pre-broadcast simulation replays every
# transaction in a single block, where the age check must fail; the local
# prep run (with vm.roll) already validated the flow.
(cd contracts && forge script script/GasBench.s.sol \
    --rpc-url "http://127.0.0.1:$PORT" --private-key "$KEY" \
    --broadcast --slow --skip-simulation -q)

HARDFORK=$HARDFORK python3 - <<'EOF'
import json, os
from pathlib import Path

run = json.loads(Path("contracts/broadcast/GasBench.s.sol/31337/run-latest.json").read_text())
gas_by_hash = {r["transactionHash"]: int(r["gasUsed"], 16) for r in run["receipts"]}
status_by_hash = {r["transactionHash"]: int(r["status"], 16) for r in run["receipts"]}

LABELS = ["deploy", "commit_action", "commit_noop", "reveal_action", "reveal_noop", "burn"]
DEPTHS = [8, 16, 20]
txs = run["transactions"]
assert len(txs) == len(LABELS) * len(DEPTHS), f"unexpected tx count {len(txs)}"

out = {"hardfork": os.environ["HARDFORK"], "depths": {}}
for d_i, depth in enumerate(DEPTHS):
    rows = {}
    for l_i, label in enumerate(LABELS):
        tx = txs[d_i * len(LABELS) + l_i]
        assert status_by_hash[tx["hash"]] == 1, f"{depth}/{label} reverted"
        data = bytes.fromhex(tx["transaction"]["input"][2:])
        rows[label] = {
            "gasUsed": gas_by_hash[tx["hash"]],
            "inputBytes": len(data),
            "zeroBytes": data.count(0),
        }
    out["depths"][str(depth)] = rows

# Sanity reconciliation: the action reveal differs from the authorization-only
# reveal by exactly the cost of executing the action (value transfer to a
# cold, empty EOA: 25000 new account + 9000 value + 2600 cold access) plus
# small calldata differences. A large residual means the harness is once
# again measuring something other than it claims.
for depth, rows in out["depths"].items():
    delta = rows["reveal_action"]["gasUsed"] - rows["reveal_noop"]["gasUsed"]
    assert 30000 < delta < 45000, f"depth {depth}: action-vs-noop delta {delta} outside expectation"

Path("bench/results").mkdir(exist_ok=True)
Path("bench/results/qca-receipts.json").write_text(json.dumps(out, indent=2) + "\n")
print("wrote bench/results/qca-receipts.json")
EOF
