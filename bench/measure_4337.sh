#!/usr/bin/env bash
# Measure the ERC-4337 reveal path from transaction receipts, the same way
# measure_qca.sh measures the base scheme. Two phases against a fresh anvil,
# with a real chain-clock advance between them so the reveal's validAfter gate
# (enforced by the EntryPoint against live time) passes.
#
# Output: bench/results/qca-4337-receipts.json, with the handleOps gasUsed for
# an action reveal and an authorization-only reveal at depth 16, alongside the
# base-scheme reveal receipts so report.py can report the 4337 overhead.
set -euo pipefail
cd "$(dirname "$0")/.."

PORT=8548
KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
RPC="http://127.0.0.1:$PORT"

anvil --port "$PORT" --hardfork prague --silent &
ANVIL_PID=$!
trap 'kill $ANVIL_PID 2>/dev/null' EXIT
until cast block-number --rpc-url "$RPC" >/dev/null 2>&1; do sleep 0.2; done

pushd contracts >/dev/null
forge script script/Bench4337.s.sol --sig "deployPhase()" \
    --rpc-url "$RPC" --private-key "$KEY" --broadcast --skip-simulation -q

# Advance the chain clock well past minCommitAge (1s) so the reveals are due.
cast rpc --rpc-url "$RPC" evm_increaseTime 10 >/dev/null
cast rpc --rpc-url "$RPC" evm_mine >/dev/null

forge script script/Bench4337.s.sol --sig "revealPhase()" \
    --rpc-url "$RPC" --private-key "$KEY" --broadcast --slow --skip-simulation -q
popd >/dev/null

python3 - <<'EOF'
import json
from pathlib import Path

def receipts(sig):
    p = Path(f"contracts/broadcast/Bench4337.s.sol/31337/{sig}-latest.json")
    run = json.loads(p.read_text())
    gas = {r["transactionHash"]: int(r["gasUsed"], 16) for r in run["receipts"]}
    status = {r["transactionHash"]: int(r["status"], 16) for r in run["receipts"]}
    return run["transactions"], gas, status

# deployPhase txs: [EntryPoint deploy, account deploy, depositTo, commit_action, commit_noop]
dtx, dgas, dstatus = receipts("deployPhase")
for t in dtx:
    assert dstatus[t["hash"]] == 1, "a deploy-phase tx reverted"
commit_gas = dgas[dtx[3]["hash"]]  # first commit (plain tx on the 4337 account)

# revealPhase txs: [handleOps(action), handleOps(noop)]
rtx, rgas, rstatus = receipts("revealPhase")
for t in rtx:
    assert rstatus[t["hash"]] == 1, "a reveal-phase handleOps reverted (validAfter not due?)"
handleops_action = rgas[rtx[0]["hash"]]
handleops_noop = rgas[rtx[1]["hash"]]

out = {
    "hardfork": "prague",
    "depth": 16,
    "commit": commit_gas,
    "handleOps_action": handleops_action,
    "handleOps_auth_only": handleops_noop,
}
Path("bench/results").mkdir(exist_ok=True)
Path("bench/results/qca-4337-receipts.json").write_text(json.dumps(out, indent=2) + "\n")
print("wrote bench/results/qca-4337-receipts.json")
print(json.dumps(out, indent=2))
EOF
