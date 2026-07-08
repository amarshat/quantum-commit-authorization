#!/usr/bin/env python3
"""Fetch a stratified sample of historical Ethereum base fees.

The gas benchmark (bench/) established that the two-transaction commit-reveal
flow beats direct on-chain PQ verification unless the base fee rises steeply
between the commit block and the reveal block. That break-even is a single
number (~15x for the cheapest baseline). This script pulls real base-fee
history so analyze.py can turn it into a distribution: how often, over the
2024-2026 period, would a commit-reveal flow actually have cost more than one
direct-verification transaction?

We do not fetch all ~5.3M blocks in the window. We take contiguous runs of
`RUN` blocks at `ANCHORS` points evenly spaced across the period, which
captures every fee regime (calm, ramps, spikes) while keeping the committed
data set small and the ratios within each run meaningful (a base-fee ratio
across a K-block gap only makes sense inside one contiguous run).

Output: fees/data/basefee.csv, columns (anchor, offset, block, basefee_wei,
gas_used_ratio). Committed, so analyze.py and CI never touch the network.
The RPC is a public no-key node; this is a one-time data-collection step,
not part of CI.
"""

import csv
import gzip
import json
import sys
import time
import urllib.request
from pathlib import Path

# A no-key public archive endpoint: needed because base fees older than the
# pruning window are "archive" requests that most free full nodes refuse.
RPC = "https://eth.drpc.org"
UA = "qca-research/0.1 (base-fee history for commit-reveal cost analysis)"
# 2024-07-01 (block 20,208,192) to a round point below the 2026-07 head.
START = 20_208_192
END = 25_480_000
ANCHORS = 40
RUN = 4096  # contiguous blocks per anchor; > commitTTL (256), so every gap fits
PAGE = 1024  # eth_feeHistory max blockCount

OUT = Path(__file__).resolve().parent / "data" / "basefee.csv.gz"


def rpc(method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    for attempt in range(5):
        try:
            req = urllib.request.Request(
                RPC, data=body, headers={"Content-Type": "application/json", "User-Agent": UA}
            )
            with urllib.request.urlopen(req, timeout=30) as r:
                out = json.load(r)
            if "result" in out:
                return out["result"]
            raise RuntimeError(out.get("error"))
        except Exception as e:  # transient node/rate-limit errors
            if attempt == 4:
                raise
            time.sleep(2 * (attempt + 1))
    raise RuntimeError("unreachable")


def fee_history(newest_block, count):
    """Return list of (block_number, basefee_wei, gas_used_ratio) for the
    `count` blocks ending at newest_block inclusive."""
    res = rpc("eth_feeHistory", [hex(count), hex(newest_block), []])
    oldest = int(res["oldestBlock"], 16)
    # baseFeePerGas has count+1 entries (includes newest+1); gasUsedRatio has
    # count. Pair block oldest+i with basefee[i] and ratio[i].
    fees = [int(x, 16) for x in res["baseFeePerGas"]]
    ratios = res["gasUsedRatio"]
    rows = []
    for i in range(len(ratios)):
        rows.append((oldest + i, fees[i], ratios[i]))
    return rows


def main():
    OUT.parent.mkdir(exist_ok=True)
    step = (END - START) // (ANCHORS - 1)
    all_rows = []
    for a in range(ANCHORS):
        anchor = START + a * step
        # Fetch RUN blocks starting at anchor, in PAGE-sized chunks.
        collected = []
        newest = anchor + RUN - 1
        remaining = RUN
        while remaining > 0:
            count = min(PAGE, remaining)
            chunk = fee_history(newest, count)
            collected = chunk + collected
            newest -= count
            remaining -= count
            time.sleep(0.3)  # be polite to the free endpoint
        collected.sort()
        for block, fee, ratio in collected:
            all_rows.append((anchor, block - anchor, block, fee, ratio))
        print(f"anchor {a + 1}/{ANCHORS} block {anchor} ({len(collected)} blocks)", file=sys.stderr)

    with gzip.open(OUT, "wt", newline="") as f:
        w = csv.writer(f)
        w.writerow(["anchor", "offset", "block", "basefee_wei", "gas_used_ratio"])
        w.writerows(all_rows)
    print(f"wrote {OUT} ({len(all_rows)} rows)", file=sys.stderr)


if __name__ == "__main__":
    main()
