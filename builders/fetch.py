#!/usr/bin/env python3
"""Fetch who built each block over the same sample the fee analysis uses.

The front-running game bounds theft by the chance that one builder (or a
coalition) produces `a` blocks in a row. The paper used to take the builder's
share and persistence as assumptions. This script collects the data to measure
them instead.

It reuses fees/fetch.py's sample exactly: ANCHORS contiguous runs of RUN blocks,
evenly spaced over 2024-07 to 2026-07. Runs of consecutive blocks are what the
game needs, and sharing the sample means builder and base-fee rows line up block
for block.

For each block it records the fee recipient (`miner`) and the raw extraData.
Turning those into builder names is analyze.py's job, driven by the committed
labels.json, so the attribution can be read and argued with separately from the
raw data.

Output: builders/data/blocks.csv.gz, columns (anchor, offset, block, miner,
extra_data). Committed, so the analysis never touches the network. Per-anchor
progress is cached in builders/data/cache/ (gitignored), so an interrupted run
resumes where it stopped.

The public node refuses batch requests and rate-limits bursts, so this makes
single calls from a few threads and backs off on 429.
"""

import csv
import gzip
import json
import os
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

# Same endpoint and sample as fees/fetch.py.
RPC = "https://eth.drpc.org"
UA = "qca-research/0.1 (block-builder history for commit-reveal theft bound)"
START = 20_208_192
END = 25_480_000
ANCHORS = 40
RUN = 4096
THREADS = 4

HERE = Path(__file__).resolve().parent
OUT = HERE / "data" / "blocks.csv.gz"
CACHE = HERE / "data" / "cache"


def ssl_context():
    # python.org and Homebrew builds may not see the system CA store; certifi
    # fixes that when present. Not needed if the default store works.
    try:
        import ssl

        import certifi

        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return None


CTX = ssl_context()


def header(n):
    body = json.dumps(
        {"jsonrpc": "2.0", "id": n, "method": "eth_getBlockByNumber", "params": [hex(n), False]}
    ).encode()
    delay = 1.0
    for attempt in range(12):
        try:
            req = urllib.request.Request(
                RPC, data=body, headers={"Content-Type": "application/json", "User-Agent": UA}
            )
            with urllib.request.urlopen(req, timeout=30, context=CTX) as r:
                out = json.load(r)
            res = out.get("result")
            if res is None:
                raise RuntimeError(out.get("error") or "null result")
            if int(res["number"], 16) != n:
                raise RuntimeError(f"asked for {n}, got {res['number']}")
            return n, res["miner"].lower(), res["extraData"]
        # Truncated bodies (JSON errors, IncompleteRead) happen on the free node
        # too, so retry anything rather than a fixed list of exception types.
        except Exception as e:  # noqa: BLE001
            if attempt == 11:
                raise RuntimeError(f"block {n}: {e}") from e
            time.sleep(delay)
            delay = min(delay * 2, 30)
    raise RuntimeError("unreachable")


def fetch_anchor(idx, anchor):
    path = CACHE / f"anchor_{idx:02d}.csv"
    if path.exists():
        with open(path) as f:
            rows = list(csv.reader(f))
        if len(rows) == RUN:
            return rows
    with ThreadPoolExecutor(THREADS) as ex:
        got = list(ex.map(header, range(anchor, anchor + RUN)))
    rows = [[str(anchor), str(n - anchor), str(n), miner, extra] for n, miner, extra in got]
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w", newline="") as f:
        csv.writer(f).writerows(rows)
    os.replace(tmp, path)
    return rows


def main():
    CACHE.mkdir(parents=True, exist_ok=True)
    step = (END - START) // (ANCHORS - 1)
    all_rows = []
    for i in range(ANCHORS):
        anchor = START + i * step
        t = time.time()
        rows = fetch_anchor(i, anchor)
        all_rows.extend(rows)
        print(f"anchor {i + 1}/{ANCHORS} block {anchor}: {len(rows)} blocks, {time.time() - t:.0f}s",
              file=sys.stderr, flush=True)

    with gzip.open(OUT, "wt", newline="") as f:
        w = csv.writer(f)
        w.writerow(["anchor", "offset", "block", "miner", "extra_data"])
        w.writerows(all_rows)
    print(f"wrote {OUT} ({len(all_rows)} rows)", file=sys.stderr)


if __name__ == "__main__":
    main()
