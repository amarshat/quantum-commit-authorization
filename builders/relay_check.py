#!/usr/bin/env python3
"""Cross-check the extraData attribution against mev-boost relay records.

A relay's proposer_payload_delivered endpoint says which builder pubkey built
each block it delivered. That pubkey is the closest thing to ground truth that
is public. For a sample of anchors, this pages through the delivered payloads
of a few large relays, joins them to our blocks by block hash, and asks two
questions:

  purity     for each builder pubkey, what share of its blocks carry its
             majority label in our attribution (a pubkey split across labels
             means our labels are wrong somewhere)
  agreement  across all joined blocks, the share whose label equals their
             pubkey's majority label

It also reports how many blocks we called self-built that a relay says came
from a builder, which is the failure the self-built default could hide.

Output: builders/results/relay_check.json. Network step, not part of CI.
"""

import csv
import gzip
import json
import sys
import time
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from analyze import attributor  # noqa: E402

HERE = Path(__file__).resolve().parent
DATA = HERE / "data" / "blocks.csv.gz"
OUT = HERE / "results" / "relay_check.json"
CACHE = HERE / "data" / "cache" / "relay"

RELAYS = ["relay.ultrasound.money", "boost-relay.flashbots.net", "titanrelay.xyz",
          "aestus.live", "agnostic-relay.net"]
SAMPLE_ANCHOR_INDEXES = (0, 39)
GENESIS = 1606824023  # beacon chain genesis time; slot = (ts - GENESIS) // 12
UA = "qca-research/0.1 (builder attribution check)"


def get(url):
    for attempt in range(6):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            from fetch import CTX
            with urllib.request.urlopen(req, timeout=60, context=CTX) as r:
                return json.load(r)
        except Exception:  # noqa: BLE001
            if attempt == 5:
                raise
            time.sleep(2 * (attempt + 1))
    return None


def block_ts(n):
    from fetch import CTX, RPC  # same endpoint as the main fetch
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_getBlockByNumber",
                       "params": [hex(n), False]}).encode()
    req = urllib.request.Request(RPC, data=body, headers={"Content-Type": "application/json",
                                                          "User-Agent": UA})
    with urllib.request.urlopen(req, timeout=30, context=CTX) as r:
        res = json.load(r)["result"]
    return int(res["timestamp"], 16), res["hash"]


def delivered(relay, slot_lo, slot_hi):
    """All payloads a relay delivered with slot in [slot_lo, slot_hi]."""
    path = CACHE / f"{relay}_{slot_lo}_{slot_hi}.json"
    if path.exists():
        return json.loads(path.read_text())
    out, cursor = [], slot_hi
    while cursor >= slot_lo:
        page = get(f"https://{relay}/relay/v1/data/bidtraces/proposer_payload_delivered"
                   f"?cursor={cursor}&limit=200") or []
        if not page:
            break
        out += [p for p in page if slot_lo <= int(p["slot"]) <= slot_hi]
        nxt = min(int(p["slot"]) for p in page) - 1
        if nxt >= cursor:
            break
        cursor = nxt
        time.sleep(0.3)
    CACHE.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(out))
    return out


def main():
    attribute = attributor()
    with gzip.open(DATA, "rt") as f:
        r = csv.reader(f)
        next(r)
        rows = list(r)
    anchors = sorted({int(x[0]) for x in rows})
    sample = [anchors[i] for i in SAMPLE_ANCHOR_INDEXES]

    from fetch import RUN
    joined = []
    report = {"relays": RELAYS, "anchors": {}}
    for anchor in sample:
        ts_lo, _ = block_ts(anchor)
        ts_hi, _ = block_ts(anchor + RUN - 1)
        slot_lo, slot_hi = (ts_lo - GENESIS) // 12, (ts_hi - GENESIS) // 12
        ours = {int(x[2]): attribute(x[2], x[3], x[4])[0] for x in rows if int(x[0]) == anchor}
        by_block = {}
        for relay in RELAYS:
            for p in delivered(relay, slot_lo, slot_hi):
                n = int(p["block_number"])
                if n in ours:
                    by_block.setdefault(n, p["builder_pubkey"])
        report["anchors"][anchor] = {"blocks": len(ours), "relay_covered": len(by_block)}
        joined += [(n, by_block[n], ours[n]) for n in by_block]
        print(f"anchor {anchor}: {len(by_block)}/{len(ours)} blocks seen by a relay", file=sys.stderr)

    labels_by_key = defaultdict(Counter)
    for _n, key, label in joined:
        labels_by_key[key][label] += 1
    majority = {k: c.most_common(1)[0][0] for k, c in labels_by_key.items()}
    agree = sum(majority[k] == label for _n, k, label in joined)
    self_but_relayed = sum(label.startswith("self:") for _n, _k, label in joined)
    impure = {k[:18]: dict(c.most_common(4)) for k, c in labels_by_key.items()
              if c.most_common(1)[0][1] < sum(c.values())}

    report.update({
        "joined_blocks": len(joined),
        "builder_pubkeys": len(labels_by_key),
        "agreement": agree / len(joined) if joined else None,
        "self_built_but_relay_delivered": self_but_relayed,
        "impure_pubkeys": impure,
    })
    OUT.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k != "impure_pubkeys"}, indent=2))
    print("impure pubkeys:", json.dumps(impure, indent=1)[:1500])


if __name__ == "__main__":
    main()
