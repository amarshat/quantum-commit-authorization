"""Turn the PTXPHISH ground-truth dataset into a hydrator seeds file.

PTXPHISH (Chen et al., "Dissecting Payload-based Transaction Phishing on
Ethereum", NDSS 2025; dataset at github.com/HypoopyH/PTXPhish) is a labeled set
of ~5,000 phishing and ~13,557 benign Ethereum transactions. Its dataset/
PTXPHISH.xlsx lays out one column per attack sub-category (each followed by a
Source column) plus benign columns.

This reads that .xlsx (stdlib only, no openpyxl/pandas) and emits a seeds JSON
for demo/hydrate.py: a curated sample of labeled tx hashes across the categories
that map to agent-signing drains, plus benign controls. The dataset itself is not
vendored; download it from the PTXPHISH repo and pass its path.

    python3 -m demo.ptxphish_seeds /path/to/PTXPHISH.xlsx 10 > seeds.json
    MAINNET_RPC=https://ethereum-rpc.publicnode.com python3 -m demo.hydrate seeds.json ptxphish_sample.json

Columns mapped (col letter -> label, malicious, action_type):
"""

from __future__ import annotations

import json
import re
import sys
import xml.etree.ElementTree as ET
import zipfile

NS = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"

# hash column -> (label, malicious, action_type hint). The hydrator re-decodes the
# real selector, so action_type is only a fallback when the selector is unknown.
COLUMNS = {
    "A":  ("ice-approve", True, "approve"),
    "C":  ("ice-permit", True, "permit"),
    "E":  ("ice-setapprovalforall", True, "approve"),
    "H":  ("nft-bulk-transfer", True, "transfer"),
    "L":  ("nft-free-buy-order", True, "order"),
    "AA": ("benign-kol", False, "call"),
    "AB": ("benign-developer", False, "call"),
}
DATA_START_ROW = 5  # rows 1-4 are title / group / sub-headers


def _read_sheet(path: str) -> list[dict]:
    z = zipfile.ZipFile(path)
    shared: list[str] = []
    if "xl/sharedStrings.xml" in z.namelist():
        root = ET.fromstring(z.read("xl/sharedStrings.xml"))
        for si in root.findall(f"{NS}si"):
            shared.append("".join(t.text or "" for t in si.iter(f"{NS}t")))
    ws = sorted(n for n in z.namelist()
                if n.startswith("xl/worksheets/") and n.endswith(".xml"))[0]
    root = ET.fromstring(z.read(ws))
    rows = []
    for row in root.iter(f"{NS}row"):
        cells: dict[str, str] = {}
        for c in row.findall(f"{NS}c"):
            col = re.match(r"[A-Z]+", c.get("r")).group()
            t = c.get("t")
            v = c.find(f"{NS}v")
            inline = c.find(f"{NS}is")
            if v is not None:
                cells[col] = shared[int(v.text)] if t == "s" else (v.text or "")
            elif inline is not None:
                cells[col] = "".join(x.text or "" for x in inline.iter(f"{NS}t"))
        rows.append(cells)
    return rows


_HASH = re.compile(r"^0x[0-9a-fA-F]{64}$")


def build_seeds(xlsx_path: str, per_col: int) -> list[dict]:
    rows = _read_sheet(xlsx_path)
    seeds = []
    for col, (label, malicious, atype) in COLUMNS.items():
        taken = 0
        for i, row in enumerate(rows[DATA_START_ROW - 1:], start=DATA_START_ROW):
            h = (row.get(col) or "").strip()
            if not _HASH.match(h):
                continue
            seeds.append({
                "id": f"ptx-{col}-{taken:02d}",
                "tx_hash": h,
                "label": label,
                "malicious": malicious,
                "kind": "onchain",
                "action_type": atype,
                "chain_id": 1,
                "note": f"PTXPHISH (NDSS 2025) column {col} ({label}), dataset row {i}.",
            })
            taken += 1
            if taken >= per_col:
                break
    return seeds


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    xlsx = argv[0]
    per_col = int(argv[1]) if len(argv) > 1 else 10
    json.dump(build_seeds(xlsx, per_col), sys.stdout, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
