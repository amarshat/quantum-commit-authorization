"""A second reputation source with dates: ScamSniffer's open address list.

GoPlus answers today, so it cannot say when an address was labelled.
ScamSniffer publishes its blacklist as a git repository
(github.com/scamsniffer/scam-database), refreshed daily with a stated 7-day
delay, so the history shows when each address entered the public list. This
module checks each drainer implementation against that history and counts
the victims who signed after the implementation was publicly listed (first
commit containing it, plus the 7-day delay), i.e. the ones a wallet using the
free list could have been warned about.

The repository is not vendored. Clone it and pass the path; it is read as
data only (git log and JSON):

    git clone https://github.com/scamsniffer/scam-database.git /path/to/clone
    python3 -m demo.upgrade_scamsniffer /path/to/clone

Writes results/upgrade_scamsniffer.json.
"""

from __future__ import annotations

import calendar
import json
import os
import subprocess
import sys
import time

from .intent_gap import block_at

_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_EXPAND = os.path.join(_HERE, "results", "upgrade_expand.json")
_BASE = os.path.join(_HERE, "results", "upgrade_baseline.json")
_OUT = os.path.join(_HERE, "results", "upgrade_scamsniffer.json")

FILES = ["blacklist/all.json", "blacklist/address.json"]
DELAY_DAYS = 7  # stated in the repository's README


def git(repo: str, *args: str) -> str:
    return subprocess.run(["git", "-C", repo, *args], check=True, capture_output=True,
                          text=True).stdout.strip()


def first_listed(repo: str, address: str) -> str | None:
    """Date (YYYY-MM-DD) of the first commit whose blacklist contains `address`."""
    out = git(repo, "log", "--reverse", "-i", f"-G{address[2:]}", "--format=%cs", "--", *FILES)
    return out.splitlines()[0] if out else None


def main() -> None:
    repo = sys.argv[1]
    rows = json.load(open(_EXPAND))["rows"]
    benign = json.load(open(_BASE))["rows"]
    impls = sorted({r["implementation"] for r in rows})
    list_start = git(repo, "log", "--reverse", "--format=%cs", "--", FILES[1]).splitlines()[0]
    listed_now = open(os.path.join(repo, FILES[0])).read().lower()

    per_impl = {}
    for a in impls:
        date = first_listed(repo, a)
        cut = None
        if date:
            ts = calendar.timegm(time.strptime(date, "%Y-%m-%d")) + DELAY_DAYS * 86400
            cut = block_at(ts)
        mine = [r for r in rows if r["implementation"] == a]
        per_impl[a] = {
            "first_listed": date,
            "listed_at_list_start": date == list_start,
            "listed_now": a in listed_now,
            "covered_from_block": cut,
            "victims": len(mine),
            "victims_after_listing": sum(cut is not None and r["block"] >= cut for r in mine),
        }

    starts = [v["covered_from_block"] for v in per_impl.values() if v["covered_from_block"]]
    after_list_exists = sum(r["block"] >= min(starts) for r in rows) if starts else 0
    summary = {
        "list_start": list_start,
        "delay_days": DELAY_DAYS,
        "repository_head": git(repo, "rev-parse", "--short", "HEAD"),
        "implementations_ever_listed": sum(v["first_listed"] is not None for v in per_impl.values()),
        "implementations": len(impls),
        "victims_covered": sum(v["victims_after_listing"] for v in per_impl.values()),
        "victims_after_list_existed": after_list_exists,
        "victims_total": len(rows),
        # Benign side against today's list, so an upper bound on its false positives.
        "benign_listed_now": sum(r["implementation"] in listed_now or r["proxy"] in listed_now
                                 for r in benign),
        "benign_wallet_relevant_listed_now": sum(
            r["wallet_relevant"] and (r["implementation"] in listed_now or r["proxy"] in listed_now)
            for r in benign),
        "benign_total": len(benign),
    }
    with open(_OUT, "w") as f:
        json.dump({"note": __doc__.split("\n\n")[0], "summary": summary, "per_implementation": per_impl},
                  f, indent=1)
        f.write("\n")
    print(json.dumps(summary, indent=1))
    for a, v in per_impl.items():
        print(f"  {a[:10]} listed {v['first_listed']} (at start: {v['listed_at_list_start']}) "
              f"victims {v['victims']} after listing {v['victims_after_listing']}")
    print(f"wrote {_OUT}")


if __name__ == "__main__":
    main()
