#!/usr/bin/env python3
"""Measure builder share, persistence and run frequency from the block sample.

The front-running game (docs/GAME.md, paper Section IV) bounds theft by the
probability that the adversary builds all `a` blocks between the victim's
broadcast and the adversary's eligibility. Under i.i.d. builders that is
beta^a; under the two-state Markov model it is beta * p^(a-1) at a stationary
broadcast time and p_sw * p^(a-1) after an honest broadcast block. Both used
assumed beta and p. This script measures, for the largest builders and for
coalitions of the top k:

  beta      share of blocks built
  p         P(next block is theirs | this block is theirs)
  run(a)    fraction of positions where they build `a` consecutive blocks,
            counted directly with no model, i.e. the stationary theft rate
            under q=1 with the adversary-favourable tie rule
  run_h(a)  the same, conditioned on the block before the window not being
            theirs (the honest-broadcast case)

and sets the two model predictions beside the direct counts. Windows never
cross an anchor boundary, since the anchors are separate contiguous runs.

Input: builders/data/blocks.csv.gz (committed), or with --cache the
per-anchor files fetch.py writes while it runs.
Output: builders/results/stats.json and builders/results/RESULTS.md.
"""

import csv
import gzip
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
DATA = HERE / "data" / "blocks.csv.gz"
CACHE = HERE / "data" / "cache"
LABELS = HERE / "labels.json"
RESULTS = HERE / "results"

A_MAX = 8
TOP = 5
COALITIONS = (1, 2, 3)
TARGETS = (1e-3, 1e-6)
# Local-share windows. The top builder's share drifts within an anchor, so its
# long runs exceed the anchor-wide beta^a; averaging beta_W^a over each
# block's own W-block neighbourhood accounts for that. 128 is the smallest
# window tried that never underpredicts the direct runs at a = 4..8 for any
# coalition, so it is the conservative sizing; 256 is reported beside it.
WINDOWS = (128, 256)
A_TTL = 256


def load_rows(use_cache):
    if use_cache:
        rows = []
        for p in sorted(CACHE.glob("anchor_*.csv")):
            with open(p) as f:
                rows.extend(csv.reader(f))
        return rows
    with gzip.open(DATA, "rt") as f:
        r = csv.reader(f)
        next(r)
        return list(r)


def decode(extra):
    try:
        return bytes.fromhex(extra[2:]).decode("utf-8", "replace").lower()
    except ValueError:
        return ""


def attributor(variant=None):
    labels = json.loads(LABELS.read_text())
    by_tag = [(name, subs) for name, subs in labels["by_tag"].items()]
    by_miner = labels["by_miner"]
    overrides = list(labels["variants"][variant].items()) if variant else []

    def attribute(block, miner, extra):
        tag = decode(extra)
        for sub, name in overrides:
            if sub in tag:
                return name, "tag"
        for name, subs in by_tag:
            if any(s in tag for s in subs):
                return name, "tag"
        if miner in by_miner:
            return by_miner[miner], "miner"
        return f"self:{block}", "self"

    return attribute


def runs_for(seqs, members, a_max):
    """Direct run counts for the entity `members` (a set of builder names)."""
    out = {}
    for a in range(1, a_max + 1):
        hit = total = hit_h = total_h = 0
        for seq in seqs:
            mine = [b in members for b in seq]
            n = len(mine)
            for k in range(n - a + 1):
                total += 1
                window = all(mine[k:k + a])
                hit += window
                # Honest-broadcast case: the block just before the window is
                # not the adversary's. Needs a predecessor inside the anchor.
                if k >= 1 and not mine[k - 1]:
                    total_h += 1
                    hit_h += window
        out[a] = {"run": hit / total, "run_h": hit_h / total_h if total_h else None,
                  "windows": total}
    return out


def entity_stats(seqs, members):
    built = stay = pairs_from = 0
    total = 0
    for seq in seqs:
        mine = [b in members for b in seq]
        total += len(mine)
        built += sum(mine)
        for x, y in zip(mine, mine[1:]):
            if x:
                pairs_from += 1
                stay += y
    beta = built / total
    p = stay / pairs_from if pairs_from else None
    runs = runs_for(seqs, members, A_MAX)
    rows = {}
    for a, r in runs.items():
        iid = beta ** a
        markov = beta * p ** (a - 1) if p is not None else None
        p_sw = beta * (1 - p) / (1 - beta) if p is not None and beta < 1 else None
        markov_h = p_sw * p ** (a - 1) if p_sw is not None else None
        rows[a] = {**r, "iid": iid, "markov": markov, "markov_h": markov_h}
    return {"beta": beta, "p": p, "blocks": total, "by_a": rows}


def per_anchor_topk(anchors, seqs, k):
    """Each anchor's own top-k builders as the adversary: the regime-matched
    comparison. Pooling anchors mixes regimes with different shares, which by
    itself makes pooled runs look clustered."""
    out = []
    for anchor, seq in zip(anchors, seqs):
        c = Counter(n for n in seq if not n.startswith("self:"))
        members = {n for n, _ in c.most_common(k)}
        s = entity_stats([seq], members)
        out.append({"anchor": anchor, "members": sorted(members), "beta": s["beta"], "p": s["p"],
                    "by_a": {a: {"run": r["run"], "iid": r["iid"]} for a, r in s["by_a"].items()}})
    return out


def sizing(regime):
    """minCommitAge each coalition requires: the smallest a with beta^a at or
    below each target at the anchor where that coalition's share is highest,
    with the medians that justify using beta^a (persistence close to share,
    direct runs close to beta^4)."""
    out = {}
    for k, rows in regime.items():
        betas = sorted(r["beta"] for r in rows)
        gaps = sorted(r["p"] - r["beta"] for r in rows)
        ratios = sorted(r["by_a"][4]["run"] / r["by_a"][4]["iid"] for r in rows)
        worst = betas[-1]
        need = {}
        for t in TARGETS:
            a = 1
            while worst ** a > t:
                a += 1
            need[f"{t:g}"] = a
        out[k] = {"beta_median": betas[len(betas) // 2], "beta_max": worst,
                  "p_minus_beta_median": gaps[len(gaps) // 2],
                  "run4_over_iid_median": ratios[len(ratios) // 2],
                  "min_commit_age_at_max_beta": need}
    return out


def local_sizing(seqs):
    """minCommitAge under each block's local share: for every position, the
    share of the coalition in the W blocks around it, and the theft rate as
    the mean of beta_W^a. Reports how well that predicts the direct runs at
    a = 4..8, the highest local share seen, and the smallest a meeting each
    target, up to commitTTL."""
    out = {}
    for k in COALITIONS:
        out[f"top{k}"] = {}
        for w in WINDOWS:
            obs = Counter()
            pred = [0.0] * (A_TTL + 1)
            n = 0
            high = 0.0
            for seq in seqs:
                c = Counter(x for x in seq if not x.startswith("self:"))
                members = {x for x, _ in c.most_common(k)}
                mine = [x in members for x in seq]
                pre = [0]
                for m in mine:
                    pre.append(pre[-1] + m)
                size = len(mine)
                for i in range(size - A_MAX):
                    hi = min(size, max(0, i - w // 2) + w)
                    lo = max(0, hi - w)
                    b = (pre[hi] - pre[lo]) / (hi - lo)
                    high = max(high, b)
                    n += 1
                    x = 1.0
                    for a in range(1, A_TTL + 1):
                        x *= b
                        pred[a] += x
                    for a in range(4, A_MAX + 1):
                        obs[a] += all(mine[i:i + a])
            need = {f"{t:g}": next((a for a in range(1, A_TTL + 1) if pred[a] / n <= t), None)
                    for t in TARGETS}
            out[f"top{k}"][str(w)] = {"obs_over_pred": {a: obs[a] / pred[a] for a in range(4, A_MAX + 1)},
                                      "max_local_beta": high,
                                      "min_commit_age": need}
    return out


def main():
    use_cache = "--cache" in sys.argv
    variant = next((a.split("=", 1)[1] for a in sys.argv if a.startswith("--variant=")), None)
    rows = load_rows(use_cache)
    attribute = attributor(variant)

    seqs_by_anchor = defaultdict(list)
    how = Counter()
    for anchor, _off, block, miner, extra in rows:
        name, method = attribute(block, miner, extra)
        how[method] += 1
        seqs_by_anchor[int(anchor)].append((int(block), name))

    seqs = []
    for anchor in sorted(seqs_by_anchor):
        s = sorted(seqs_by_anchor[anchor])
        blocks = [b for b, _ in s]
        if blocks != list(range(blocks[0], blocks[0] + len(blocks))):
            raise SystemExit(f"anchor {anchor} is not contiguous")
        seqs.append([n for _, n in s])

    share = Counter(n for seq in seqs for n in seq if not n.startswith("self:"))
    total = sum(len(s) for s in seqs)
    ranked = [n for n, _ in share.most_common()]

    per_anchor = []
    for anchor, seq in zip(sorted(seqs_by_anchor), seqs):
        c = Counter(n for n in seq if not n.startswith("self:"))
        top = c.most_common(3)
        per_anchor.append({"anchor": anchor, "top": [[n, k / len(seq)] for n, k in top],
                           "self_built": sum(n.startswith("self:") for n in seq) / len(seq)})

    singles = {n: entity_stats(seqs, {n}) for n in ranked[:TOP]}
    coalitions = {f"top{k}": {"members": ranked[:k], **entity_stats(seqs, set(ranked[:k]))}
                  for k in COALITIONS}

    anchors = sorted(seqs_by_anchor)
    regime = {f"top{k}": per_anchor_topk(anchors, seqs, k) for k in COALITIONS}

    out = {
        "source": "cache (partial)" if use_cache else str(DATA.relative_to(HERE.parent)),
        "variant": variant,
        "anchors": len(seqs),
        "blocks": total,
        "attribution": dict(how),
        "share": {n: k / total for n, k in share.most_common(10)},
        "per_anchor": per_anchor,
        "builders": singles,
        "coalitions": coalitions,
        "per_anchor_topk": regime,
        "sizing": sizing(regime),
        "local_sizing": local_sizing(seqs),
    }
    RESULTS.mkdir(exist_ok=True)
    suffix = f"-{variant}" if variant else ""
    (RESULTS / f"stats{suffix}.json").write_text(json.dumps(out, indent=2) + "\n")
    (RESULTS / f"RESULTS{suffix}.md").write_text(report(out))
    print(report(out))


def fmt(x):
    if x is None:
        return "n/a"
    if x == 0:
        return "0"
    return f"{x:.2e}" if x < 1e-3 else f"{x:.4f}"


def report(o):
    lines = [
        "# Builder share, persistence and runs",
        "",
        f"Source: `{o['source']}`. {o['anchors']} anchors, {o['blocks']:,} blocks."
        + (f" Attribution variant: `{o['variant']}`." if o["variant"] else ""),
        f"Attribution: {o['attribution'].get('tag', 0):,} by extraData tag, "
        f"{o['attribution'].get('miner', 0):,} by fee recipient, "
        f"{o['attribution'].get('self', 0):,} unattributed and treated as self-built.",
        "",
        "`run` is the direct fraction of windows of `a` consecutive blocks all built by the",
        "entity (stationary theft rate at q=1). `run_h` conditions on the block before the",
        "window not being theirs (honest broadcast). `iid` = beta^a, `markov` = beta p^(a-1),",
        "`markov_h` = p_sw p^(a-1).",
        "",
    ]
    for title, group in (("Coalitions of the largest builders", o["coalitions"]),
                         ("Largest single builders", o["builders"])):
        lines += [f"## {title}", ""]
        for name, s in group.items():
            label = name if "members" not in s else f"{name} ({', '.join(s['members'])})"
            lines += [f"### {label}", "", f"beta = {fmt(s['beta'])}, p = {fmt(s['p'])}", "",
                      "| a | run | iid | markov | run_h | markov_h |",
                      "|---|---|---|---|---|---|"]
            for a, r in s["by_a"].items():
                lines.append(f"| {a} | {fmt(r['run'])} | {fmt(r['iid'])} | {fmt(r['markov'])} | "
                             f"{fmt(r['run_h'])} | {fmt(r['markov_h'])} |")
            lines.append("")
    lines += ["## Each anchor's own top-k builders (regime-matched)", "",
              "Pooled numbers above mix anchors with different shares. Here each anchor's",
              "adversary is that anchor's own top-k builders, and `run` is compared with",
              "that anchor's beta^a.", "",
              "| k | anchor block | beta | p | run(4) | beta^4 | run(8) | beta^8 |",
              "|---|---|---|---|---|---|---|---|"]
    for k, rows in o["per_anchor_topk"].items():
        for r in rows:
            b = r["by_a"]
            lines.append(f"| {k} | {r['anchor']} | {fmt(r['beta'])} | {fmt(r['p'])} | "
                         f"{fmt(b[4]['run'])} | {fmt(b[4]['iid'])} | {fmt(b[8]['run'])} | {fmt(b[8]['iid'])} |")
    lines += ["", "## minCommitAge at measured shares", "",
              "Per anchor, as above. `a` is the smallest minCommitAge with beta^a at or below",
              "the target at the anchor where the coalition's share is highest.", "",
              "| k | median beta | max beta | median p - beta | median run(4)/beta^4 | "
              + " | ".join(f"a for {t:g}" for t in TARGETS) + " |",
              "|---|---|---|---|---|" + "---|" * len(TARGETS)]
    for k, z in o["sizing"].items():
        lines.append(f"| {k} | {fmt(z['beta_median'])} | {fmt(z['beta_max'])} | "
                     f"{z['p_minus_beta_median']:+.4f} | {z['run4_over_iid_median']:.2f} | "
                     + " | ".join(str(v) for v in z["min_commit_age_at_max_beta"].values()) + " |")
    lines += ["", "## minCommitAge under local share", "",
              "Each block's adversary share is the coalition's share in the W blocks around it,",
              "and the theft rate is the mean of beta_W^a. `obs/pred` compares the direct runs",
              "with that prediction at a = 4..8; `none` means no a up to commitTTL (256) meets",
              "the target.", "",
              "| k | W | obs/pred a=4..8 | max local beta | "
              + " | ".join(f"a for {t:g}" for t in TARGETS) + " |",
              "|---|---|---|---|" + "---|" * len(TARGETS)]
    for k, ws in o["local_sizing"].items():
        for w, z in ws.items():
            fit = " ".join(f"{v:.2f}" for v in z["obs_over_pred"].values())
            lines.append(f"| {k} | {w} | {fit} | {z['max_local_beta']:.3f} | "
                         + " | ".join(str(v) if v else "none" for v in z["min_commit_age"].values()) + " |")
    lines += ["", "## Top builders per anchor", "", "| anchor block | 1st | 2nd | 3rd | self-built |",
              "|---|---|---|---|---|"]
    for pa in o["per_anchor"]:
        cells = [f"{n} {s:.0%}" for n, s in pa["top"]] + [""] * (3 - len(pa["top"]))
        lines.append(f"| {pa['anchor']} | " + " | ".join(cells) + f" | {pa['self_built']:.0%} |")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    main()
