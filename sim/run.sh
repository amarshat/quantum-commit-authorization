#!/usr/bin/env bash
# Regenerate the committed simulator result vectors. These back the figures
# in docs/GAME.md and the paper; CI reruns this and diffs, the same drift
# policy as the golden vectors and the gas benchmark. Deterministic: every
# cell seeds a ChaCha8 from a fixed base seed, so output is byte-stable.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p sim/results

RUN="cargo run -q --release -p qca-sim --manifest-path tooling/Cargo.toml --"

# Theorem 1 theft race: p_steal over (age, beta) at q=1, adversary-favorable
# tie (the beta^a edge). This is the headline sizing curve for minCommitAge.
$RUN sweep --ages 1,2,4,8 --betas 0.1,0.25,0.5,0.75,0.9 \
    --trials 2000000 --seed 1 > sim/results/theft-sweep.json

# Corollary 1a passive victim: same grid at q=0.5, showing the exponent's
# base widen from beta to beta + (1-beta)(1-q).
$RUN sweep --ages 1,2,4,8 --betas 0.1,0.25,0.5,0.75,0.9 \
    --q 0.5 --trials 2000000 --seed 2 > sim/results/theft-sweep-passive.json

# Theorem 2 recovery race, both tie edges, to exhibit the [beta, 1] bracket
# that replaced the old (wrong) beta^a recovery bound.
$RUN sweep --ages 4 --betas 0.1,0.25,0.5,0.75 \
    --remaining-ttl 0 --burn-response --tie victim \
    --trials 2000000 --seed 3 > sim/results/recovery-victim-ties.json
$RUN sweep --ages 4 --betas 0.1,0.25,0.5,0.75 \
    --remaining-ttl 0 --burn-response --tie adversary \
    --trials 2000000 --seed 4 > sim/results/recovery-adversary-ties.json

# Concentrated builders: theft race at beta=0.25 under rising autocorrelation,
# showing censorship gets cheaper than the i.i.d. baseline at equal share.
for P in 0.25 0.5 0.75 0.9; do
    $RUN sweep --ages 4 --betas 0.25 --persistence "$P" \
        --trials 2000000 --seed 5 > "sim/results/theft-markov-p${P}.json"
done

echo "wrote sim/results/*.json"
