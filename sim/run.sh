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
# showing censorship success rises several-fold over the i.i.d. baseline at
# equal share (non-monotonic in persistence: it peaks at moderate runs, since
# extreme persistence rarely re-enters a run at the victim's reveal block).
for P in 0.25 0.5 0.75 0.9; do
    $RUN sweep --ages 4 --betas 0.25 --persistence "$P" \
        --trials 2000000 --seed 5 > "sim/results/theft-markov-p${P}.json"
done

# The clean concentration figure: theft-vs-beta at a4 under moderate builder
# autocorrelation (persistence 0.75), overlaid against the i.i.d. beta^a
# baseline. Betas kept <= 0.5 so persistence >= beta holds (the Markov chain
# is only valid when the adversary is at least as likely to stay as its
# share). The story: a low-share adversary that clusters its blocks censors a
# window it could never hold i.i.d., lifting small-beta theft by orders of
# magnitude.
$RUN sweep --ages 4 --betas 0.1,0.2,0.3,0.4,0.5 --persistence 0.75 \
    --trials 2000000 --seed 6 > sim/results/theft-concentrated.json

# --- Forcing adversary (docs/STATE_MODEL.md milestone M4) ---
# The forcing sim's cross-checks live in its unit tests (run in the tooling job);
# these vectors are the committed figures. Forcing games run a block horizon, so
# they are heavier than the AUTH-RACE games and use fewer trials.

# R2a safety figure: under full defenses, forgery and double-execution are 0
# across the whole strand-rate x builder-share grid, even with intent changes,
# MEV-sensitive actions, griefing, and a finite validUntil.
$RUN forcing --p-reorgs 0.0,0.3,0.6,0.9 --betas 0.1,0.25,0.5 \
    --p-intent-change 0.3 --mev-sensitive-frac 0.5 --adversary-griefs \
    --valid-until 16 --trials 200000 --seed 21 > sim/results/forcing-safety.json

# Residual figure (the go/no-go): full defenses, sweep the strand rate; the land
# rate, delay percentiles, leaves consumed, and adversary-attributed MEV-coupling
# loss/profit are the residual, none of which is a forgery.
$RUN forcing --p-reorgs 0.0,0.2,0.5,0.8 --betas 0.25 \
    --p-intent-change 0.2 --mev-sensitive-frac 0.5 --valid-until 16 \
    --trials 200000 --seed 22 > sim/results/forcing-residual.json

# FORS few-time value: with a restore accident, the forgery rate falls sharply
# from the WOTS baseline (r_max=1) to FORS (r_max=2), and stays under the exact
# binomial bound (q=0 so games run the full horizon, the hard regime).
$RUN forcing --p-reorgs 0.3 --betas 0.25 --q 0.0 --restore-rate 0.01 \
    --r-max 1 --trials 200000 --seed 23 > sim/results/forcing-fewtime-r1.json
$RUN forcing --p-reorgs 0.3 --betas 0.25 --q 0.0 --restore-rate 0.01 \
    --r-max 2 --trials 200000 --seed 23 > sim/results/forcing-fewtime-r2.json

# PoC-per-defense: removing each safety defense opens exactly its attack.
$RUN forcing --p-reorgs 0.3 --betas 0.25 --p-intent-change 0.3 --no-write-ahead \
    --trials 200000 --seed 24 > sim/results/forcing-poc-no-write-ahead.json
$RUN forcing --p-reorgs 0.3 --betas 0.25 --p-intent-change 0.4 --q 1.0 \
    --no-same-key-nonce --trials 200000 --seed 25 > sim/results/forcing-poc-no-same-key.json
$RUN forcing --p-reorgs 0.3 --betas 0.25 --q 0.0 --restore-rate 0.01 --r-max 2 \
    --no-randomizer-r --trials 200000 --seed 26 > sim/results/forcing-poc-no-randomizer.json

echo "wrote sim/results/*.json"
