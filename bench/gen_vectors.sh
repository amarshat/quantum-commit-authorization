#!/usr/bin/env bash
# Generate the fixed vectors used by contracts/script/GasBench.s.sol.
#
# One vector file per tree depth, three leaves each: one for the action
# reveal, one for the authorization-only reveal, one for the defensive burn.
# The seed is the same fixed test seed the golden vectors use, so every
# number in the benchmark report is reproducible from a clean clone:
# bench/gen_vectors.sh && bench/run.sh
set -euo pipefail
cd "$(dirname "$0")/.."

SEED=$(python3 -c "import json; print(json.load(open('contracts/test/vectors/golden.json'))['seed'])")

for DEPTH in 8 16 20; do
  OUT="contracts/test/vectors/bench-depth${DEPTH}.json"
  # The CLI emits pretty-printed JSON objects back to back; decode them
  # streamingly instead of splitting on braces.
  (cd tooling && for IDX in 5 7 9 11 13; do
      cargo run -q --release -p qca-cli -- proof --seed "$SEED" --depth "$DEPTH" --index "$IDX"
   done) | python3 -c "
import json, sys
dec = json.JSONDecoder()
buf = sys.stdin.read()
leaves, pos = [], 0
while pos < len(buf):
    obj, end = dec.raw_decode(buf, pos)
    leaves.append(obj)
    pos = end
    while pos < len(buf) and buf[pos].isspace():
        pos += 1
roots = {l['root'] for l in leaves}
assert len(roots) == 1, roots
json.dump({'depth': $DEPTH, 'seed': '$SEED', 'root': leaves[0]['root'],
           'leaves': [{'index': l['leaf_index'], 'secret': l['secret'],
                       'proof': l['proof']} for l in leaves]},
          open('$OUT', 'w'), indent=2)
print('wrote $OUT')
"
done
