#!/usr/bin/env bash
# Run every gas benchmark and regenerate bench/results/.
#
# Baselines run inside their pinned submodules with their own foundry.toml,
# so upstream's published numbers stay reproducible on their terms. Our
# numbers come from transaction receipts against anvil (measure_qca.sh).
# report.py folds both into the comparison tables.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p results

DESC=$(git -C .. describe --always --dirty)
case "$DESC" in
  *-dirty) echo "WARNING: working tree dirty; results will not be attributable to a commit" ;;
esac

{
  forge --version
  anvil --version | head -1
  echo "ETHFALCON    $(git -C lib/ETHFALCON rev-parse HEAD)"
  echo "ETHDILITHIUM $(git -C lib/ETHDILITHIUM rev-parse HEAD)"
  echo "qca          $DESC"
  echo "date         $(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > results/env.txt

echo "== ETHFALCON baselines (upstream Benchmark suite) =="
(cd lib/ETHFALCON && forge test --match-contract Benchmark -vv) | tee results/ethfalcon.log

echo "== ETHDILITHIUM baselines (upstream KAT suites, no FFI) =="
(cd lib/ETHDILITHIUM && forge test --match-path 'test/dilithiumKATS.t.sol' -vv) | tee results/dilithium-nist.log
(cd lib/ETHDILITHIUM && forge test --match-path 'test/ethdilithiumKAT.t.sol' -vv) | tee results/dilithium-eth.log

echo "== CommitRevealAccount (receipts from anvil) =="
./measure_qca.sh

echo "== CommitRevealAccount under ERC-4337 v0.8 (receipts from anvil) =="
./measure_4337.sh

python3 report.py > results/RESULTS.md
echo "wrote results/RESULTS.md"
