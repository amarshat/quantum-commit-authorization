# Era Sepolia public-testnet run

Turns the anvil-zksync emulator existence proof into a real on-chain one: the
native-AA reveal validated and executed on a public network, at live pubdata
pricing. Your private key stays in your shell (read from `PRIVATE_KEY`); it is
never written to the repo, the output file, or any log.

## 1. A throwaway testnet key

Use a fresh, testnet-only key. Never a key that holds mainnet funds.

```
cast wallet new          # prints an address + private key, or use any throwaway
```

## 2. Era Sepolia testnet ETH (~0.1 ETH is plenty)

Two routes:
- Faucet straight to Era Sepolia (fastest if available): the zkSync docs list
  current faucets at https://docs.zksync.io/build/tooling/network-faucets .
- Or get Ethereum Sepolia ETH from any Sepolia faucet, then bridge it to Era
  Sepolia at https://portal.zksync.io/bridge (select Sepolia testnet).

Fund the throwaway address from step 1. One run of all three depths funds six
throwaway accounts at 0.02 ETH each plus deploy/commit gas, so ~0.15 ETH covers
the full sweep; ~0.05 ETH covers a single-depth smoke run (`DEPTHS=16`).

## 3. Rebuild the fixed contract and run

```
cd contracts-zksync
~/.foundry/bin/forge build --zksync -q        # matches committed source

export PRIVATE_KEY=0x<your throwaway testnet key>

# Smoke test first: one depth, proves the path works and prints the headline.
RPC=https://sepolia.era.zksync.dev DEPTHS=16 \
  node bench/sepolia_flow.mjs > bench/results/qca-sepolia-receipts.json

# Full sweep once the smoke test lands (all three depths for the scaling figure):
RPC=https://sepolia.era.zksync.dev DEPTHS=8,16,20 \
  node bench/sepolia_flow.mjs > bench/results/qca-sepolia-receipts.json
```

The run takes a few minutes: it genuinely sleeps ~20s between each commit and its
reveal (real wall-clock aging, no `evm_increaseTime` on a public chain). Progress
prints to stderr; the JSON goes to the results file.

## 4. What to send back

`bench/results/qca-sepolia-receipts.json`. It records, per depth and flow, the
receipt `gasUsed`, the effective gas price, the reveal status (must be 1), and a
block-explorer URL for every transaction so every number is independently
verifiable on-chain. I fold the real numbers into the paper's L2 section and drop
the "emulator floor" hedge.

## Notes / troubleshooting

- If a reveal comes back status 0 (reverted), capture the explorer link and the
  stderr; the likely causes are underfunding (raise `FUND`) or the account not
  being aged yet (raise `AGE_SLEEP_MS`).
- `FIXED_GAS`, `FUND`, `ACTION_VALUE`, `EXPLORER` are overridable via env if the
  defaults do not fit the network conditions on the day.
- The account keeps its small leftover balance; on testnet it is not worth
  sweeping back.
