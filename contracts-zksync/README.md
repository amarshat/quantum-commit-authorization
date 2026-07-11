# contracts-zksync

The zkSync Era native-AA build of the commit-reveal account
(`QCAAccountZkSync.sol`), the end-to-end zero-ECDSA existence proof. Kept in a
separate Foundry project because it needs the foundry-zksync toolchain (zksolc,
EraVM), isolated from the main `contracts/` L1 stack and its CI.

## Setup

```
npm install                              # zksync-contracts, OZ, ethers, zksync-ethers
git clone --depth 1 https://github.com/foundry-rs/forge-std lib/forge-std
foundryup-zksync                         # installs the zksync forge + anvil-zksync
```

## Build and test

```
forge build --zksync                     # compile with zksolc to EraVM
forge test  --zksync -vv
```

Pinned: foundry-zksync 0.1.9, zksolc 1.5.15 (see foundry.toml). Deps pinned in
package-lock.json.

`foundry.toml` sets `enable_eravm_extensions = true`. This is required: the
`NonceHolder` system call in `validateTransaction` goes through
`SystemContractsCaller`, which only compiles to a real EraVM system call with the
flag on. Without it a live node halts validation with "no function selector
available." The forge test VM never runs that path, so leaving it off looks fine
until the end-to-end run below.

## End-to-end AA flow + gas (anvil-zksync)

```
bench/measure_zksync.sh                   # real type-0x71 reveal, receipts -> bench/results/
python3 bench/report.py                   # -> bench/results/RESULTS.md
```

This is the part the unit tests cannot show: it drives a real type-`0x71`
transaction through the bootloader (validation with the NonceHolder increment)
and executeTransaction, and reads gas from the receipt. Deterministic (fixed
secrets), so re-running reproduces the same hashes and gas. The forge tests cover
the execute path and the security bindings (fee cap, call-gas floor, action
binding, aging-in-execute with leaf preservation) on the zkSync VM. See
docs/AA-ZKSYNC.md; testnet deploy (Era Sepolia) is the remaining step.
