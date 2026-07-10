# contracts-zksync

The zkSync Era native-AA build of the commit-reveal account
(`QCAAccountZkSync.sol`), the end-to-end zero-ECDSA existence proof. Kept in a
separate Foundry project because it needs the foundry-zksync toolchain (zksolc,
EraVM), isolated from the main `contracts/` L1 stack and its CI.

## Setup

```
npm install                              # @matterlabs/zksync-contracts, OZ
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

The execute path and the security bindings (fee cap, call-gas floor, action
binding, aging-in-execute with leaf preservation) are covered by forge tests on
the zkSync VM. The full validation path increments the account nonce through the
NonceHolder system contract, which foundry-zksync's test VM does not run; that
path is exercised on anvil-zksync / Era Sepolia. See docs/AA-ZKSYNC.md.
