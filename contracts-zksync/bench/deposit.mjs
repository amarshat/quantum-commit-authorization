// Bridge Ethereum Sepolia (L1) ETH to zkSync Era Sepolia (L2), signing with the
// same throwaway key the measurement run uses. This is the no-mainnet-balance
// path: fund the address on L1 Sepolia from a proof-of-work faucet (which gates
// on nothing), then run this to move it to Era Sepolia. No MetaMask, no portal.
//
// Usage:
//   export PRIVATE_KEY=0x<throwaway key, already funded on L1 Sepolia>
//   node bench/deposit.mjs            # bridges AMOUNT (default 0.05) ETH to L2
//
// The L1->L2 deposit takes ~10-20 minutes to finalize on L2; the script waits.
// Override L1_RPC / AMOUNT via env if needed.

import { ethers } from "ethers";
import { Provider, Wallet, utils } from "zksync-ethers";

const PRIVATE_KEY = process.env.PRIVATE_KEY;
if (!PRIVATE_KEY) {
  console.error("Set PRIVATE_KEY (throwaway testnet key, funded on Ethereum Sepolia L1).");
  process.exit(1);
}
const L1_RPC = process.env.L1_RPC || "https://ethereum-sepolia-rpc.publicnode.com";
const L2_RPC = process.env.RPC || "https://sepolia.era.zksync.dev";
const AMOUNT = ethers.parseEther(process.env.AMOUNT || "0.05");

const l1 = new ethers.JsonRpcProvider(L1_RPC);
const l2 = new Provider(L2_RPC);
const wallet = new Wallet(PRIVATE_KEY, l2, l1);

const l1bal = await l1.getBalance(wallet.address);
const l2bal = await l2.getBalance(wallet.address);
console.error(`address ${wallet.address}`);
console.error(`  L1 Sepolia balance: ${ethers.formatEther(l1bal)} ETH`);
console.error(`  L2 Era Sepolia balance (before): ${ethers.formatEther(l2bal)} ETH`);

if (l1bal < AMOUNT) {
  console.error(`L1 balance below AMOUNT (${ethers.formatEther(AMOUNT)}). Fund L1 Sepolia first.`);
  process.exit(1);
}

console.error(`depositing ${ethers.formatEther(AMOUNT)} ETH L1 -> L2 ...`);
const dep = await wallet.deposit({ token: utils.ETH_ADDRESS, amount: AMOUNT, to: wallet.address });
console.error(`  L1 deposit tx: ${dep.hash}`);
console.error(`  waiting for L2 finalization (~10-20 min)...`);
await dep.wait();
const after = await l2.getBalance(wallet.address);
console.error(`done. L2 Era Sepolia balance (after): ${ethers.formatEther(after)} ETH`);
