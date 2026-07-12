// Sample the ECDSA DefaultAccount baseline several times to denoise the
// real-network variance. A zkSync EOA is the DefaultAccount system contract
// (secp256k1 in its own validation), so a plain signed transfer is the cost of
// an ECDSA account authorizing a transfer. N samples to an already-existing
// recipient (no account-creation state diff), reported with the median.
//   export PRIVATE_KEY=0x...
//   RPC=https://sepolia.era.zksync.dev N=6 node bench/baseline_sample.mjs
import { ethers } from "ethers";
import { Provider, Wallet } from "zksync-ethers";

const RPC = process.env.RPC || "https://sepolia.era.zksync.dev";
const N = parseInt(process.env.N || "6", 10);
const wallet = new Wallet(process.env.PRIVATE_KEY, new Provider(RPC));
// Existing account (funded by earlier runs) so no first-touch creation cost.
const to = "0x00000000000000000000000000000000DeaDBeef";
const val = ethers.parseEther("0.00001");

const samples = [];
for (let i = 0; i < N; i++) {
  const rcpt = await (await wallet.sendTransaction({ to, value: val })).wait();
  samples.push(Number(rcpt.gasUsed));
  console.error(`sample ${i}: ${rcpt.gasUsed}`);
}
samples.sort((a, b) => a - b);
const median = samples[Math.floor(samples.length / 2)];
console.error(`min ${samples[0]} median ${median} max ${samples[samples.length - 1]}`);
process.stdout.write(JSON.stringify({ samples, median, min: samples[0], max: samples[samples.length - 1] }) + "\n");
