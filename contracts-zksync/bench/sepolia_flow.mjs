// End-to-end native-AA (tx type 0x71) driver for QCAAccountZkSync on a REAL
// public network: zkSync Era Sepolia testnet. This is the on-chain existence
// proof, as opposed to bench/aa_flow.mjs which runs the identical flow on the
// anvil-zksync emulator. The differences from the emulator harness are exactly
// the ones that make this a real-network result:
//
//   - Aging is real wall-clock: there is no evm_increaseTime on a public chain,
//     so the harness actually sleeps minCommitAge (plus a block-time margin)
//     between the commit and the reveal.
//   - Pubdata is priced by the live network, not a fixed emulator rate, so the
//     reveal's extra nullifier state-diff is charged at the real gasPerPubdata
//     the sequencer reports. This is the number the emulator run can only bound.
//   - Funding comes from a deployer key the operator supplies out of band
//     (env PRIVATE_KEY); it never appears in this file or the committed output.
//
// Usage (the key stays in your shell, not in the repo or in any log):
//   export PRIVATE_KEY=0x<era-sepolia-testnet-key-with-testnet-ETH>
//   RPC=https://sepolia.era.zksync.dev DEPTHS=8,16,20 \
//     node bench/sepolia_flow.mjs > bench/results/qca-sepolia-receipts.json
//
// Output: JSON on stdout, same shape as aa_flow.mjs, with an added blockExplorer
// URL per transaction so every measured number is independently verifiable
// on-chain.

import { ethers } from "ethers";
import { Provider, Wallet, ContractFactory, utils } from "zksync-ethers";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const RPC = process.env.RPC || "https://sepolia.era.zksync.dev";
const EXPLORER = process.env.EXPLORER || "https://sepolia.explorer.zksync.io/tx";
const PRIVATE_KEY = process.env.PRIVATE_KEY;
if (!PRIVATE_KEY) {
  console.error("Set PRIVATE_KEY to an Era Sepolia testnet key funded with testnet ETH.");
  console.error("Use a THROWAWAY key (testnet only). It is read from env and never written out.");
  process.exit(1);
}
const DEPTHS = (process.env.DEPTHS || "8,16,20").split(",").map((s) => parseInt(s, 10));

// Real network: minCommitAge in seconds, and we genuinely wait it out. Keep it
// small so the run finishes in minutes, with a margin above L2 block time when
// we sleep. TTL comfortably longer than the whole per-flow sequence.
const MIN_AGE = 3n; // seconds
const TTL = 3600n; // seconds
const AGE_SLEEP_MS = 20_000; // wall sleep after commit: MIN_AGE + block-time margin

// Envelope caps: generous so the binding is never the measured limit (the
// rejection paths are covered by the forge tests). Must sit above the tx fields.
const MAX_FEE_CAP = ethers.parseEther("1");
const MAX_GAS_CEIL = 10n ** 12n;
const MAX_PUBDATA_CEIL = 10n ** 9n;
const CALL_GAS_LIMIT = 2_000_000n;

// A fixed, generous tx gasLimit: estimateGas runs validation at block-max gas so
// uint32(gasleft()) truncates and panics (same hazard as the emulator harness
// and the stock DefaultAccount), so we never estimate. Unused gas is refunded;
// the receipt's gasUsed is the ground truth. Kept far smaller than the emulator's
// 80M so the account's totalRequiredBalance preflight (gasLimit * maxFeePerGas)
// stays affordable in scarce testnet ETH.
const FIXED_GAS = BigInt(process.env.FIXED_GAS || "30000000");
// Tiny action value: on testnet ETH is scarce, and the value amount does not
// affect the CALL gas, so a small transfer measures the same action-flow gas as
// the emulator's 1 ETH transfer.
const ACTION_VALUE = ethers.parseEther(process.env.ACTION_VALUE || "0.0001");
// Per-account funding: covers the fee preflight (FIXED_GAS * gasPrice) plus the
// action value, with margin. Refunded gas returns here, so this is a float.
const FUND = ethers.parseEther(process.env.FUND || "0.02");

const here = dirname(fileURLToPath(import.meta.url));
const artifact = JSON.parse(
  readFileSync(join(here, "../zkout/QCAAccountZkSync.sol/QCAAccountZkSync.json"), "utf8"),
);

const abi = ethers.AbiCoder.defaultAbiCoder();
const kc = ethers.keccak256;
const tag = (s) => kc(ethers.toUtf8Bytes(s));
const TAG_LEAF = tag("QCA/v1/leaf");
const TAG_NODE = tag("QCA/v1/node");
const TAG_ACTION = tag("QCA/v1/action");
const TAG_COMMIT = tag("QCA/v1/commit");
const TAG_ENV_ZKSYNC = tag("QCA/v1/env/zksync");

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function leafHashOf(secret) {
  return kc(abi.encode(["bytes32", "bytes32"], [TAG_LEAF, secret]));
}

// Depth-d membership proof for leafIndex 0 without materializing 2^d leaves:
// arbitrary sibling hashes folded up give the root the contract recomputes.
// leafIndex 0 => every step hashes (node, sibling); the contract only checks
// fold(leaf, proof) == root, so this is a genuine valid proof.
function buildProofAndRoot(secret, depth) {
  const proof = [];
  for (let i = 0; i < depth; i++) {
    proof.push(kc(abi.encode(["bytes32", "uint256"], [TAG_NODE, BigInt(i + 1)])));
  }
  let node = leafHashOf(secret);
  for (let i = 0; i < depth; i++) {
    node = kc(abi.encode(["bytes32", "bytes32", "bytes32"], [TAG_NODE, node, proof[i]]));
  }
  return { proof, root: node };
}

function actionHashOf(target, value, data) {
  return kc(
    abi.encode(
      ["bytes32", "address", "uint256", "bytes32"],
      [TAG_ACTION, target, value, kc(data)],
    ),
  );
}

function commitmentOf(chainId, account, actionHash, leafIndex, secret) {
  return kc(
    abi.encode(
      [
        "bytes32", "bytes32", "uint256", "address", "bytes32", "uint256", "bytes32",
        "uint256", "uint256", "uint256", "uint256",
      ],
      [
        TAG_COMMIT, TAG_ENV_ZKSYNC, chainId, account, actionHash, leafIndex, secret,
        MAX_FEE_CAP, MAX_GAS_CEIL, MAX_PUBDATA_CEIL, CALL_GAS_LIMIT,
      ],
    ),
  );
}

async function runFlow(provider, deployer, chainId, depth, label, target, value) {
  // Deterministic secret so a re-run reproduces the same commitment (gas can
  // still move because pubdata price floats; that is the real-network point).
  const secret = kc(ethers.toUtf8Bytes(`QCA/sepolia-bench/${label}/${depth}`));
  const leafIndex = 0n;
  const { proof, root } = buildProofAndRoot(secret, depth);

  // Deploy via createAccount so the deployment registers an AA account; a plain
  // CREATE registers a non-account and the bootloader rejects its type-0x71 tx.
  const factory = new ContractFactory(artifact.abi, artifact.bytecode, deployer, "createAccount");
  const account = await factory.deploy(root, depth, MIN_AGE, TTL);
  await account.waitForDeployment();
  const accountAddr = await account.getAddress();

  // Fund the account: it pays its own fees to the bootloader plus the action value.
  await (await deployer.sendTransaction({ to: accountAddr, value: FUND })).wait();

  const data = "0x";
  const actionHash = actionHashOf(target, value, data);
  const c = commitmentOf(chainId, accountAddr, actionHash, leafIndex, secret);

  // Commit (permissionless plain tx) through the account itself.
  const acctAsDeployer = new ethers.Contract(accountAddr, artifact.abi, deployer);
  const commitRcpt = await (await acctAsDeployer.commit(c)).wait();

  // Real aging: wait out minCommitAge in wall-clock, plus a block-time margin,
  // so the reveal executes in a block whose timestamp is past committedAt+MIN_AGE.
  await sleep(AGE_SLEEP_MS);

  const sig = abi.encode(
    ["uint256", "bytes32", "bytes32[]", "uint256", "uint256", "uint256", "uint256"],
    [leafIndex, secret, proof, MAX_FEE_CAP, MAX_GAS_CEIL, MAX_PUBDATA_CEIL, CALL_GAS_LIMIT],
  );

  const gasPrice = await provider.getGasPrice();
  const tx = {
    type: 113,
    from: accountAddr,
    to: target,
    value,
    data,
    chainId,
    nonce: await provider.getTransactionCount(accountAddr),
    gasPrice,
    gasLimit: FIXED_GAS,
    customData: { gasPerPubdata: utils.DEFAULT_GAS_PER_PUBDATA_LIMIT, customSignature: sig },
  };
  const resp = await provider.broadcastTransaction(utils.serializeEip712(tx));
  const revealRcpt = await resp.wait();

  return {
    label,
    depth,
    account: accountAddr,
    commitGasUsed: commitRcpt.gasUsed.toString(),
    revealGasUsed: revealRcpt.gasUsed.toString(),
    revealEffectiveGasPrice: revealRcpt.gasPrice ? revealRcpt.gasPrice.toString() : undefined,
    revealStatus: revealRcpt.status,
    commitTx: `${EXPLORER}/${commitRcpt.hash}`,
    revealTx: `${EXPLORER}/${revealRcpt.hash}`,
  };
}

async function runBaseline(wallet, label, target, value) {
  // ECDSA DefaultAccount baseline: a plain signed transfer from an EOA, whose
  // validation verifies secp256k1. Like-for-like cost of an ECDSA account
  // authorizing the same action.
  const rcpt = await (await wallet.sendTransaction({ to: target, value, data: "0x" })).wait();
  return {
    label,
    value: value.toString(),
    gasUsed: rcpt.gasUsed.toString(),
    tx: `${EXPLORER}/${rcpt.hash}`,
  };
}

async function main() {
  const provider = new Provider(RPC);
  const deployer = new Wallet(PRIVATE_KEY, provider);
  const net = await provider.getNetwork();
  const chainId = net.chainId;
  const bal = await provider.getBalance(deployer.address);
  console.error(`deployer ${deployer.address} balance ${ethers.formatEther(bal)} ETH on chain ${chainId}`);

  const recipient = "0x000000000000000000000000000000000000bEEF"; // inert sink for the action value
  const sink = "0x000000000000000000000000000000000000dEaD";

  // ECDSA baseline from the deployer EOA for the two actions.
  const baseline = {
    authOnly: await runBaseline(deployer, "authOnly", recipient, 0n),
    action: await runBaseline(deployer, "action", recipient, ACTION_VALUE),
  };
  console.error(`ecdsa baseline: authOnly ${baseline.authOnly.gasUsed}, action ${baseline.action.gasUsed}`);

  const out = { network: "zksync-era-sepolia", chainId: chainId.toString(), rpc: RPC, ecdsaBaseline: baseline, depths: {} };
  for (const depth of DEPTHS) {
    const authOnly = await runFlow(provider, deployer, chainId, depth, "authOnly", sink, 0n);
    const action = await runFlow(provider, deployer, chainId, depth, "action", recipient, ACTION_VALUE);
    out.depths[depth] = { authOnly, action };
    console.error(`depth ${depth}: authOnly ${authOnly.revealGasUsed} (${authOnly.revealStatus}), action ${action.revealGasUsed} (${action.revealStatus})`);
  }
  process.stdout.write(JSON.stringify(out, null, 2) + "\n");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
