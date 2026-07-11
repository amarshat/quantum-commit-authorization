// End-to-end native-AA (tx type 0x71) driver for QCAAccountZkSync on
// anvil-zksync. Unlike the forge --zksync unit tests, this exercises the FULL
// path: validateTransaction runs in the bootloader and increments the account
// nonce through the NonceHolder system contract (which the forge test VM does
// not run), then executeTransaction runs the aging gate and the action. Gas is
// read from the transaction receipt, the only ground truth.
//
// Per depth we drive two flows, matching the L1 base and 4337 benches:
//   - auth-only: to a burn-address sink, value 0, empty calldata
//   - action:    a 1-ETH transfer to a recipient
// A commit is posted, chain time is advanced past minCommitAge, then the reveal
// is sent as a type-0x71 transaction from the account with the reveal payload
// carried in customSignature.
//
// Output: JSON on stdout, {depth: {authOnly, action}} with receipt gasUsed.

import { ethers } from "ethers";
import { Provider, Wallet, ContractFactory, utils, types } from "zksync-ethers";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const RPC = process.env.RPC || "http://127.0.0.1:8011";
// anvil-zksync rich account 0 (same key as anvil).
const RICH_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const DEPTHS = (process.env.DEPTHS || "8,16,20").split(",").map((s) => parseInt(s, 10));

const MIN_AGE = 5n; // seconds
const TTL = 1000n; // seconds
const MAX_FEE_CAP = ethers.parseEther("1"); // huge cap, binding never the limit here
const CALL_GAS_FLOOR = 0n;

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

function leafHashOf(secret) {
  return kc(abi.encode(["bytes32", "bytes32"], [TAG_LEAF, secret]));
}

// A depth-d membership proof for leafIndex 0 without materializing 2^d leaves:
// pick arbitrary sibling hashes and fold up to get the root the contract will
// recompute. leafIndex 0 => every step hashes (node, sibling). The contract
// only checks fold(leaf, proof) == root, so this is a genuine valid proof.
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

function commitmentOf(chainId, account, actionHash, leafIndex, secret, maxFeeCap, callGasFloor) {
  return kc(
    abi.encode(
      ["bytes32", "uint256", "address", "bytes32", "uint256", "bytes32", "uint256", "uint256"],
      [TAG_COMMIT, chainId, account, actionHash, leafIndex, secret, maxFeeCap, callGasFloor],
    ),
  );
}

async function rpc(provider, method, params = []) {
  return provider.send(method, params);
}

async function runFlow(provider, richWallet, chainId, depth, label, target, value) {
  // Deterministic secret (not random) so the whole run reproduces: same secret
  // => same proof, commitment, account address, tx hash, and gasUsed, which is
  // what the CI drift check re-measures and diffs against the committed file.
  const secret = kc(ethers.toUtf8Bytes(`QCA/zksync-bench/${label}/${depth}`));
  const leafIndex = 0n;
  const { proof, root } = buildProofAndRoot(secret, depth);

  // Deploy a fresh account per flow so nonces / used-leaf state never collide.
  // Must be "createAccount": a plain CREATE registers a non-account contract,
  // and the bootloader rejects a type-0x71 tx from it ("Sender is not an
  // account"). createAccount marks AccountAbstractionVersion.Version1.
  const factory = new ContractFactory(artifact.abi, artifact.bytecode, richWallet, "createAccount");
  const account = await factory.deploy(root, depth, MIN_AGE, TTL);
  await account.waitForDeployment();
  const accountAddr = await account.getAddress();

  // Fund the account: it pays its own fees to the bootloader, plus any action value.
  await (
    await richWallet.sendTransaction({
      to: accountAddr,
      value: ethers.parseEther("10"),
    })
  ).wait();

  const data = "0x";
  const actionHash = actionHashOf(target, value, data);
  const c = commitmentOf(chainId, accountAddr, actionHash, leafIndex, secret, MAX_FEE_CAP, CALL_GAS_FLOOR);

  // Commit (permissionless plain tx). Anyone may post; use the account itself
  // via a rich-wallet call to account.commit(c).
  const acctAsRich = new ethers.Contract(accountAddr, artifact.abi, richWallet);
  const commitTx = await acctAsRich.commit(c);
  const commitRcpt = await commitTx.wait();

  // Advance chain time past minCommitAge so the aging gate in execute passes.
  await rpc(provider, "evm_increaseTime", [Number(MIN_AGE) + 2]);
  await rpc(provider, "evm_mine", []);

  // Build the reveal as a type-0x71 tx from the account. The reveal payload
  // rides in customSignature; validateTransaction decodes it.
  const sig = abi.encode(
    ["uint256", "bytes32", "bytes32[]", "uint256", "uint256"],
    [leafIndex, secret, proof, MAX_FEE_CAP, CALL_GAS_FLOOR],
  );

  const gasPrice = await provider.getGasPrice();
  // Do NOT call provider.estimateGas here. Estimation runs validation with the
  // block's maximum gas, so gasleft() exceeds 2^32 and the account's
  // uint32(gasleft()) passed to the NonceHolder system call truncates to
  // garbage, panicking the SystemContractsCaller trampoline (the stock
  // DefaultAccount has the identical hazard). Under a concrete, sane gasLimit
  // the truncation is a no-op. We pass a generous fixed limit; unused gas is
  // refunded and the receipt's gasUsed is the ground truth we report.
  const FIXED_GAS = BigInt(process.env.FIXED_GAS || "80000000");
  let tx = {
    type: 113,
    from: accountAddr,
    to: target,
    value,
    data,
    chainId,
    nonce: await provider.getTransactionCount(accountAddr),
    gasPrice,
    gasLimit: FIXED_GAS,
    customData: {
      gasPerPubdata: utils.DEFAULT_GAS_PER_PUBDATA_LIMIT,
      customSignature: sig,
    },
  };
  const serialized = utils.serializeEip712(tx);
  const resp = await provider.broadcastTransaction(serialized);
  const revealRcpt = await resp.wait();

  return {
    label,
    depth,
    account: accountAddr,
    commitGasUsed: commitRcpt.gasUsed.toString(),
    revealGasUsed: revealRcpt.gasUsed.toString(),
    revealGasLimit: tx.gasLimit.toString(),
    revealStatus: revealRcpt.status,
    revealTxHash: revealRcpt.hash,
  };
}

// The ECDSA baseline. A zkSync EOA is the DefaultAccount system contract, which
// verifies a secp256k1 signature in its validateTransaction. So a plain signed
// transfer from an EOA is the like-for-like "ECDSA account authorizes the same
// action" cost. The gap to our reveal is what the zero-ECDSA commit-reveal
// machinery (membership proof, nullifier SSTORE, aging) adds. A dedicated wallet
// with its own nonce sequence keeps this deterministic and independent of the
// account flows.
const BASELINE_KEY = "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba"; // rich acct 5

async function runBaseline(wallet, label, target, value) {
  const rcpt = await (await wallet.sendTransaction({ to: target, value, data: "0x" })).wait();
  return {
    label,
    target,
    value: value.toString(),
    gasUsed: rcpt.gasUsed.toString(),
    txHash: rcpt.hash,
  };
}

async function main() {
  const provider = new Provider(RPC);
  const richWallet = new Wallet(RICH_KEY, provider);
  const net = await provider.getNetwork();
  const chainId = net.chainId;

  const sink = "0x000000000000000000000000000000000000dEaD";
  const recipient = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"; // rich acct 1

  // ECDSA DefaultAccount baseline for the same two actions.
  // Baseline sends to a real EOA (not the 0xdead sink): anvil-zksync rejects a
  // tx-level transfer to the empty 0xdead address, though the QCA reveal reaches
  // it fine via an internal call. The destination is immaterial to what this
  // measures (the DefaultAccount's ECDSA validation overhead).
  const baseWallet = new Wallet(BASELINE_KEY, provider);
  const baseline = {
    authOnly: await runBaseline(baseWallet, "authOnly", recipient, 0n),
    action: await runBaseline(baseWallet, "action", recipient, ethers.parseEther("1")),
  };
  console.error(
    `ecdsa baseline: authOnly ${baseline.authOnly.gasUsed} gas, action ${baseline.action.gasUsed} gas`,
  );

  const out = { chainId: chainId.toString(), rpc: RPC, ecdsaBaseline: baseline, depths: {} };
  for (const depth of DEPTHS) {
    const authOnly = await runFlow(provider, richWallet, chainId, depth, "authOnly", sink, 0n);
    const action = await runFlow(
      provider,
      richWallet,
      chainId,
      depth,
      "action",
      recipient,
      ethers.parseEther("1"),
    );
    out.depths[depth] = { authOnly, action };
    console.error(
      `depth ${depth}: authOnly reveal ${authOnly.revealGasUsed} gas, action reveal ${action.revealGasUsed} gas`,
    );
  }
  process.stdout.write(JSON.stringify(out, null, 2) + "\n");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
