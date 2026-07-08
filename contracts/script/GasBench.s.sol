// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Script, console} from "forge-std/Script.sol";
import {CommitRevealAccount} from "../src/CommitRevealAccount.sol";

/// @notice Sends the full benchmark flow as real transactions so the numbers
///         come from receipts, not from in-test gas accounting. Run against
///         a fresh anvil instance by bench/run.sh:
///
///             forge script script/GasBench.s.sol --rpc-url $RPC \
///                 --private-key $KEY --broadcast
///
///         Receipt gasUsed already contains intrinsic gas, calldata gas and
///         the EIP-7623 floor, so bench/report.py applies no model to our
///         side at all. Earlier snapshotGas-based numbers double counted
///         those components; receipts cannot.
///
///         Per depth, six transactions in fixed order (bench/report.py
///         indexes into the receipt list by this order):
///           1. deploy (the one-time cost the amortization column uses)
///           2. commit for the action reveal
///           3. commit for the authorization-only reveal
///           4. reveal executing 1 ether to a cold empty EOA
///           5. reveal executing nothing (target = the account itself,
///              zero value), the like-for-like row against baselines that
///              only verify a signature
///           6. defensive burn of a third leaf
///
///         minCommitAge is 1 here because anvil mines one block per
///         transaction and there is no vm.roll on a live chain; the age
///         check compares block numbers, so the parameter does not change
///         reveal gas.
contract GasBenchScript is Script {
    bytes32 constant TAG_ACTION = keccak256("QCA/v1/action");
    bytes32 constant TAG_COMMIT = keccak256("QCA/v1/commit");
    bytes32 constant TAG_BURN = keccak256("QCA/v1/burn");

    uint256 constant MIN_COMMIT_AGE = 1;
    uint256 constant COMMIT_TTL = 256;
    uint256 constant ACTION_VALUE = 1 ether;

    /// Distinct per depth: the first flow would otherwise fund the shared
    /// target, and later flows would not pay the 25K new-account cost a
    /// transfer to a fresh EOA really costs.
    function actionTarget(uint256 depth) internal pure returns (address) {
        return address(uint160(0xBEEF00) + uint160(depth));
    }

    function run() external {
        uint256[3] memory depths = [uint256(8), 16, 20];
        // At genesis a commit would store committedAt = block.number = 0,
        // which the contract defines as "no commitment". Only reachable in
        // the local prep run against a fresh anvil.
        if (block.number == 0) vm.roll(1);
        vm.startBroadcast();
        for (uint256 i = 0; i < depths.length; i++) {
            runDepth(depths[i]);
        }
        vm.stopBroadcast();
    }

    function runDepth(uint256 depth) internal {
        string memory json = vm.readFile(string.concat("test/vectors/bench-depth", vm.toString(depth), ".json"));
        bytes32 root = vm.parseJsonBytes32(json, ".root");

        (uint256 idxAction, bytes32 secretAction, bytes32[] memory proofAction) = leaf(json, 0);
        (uint256 idxNoop, bytes32 secretNoop, bytes32[] memory proofNoop) = leaf(json, 1);
        (uint256 idxBurn, bytes32 secretBurn, bytes32[] memory proofBurn) = leaf(json, 2);

        CommitRevealAccount account =
            new CommitRevealAccount{value: 10 ether}(root, depth, MIN_COMMIT_AGE, COMMIT_TTL);

        account.commit(commitment(account, actionTarget(depth), ACTION_VALUE, "", idxAction, secretAction));
        account.commit(commitment(account, address(account), 0, "", idxNoop, secretNoop));
        // Burn is age-gated now, so the defensive nullify is itself a two-tx
        // flow: commit-to-burn, then burn. The burn commitment sits in the
        // action slot as TAG_BURN, domain-separated from action commitments.
        account.commit(burnCommitment(account, idxBurn, secretBurn));

        // Local prep execution runs the whole body in one block, where the
        // reveals would fail the minCommitAge check (and at anvil's genesis
        // block 0 a commit would store committedAt = 0, which the contract
        // reads as absent). vm.roll fixes the local run and is not a
        // transaction, so it changes nothing on the target chain, where
        // --slow mines each transaction in its own block anyway.
        vm.roll(block.number + MIN_COMMIT_AGE);

        account.reveal(actionTarget(depth), ACTION_VALUE, "", idxAction, secretAction, proofAction);
        account.reveal(address(account), 0, "", idxNoop, secretNoop, proofNoop);
        account.burn(idxBurn, secretBurn, proofBurn);
    }

    function leaf(string memory json, uint256 i)
        internal
        pure
        returns (uint256 index, bytes32 secret, bytes32[] memory proof)
    {
        string memory base = string.concat(".leaves[", vm.toString(i), "]");
        index = vm.parseJsonUint(json, string.concat(base, ".index"));
        secret = vm.parseJsonBytes32(json, string.concat(base, ".secret"));
        proof = vm.parseJsonBytes32Array(json, string.concat(base, ".proof"));
    }

    function commitment(
        CommitRevealAccount account,
        address target,
        uint256 value,
        bytes memory data,
        uint256 index,
        bytes32 secret
    ) internal view returns (bytes32) {
        bytes32 actionHash = keccak256(abi.encode(TAG_ACTION, target, value, keccak256(data)));
        return keccak256(abi.encode(TAG_COMMIT, block.chainid, address(account), actionHash, index, secret));
    }

    function burnCommitment(CommitRevealAccount account, uint256 index, bytes32 secret)
        internal
        view
        returns (bytes32)
    {
        return keccak256(abi.encode(TAG_COMMIT, block.chainid, address(account), TAG_BURN, index, secret));
    }
}
