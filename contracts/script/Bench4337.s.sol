// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {EntryPoint} from "@account-abstraction/core/EntryPoint.sol";
import {IEntryPoint} from "@account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@account-abstraction/interfaces/PackedUserOperation.sol";
import {QCAAccount4337} from "../src/QCAAccount4337.sol";

/// @notice Receipt-level gas for the 4337 reveal path, measured the same way as
///         the base benchmark (bench/): real transactions against anvil, so
///         intrinsic gas, calldata, EntryPoint overhead, validation, and
///         execution are all inside gasUsed. Run in two phases with a real
///         time advance between them, because the reveal's validAfter gate is
///         enforced by the EntryPoint against the live chain clock:
///
///           forge script ... --sig "deployPhase()" --broadcast --skip-simulation
///           cast rpc evm_increaseTime 5 ; cast rpc evm_mine
///           forge script ... --sig "revealPhase()" --broadcast --slow --skip-simulation
///
///         bench/measure_4337.sh drives this and reads the receipts. Depth 16
///         only: the 4337 overhead over the base reveal is dominated by the
///         EntryPoint wrapper and UserOp calldata, which do not vary with tree
///         depth; the Merkle part scales exactly as the base scheme (measured
///         at 8/16/20 there).
contract Bench4337Script is Script {
    bytes32 constant TAG_ACTION = keccak256("QCA/v1/action");
    bytes32 constant TAG_COMMIT = keccak256("QCA/v1/commit");

    uint256 constant MIN_AGE = 1; // seconds; validAfter granularity
    uint256 constant TTL = 100_000;
    uint256 constant ACTION_VALUE = 1 ether;
    address constant ACTION_TARGET = address(0xBEEF16);

    string constant ADDR_FILE = "bench-4337-addrs.json";

    function deployPhase() external {
        string memory json = vm.readFile("test/vectors/bench-depth16.json");
        bytes32 root = vm.parseJsonBytes32(json, ".root");
        uint256 depth = vm.parseJsonUint(json, ".depth");
        (uint256 idxAction, bytes32 secretAction,) = leaf(json, 0);
        (uint256 idxNoop, bytes32 secretNoop,) = leaf(json, 1);

        vm.startBroadcast();
        EntryPoint entryPoint = new EntryPoint();
        QCAAccount4337 account =
            new QCAAccount4337{value: 10 ether}(IEntryPoint(address(entryPoint)), root, depth, MIN_AGE, TTL);
        entryPoint.depositTo{value: 1 ether}(address(account));

        account.commit(commitmentOf(account, ACTION_TARGET, ACTION_VALUE, "", idxAction, secretAction));
        account.commit(commitmentOf(account, address(account), 0, "", idxNoop, secretNoop));
        vm.stopBroadcast();

        string memory out = "addrs";
        vm.serializeAddress(out, "entryPoint", address(entryPoint));
        string memory ser = vm.serializeAddress(out, "account", address(account));
        vm.writeJson(ser, ADDR_FILE);
    }

    function revealPhase() external {
        string memory addrs = vm.readFile(ADDR_FILE);
        EntryPoint entryPoint = EntryPoint(payable(vm.parseJsonAddress(addrs, ".entryPoint")));
        QCAAccount4337 account = QCAAccount4337(payable(vm.parseJsonAddress(addrs, ".account")));

        string memory json = vm.readFile("test/vectors/bench-depth16.json");
        (uint256 idxAction, bytes32 secretAction, bytes32[] memory proofAction) = leaf(json, 0);
        (uint256 idxNoop, bytes32 secretNoop, bytes32[] memory proofNoop) = leaf(json, 1);

        vm.startBroadcast();
        entryPoint.handleOps(
            wrap(buildOp(entryPoint, account, ACTION_TARGET, ACTION_VALUE, "", idxAction, secretAction, proofAction)),
            payable(msg.sender)
        );
        entryPoint.handleOps(
            wrap(buildOp(entryPoint, account, address(account), 0, "", idxNoop, secretNoop, proofNoop)),
            payable(msg.sender)
        );
        vm.stopBroadcast();
    }

    // --- helpers ------------------------------------------------------------

    function wrap(PackedUserOperation memory op) internal pure returns (PackedUserOperation[] memory ops) {
        ops = new PackedUserOperation[](1);
        ops[0] = op;
    }

    function buildOp(
        EntryPoint entryPoint,
        QCAAccount4337 account,
        address target,
        uint256 value,
        bytes memory data,
        uint256 leafIndex,
        bytes32 secret,
        bytes32[] memory proof
    ) internal view returns (PackedUserOperation memory op) {
        op.sender = address(account);
        op.nonce = entryPoint.getNonce(address(account), 0);
        op.callData = abi.encodeCall(QCAAccount4337.execute, (target, value, data));
        op.accountGasLimits = bytes32((uint256(1_500_000) << 128) | uint256(1_000_000));
        op.preVerificationGas = 100_000;
        op.gasFees = bytes32((uint256(1 gwei) << 128) | uint256(1 gwei));
        op.signature = abi.encode(leafIndex, secret, proof);
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

    function commitmentOf(
        QCAAccount4337 account,
        address target,
        uint256 value,
        bytes memory data,
        uint256 index,
        bytes32 secret
    ) internal view returns (bytes32) {
        bytes32 actionHash = keccak256(abi.encode(TAG_ACTION, target, value, keccak256(data)));
        return keccak256(abi.encode(TAG_COMMIT, block.chainid, address(account), actionHash, index, secret));
    }
}
