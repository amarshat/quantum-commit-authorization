// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {EntryPoint} from "@account-abstraction/core/EntryPoint.sol";
import {IEntryPoint} from "@account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@account-abstraction/interfaces/PackedUserOperation.sol";
import {QCAAccount4337} from "../src/QCAAccount4337.sol";

/// @notice Receipt-level gas for the 4337 reveal path, measured like the base
///         benchmark: real handleOps transactions against anvil through a real
///         EntryPoint v0.8, so gasUsed includes intrinsic, calldata, EntryPoint
///         overhead, validation, and execution.
///
///         Per depth we measure three authorization-only reveals so the report
///         can separate what a reviewer must see separately:
///           - warmup: the account's FIRST op ever, which pays a one-time
///             EntryPoint nonce-slot initialization (~17k, cold SSTORE_SET vs
///             the 5k reset every later op pays);
///           - single: a steady-state op, one per bundle (the WORST case, since
///             a lone op carries the whole per-bundle fixed overhead);
///           - bundle2: two ops in one handleOps, so bundle2 - single is the
///             AMORTIZED marginal cost of an op inside a larger bundle.
///
///         Two phases with a real chain-clock advance between them (the reveal
///         validAfter gate is enforced against live time), driven by
///         bench/measure_4337.sh:
///           forge script ... --sig "deployPhase(uint256)" <depth> --broadcast --skip-simulation
///           cast rpc evm_increaseTime 10 ; cast rpc evm_mine
///           forge script ... --sig "revealPhase(uint256)" <depth> --broadcast --slow --skip-simulation
contract Bench4337Script is Script {
    bytes32 constant TAG_ACTION = keccak256("QCA/v1/action");
    bytes32 constant TAG_COMMIT = keccak256("QCA/v1/commit");

    uint256 constant MIN_AGE = 1; // seconds
    uint256 constant TTL = 100_000;
    uint256 constant MAX_FEE_CAP = 100 gwei;
    uint256 constant CALL_GAS_FLOOR = 200_000;
    uint256 constant MAX_PVG_CEIL = 200_000;

    function deployPhase(uint256 depth) external {
        string memory json = vm.readFile(vectorFile(depth));
        bytes32 root = vm.parseJsonBytes32(json, ".root");

        vm.startBroadcast();
        EntryPoint entryPoint = new EntryPoint();
        QCAAccount4337 account =
            new QCAAccount4337{value: 10 ether}(IEntryPoint(address(entryPoint)), root, depth, MIN_AGE, TTL);
        entryPoint.depositTo{value: 2 ether}(address(account));

        // Commit an authorization-only self-call for the first four leaves,
        // keyed by each leaf's real tree index (not the loop counter).
        for (uint256 i = 0; i < 4; i++) {
            (uint256 idx, bytes32 secret,) = leaf(json, i);
            account.commit(commitmentOf(account, address(account), 0, "", idx, secret));
        }
        vm.stopBroadcast();

        string memory o = "addrs";
        vm.serializeAddress(o, "entryPoint", address(entryPoint));
        string memory ser = vm.serializeAddress(o, "account", address(account));
        vm.writeJson(ser, addrFile(depth));
    }

    function revealPhase(uint256 depth) external {
        string memory addrs = vm.readFile(addrFile(depth));
        EntryPoint entryPoint = EntryPoint(payable(vm.parseJsonAddress(addrs, ".entryPoint")));
        QCAAccount4337 account = QCAAccount4337(payable(vm.parseJsonAddress(addrs, ".account")));
        string memory json = vm.readFile(vectorFile(depth));

        vm.startBroadcast();
        // tx 0: warmup (first op, nonce-slot init)
        entryPoint.handleOps(wrap(op(entryPoint, account, json, 0)), payable(msg.sender));
        // tx 1: steady single op
        entryPoint.handleOps(wrap(op(entryPoint, account, json, 1)), payable(msg.sender));
        // tx 2: bundle of two ops
        PackedUserOperation[] memory pair = new PackedUserOperation[](2);
        pair[0] = op(entryPoint, account, json, 2);
        pair[1] = op(entryPoint, account, json, 3);
        // Both were built before the bundle executes, so both read the same
        // account nonce; the second op in the bundle must use the next nonce.
        pair[1].nonce = pair[0].nonce + 1;
        entryPoint.handleOps(pair, payable(msg.sender));
        vm.stopBroadcast();
    }

    // --- helpers ------------------------------------------------------------

    function vectorFile(uint256 depth) internal pure returns (string memory) {
        return string.concat("test/vectors/bench-depth", vm.toString(depth), ".json");
    }

    function addrFile(uint256 depth) internal pure returns (string memory) {
        return string.concat("bench-4337-addrs-", vm.toString(depth), ".json");
    }

    function wrap(PackedUserOperation memory o) internal pure returns (PackedUserOperation[] memory ops) {
        ops = new PackedUserOperation[](1);
        ops[0] = o;
    }

    function op(EntryPoint entryPoint, QCAAccount4337 account, string memory json, uint256 i)
        internal
        view
        returns (PackedUserOperation memory o)
    {
        (uint256 leafIndex, bytes32 secret, bytes32[] memory proof) = leaf(json, i);
        o.sender = address(account);
        o.nonce = entryPoint.getNonce(address(account), 0);
        o.callData = abi.encodeCall(QCAAccount4337.execute, (address(account), 0, ""));
        o.accountGasLimits = bytes32((uint256(1_500_000) << 128) | uint256(1_000_000));
        o.preVerificationGas = 100_000;
        o.gasFees = bytes32((uint256(1 gwei) << 128) | uint256(1 gwei));
        o.signature = abi.encode(leafIndex, secret, proof, MAX_FEE_CAP, CALL_GAS_FLOOR, MAX_PVG_CEIL);
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
        return keccak256(
            abi.encode(
                TAG_COMMIT,
                block.chainid,
                address(account),
                actionHash,
                index,
                secret,
                MAX_FEE_CAP,
                CALL_GAS_FLOOR,
                MAX_PVG_CEIL
            )
        );
    }
}
