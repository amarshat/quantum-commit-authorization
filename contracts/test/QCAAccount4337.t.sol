// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {EntryPoint} from "@account-abstraction/core/EntryPoint.sol";
import {IEntryPoint} from "@account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@account-abstraction/interfaces/PackedUserOperation.sol";
import {QCAAccount4337} from "../src/QCAAccount4337.sol";

contract Receiver {
    uint256 public x;
    uint256 public paid;

    function setX(uint256 v) external payable {
        x = v;
        paid += msg.value;
    }
}

/// Drives the commit-reveal account through a real EntryPoint v0.8: commit an
/// action, age it in wall-clock time, then authorize a reveal UserOp whose
/// signature carries the secret and Merkle proof and whose callData is the
/// action. No ECDSA anywhere in the account's authorization.
contract QCAAccount4337Test is Test {
    bytes32 constant TAG_ACTION = keccak256("QCA/v1/action");
    bytes32 constant TAG_COMMIT = keccak256("QCA/v1/commit");
    bytes32 constant TAG_BURN = keccak256("QCA/v1/burn");
    bytes32 constant TAG_LEAF = keccak256("QCA/v1/leaf");

    uint256 constant MIN_AGE = 60; // seconds
    uint256 constant TTL = 3600;
    uint256 constant MAX_FEE_CAP = 100 gwei; // committed fee ceiling
    uint256 constant CALL_GAS_FLOOR = 200_000; // committed call-gas floor

    EntryPoint entryPoint;
    QCAAccount4337 account;
    Receiver receiver;

    bytes32 root;
    uint256 leafIndex;
    bytes32 secret;
    bytes32[] proof;

    function setUp() public {
        string memory json = vm.readFile("test/vectors/bench-depth8.json");
        root = vm.parseJsonBytes32(json, ".root");
        leafIndex = vm.parseJsonUint(json, ".leaves[0].index");
        secret = vm.parseJsonBytes32(json, ".leaves[0].secret");
        proof = vm.parseJsonBytes32Array(json, ".leaves[0].proof");

        entryPoint = new EntryPoint();
        uint256 depth = vm.parseJsonUint(json, ".depth");
        account = new QCAAccount4337{value: 10 ether}(IEntryPoint(address(entryPoint)), root, depth, MIN_AGE, TTL);

        // Pre-fund the account's gas in the EntryPoint so missingAccountFunds
        // is zero and the run needs no ECDSA gas-payer beyond the beneficiary.
        entryPoint.depositTo{value: 1 ether}(address(account));

        receiver = new Receiver();
        vm.warp(1_000_000);
    }

    function actionHash(address target, uint256 value, bytes memory data) internal pure returns (bytes32) {
        return keccak256(abi.encode(TAG_ACTION, target, value, keccak256(data)));
    }

    function commitmentOf(address target, uint256 value, bytes memory data) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                TAG_COMMIT,
                block.chainid,
                address(account),
                actionHash(target, value, data),
                leafIndex,
                secret,
                MAX_FEE_CAP,
                CALL_GAS_FLOOR
            )
        );
    }

    /// Build a reveal op. `maxFee` and `callGasLimit` are the ACTUAL UserOp
    /// fields; the committed bounds are MAX_FEE_CAP / CALL_GAS_FLOOR. An honest
    /// op stays inside them; the adversary tests push past them.
    function buildOp(address target, uint256 value, bytes memory data, uint256 maxFee, uint256 callGasLimit)
        internal
        view
        returns (PackedUserOperation memory op)
    {
        op.sender = address(account);
        op.nonce = entryPoint.getNonce(address(account), 0);
        op.initCode = "";
        op.callData = abi.encodeCall(QCAAccount4337.execute, (target, value, data));
        op.accountGasLimits = bytes32((uint256(1_500_000) << 128) | callGasLimit);
        op.preVerificationGas = 100_000;
        op.gasFees = bytes32((uint256(1 gwei) << 128) | maxFee);
        op.paymasterAndData = "";
        op.signature = abi.encode(leafIndex, secret, proof, MAX_FEE_CAP, CALL_GAS_FLOOR);
    }

    function buildOp(address target, uint256 value, bytes memory data)
        internal
        view
        returns (PackedUserOperation memory op)
    {
        return buildOp(target, value, data, 1 gwei, 1_000_000);
    }

    function test_commitRevealExecutesThroughEntryPoint() public {
        bytes memory data = abi.encodeCall(Receiver.setX, (42));
        address target = address(receiver);
        uint256 value = 1 ether;

        account.commit(commitmentOf(target, value, data));
        vm.warp(block.timestamp + MIN_AGE + 1);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = buildOp(target, value, data);
        entryPoint.handleOps(ops, payable(address(0xB0B)));

        assertEq(receiver.x(), 42, "action did not execute");
        assertEq(receiver.paid(), 1 ether, "value not forwarded");
        assertTrue(account.usedLeaves(keccak256(abi.encode(TAG_LEAF, secret))), "leaf not nullified");
        assertEq(account.commitments(commitmentOf(target, value, data)), 0, "commitment not cleared");
    }

    function test_revealBeforeAgingIsRejected() public {
        bytes memory data = abi.encodeCall(Receiver.setX, (7));
        address target = address(receiver);
        account.commit(commitmentOf(target, 0, data));
        // Not aged: validAfter is in the future, EntryPoint must reject.
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = buildOp(target, 0, data);
        vm.expectRevert(); // FailedOp: AA22 expired or not due
        entryPoint.handleOps(ops, payable(address(0xB0B)));
        assertEq(receiver.x(), 0);
    }

    function test_bundlerCannotRetargetAction() public {
        // The binding result: a bundler who copies the revealed secret+proof
        // into a UserOp for a DIFFERENT action has no matching commitment, so
        // validation reverts. Only the committed action can execute.
        bytes memory committed = abi.encodeCall(Receiver.setX, (42));
        account.commit(commitmentOf(address(receiver), 0, committed));
        vm.warp(block.timestamp + MIN_AGE + 1);

        bytes memory swapped = abi.encodeCall(Receiver.setX, (999)); // attacker's action
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = buildOp(address(receiver), 0, swapped);
        vm.expectRevert(); // no commitment for the swapped action
        entryPoint.handleOps(ops, payable(address(0xB0B)));
        assertEq(receiver.x(), 0, "attacker action must not execute");
    }

    function test_bundlerCannotInflateFeeToDrainDeposit() public {
        // F1: a bundler replays the reveal with maxFeePerGas above the
        // committed cap to drain the account's deposit as fees. The committed
        // fee cap makes validation reject it.
        bytes memory data = abi.encodeCall(Receiver.setX, (42));
        account.commit(commitmentOf(address(receiver), 0, data));
        vm.warp(block.timestamp + MIN_AGE + 1);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = buildOp(address(receiver), 0, data, MAX_FEE_CAP + 1, 1_000_000);
        vm.expectRevert(); // FeeCapExceeded inside validation
        entryPoint.handleOps(ops, payable(address(0xB0B)));
        assertEq(receiver.x(), 0);
    }

    function test_bundlerCannotStarveCallGasToBurnLeaf() public {
        // F3: a bundler sets callGasLimit below the committed floor to starve
        // execute, consuming the leaf without running the action. The floor
        // makes validation reject it, so the leaf survives.
        bytes memory data = abi.encodeCall(Receiver.setX, (42));
        account.commit(commitmentOf(address(receiver), 0, data));
        vm.warp(block.timestamp + MIN_AGE + 1);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = buildOp(address(receiver), 0, data, 1 gwei, CALL_GAS_FLOOR - 1);
        vm.expectRevert(); // CallGasBelowFloor inside validation
        entryPoint.handleOps(ops, payable(address(0xB0B)));
        assertFalse(account.usedLeaves(keccak256(abi.encode(TAG_LEAF, secret))), "leaf must not be burned");
    }

    function test_rotateViaSelfActionCancelsOldTree() public {
        // F5: rotation is reachable as a committed self-action and switches the
        // root, the break-glass response. After rotating to a fresh root, a
        // reveal against the old tree no longer validates.
        bytes32 newRoot = keccak256("fresh tree");
        bytes memory rotateData = abi.encodeCall(QCAAccount4337.rotate, (newRoot, 8));
        account.commit(commitmentOf(address(account), 0, rotateData));
        vm.warp(block.timestamp + MIN_AGE + 1);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = buildOp(address(account), 0, rotateData);
        entryPoint.handleOps(ops, payable(address(0xB0B)));
        assertEq(account.root(), newRoot, "root did not rotate");
    }

    function test_leafCannotBeReused() public {
        bytes memory data = abi.encodeCall(Receiver.setX, (42));
        account.commit(commitmentOf(address(receiver), 0, data));
        vm.warp(block.timestamp + MIN_AGE + 1);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = buildOp(address(receiver), 0, data);
        entryPoint.handleOps(ops, payable(address(0xB0B)));

        // Re-commit the same action (fresh timestamp), age, and replay: the
        // leaf nullifier must block it.
        account.commit(commitmentOf(address(receiver), 0, data));
        vm.warp(block.timestamp + MIN_AGE + 1);
        PackedUserOperation[] memory ops2 = new PackedUserOperation[](1);
        ops2[0] = buildOp(address(receiver), 0, data);
        vm.expectRevert(); // LeafAlreadyUsed inside validation
        entryPoint.handleOps(ops2, payable(address(0xB0B)));
    }
}
