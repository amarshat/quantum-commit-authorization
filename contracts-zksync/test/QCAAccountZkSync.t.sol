// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Transaction} from
    "@matterlabs/zksync-contracts/contracts/system-contracts/libraries/TransactionHelper.sol";
import {
    ACCOUNT_VALIDATION_SUCCESS_MAGIC
} from "@matterlabs/zksync-contracts/contracts/system-contracts/interfaces/IAccount.sol";
import {BOOTLOADER_FORMAL_ADDRESS} from
    "@matterlabs/zksync-contracts/contracts/system-contracts/Constants.sol";
import {QCAAccountZkSync} from "../src/QCAAccountZkSync.sol";

contract Receiver {
    uint256 public x;

    function setX(uint256 v) external payable {
        x = v;
    }
}

/// Drives the zkSync native-AA account through the bootloader-facing entry
/// points (validateTransaction then executeTransaction) with a crafted
/// type-0x71 Transaction, using a small depth-2 tree built in-test.
contract QCAAccountZkSyncTest is Test {
    bytes32 constant TAG_SECRET = keccak256("QCA/v1/secret");
    bytes32 constant TAG_LEAF = keccak256("QCA/v1/leaf");
    bytes32 constant TAG_NODE = keccak256("QCA/v1/node");
    bytes32 constant TAG_ACTION = keccak256("QCA/v1/action");
    bytes32 constant TAG_COMMIT = keccak256("QCA/v1/commit");
    bytes32 constant TAG_ENV_ZKSYNC = keccak256("QCA/v1/env/zksync");

    uint256 constant DEPTH = 2;
    uint256 constant MIN_AGE = 60;
    uint256 constant TTL = 3600;
    uint256 constant MAX_FEE_CAP = 100 gwei;
    uint256 constant MAX_GAS_CEIL = 2_000_000;
    uint256 constant MAX_PUBDATA_CEIL = 50_000;
    uint256 constant CALL_GAS_LIMIT = 200_000;
    bytes32 constant SEED = keccak256("zksync test seed");

    QCAAccountZkSync account;
    Receiver receiver;
    bytes32[] leaves;

    function secretAt(uint256 i) internal pure returns (bytes32) {
        return keccak256(abi.encode(TAG_SECRET, SEED, i));
    }

    function leafAt(uint256 i) internal pure returns (bytes32) {
        return keccak256(abi.encode(TAG_LEAF, secretAt(i)));
    }

    function setUp() public {
        leaves = new bytes32[](4);
        for (uint256 i = 0; i < 4; i++) {
            leaves[i] = leafAt(i);
        }
        bytes32 n0 = keccak256(abi.encode(TAG_NODE, leaves[0], leaves[1]));
        bytes32 n1 = keccak256(abi.encode(TAG_NODE, leaves[2], leaves[3]));
        bytes32 root = keccak256(abi.encode(TAG_NODE, n0, n1));

        account = new QCAAccountZkSync{value: 10 ether}(root, DEPTH, MIN_AGE, TTL);
        receiver = new Receiver();
        vm.warp(1_000_000);
    }

    function proofFor(uint256 index) internal view returns (bytes32[] memory proof) {
        proof = new bytes32[](2);
        proof[0] = leaves[index ^ 1];
        bytes32 n0 = keccak256(abi.encode(TAG_NODE, leaves[0], leaves[1]));
        bytes32 n1 = keccak256(abi.encode(TAG_NODE, leaves[2], leaves[3]));
        proof[1] = index < 2 ? n1 : n0;
    }

    function commitmentOf(address target, uint256 value, bytes memory data, uint256 index)
        internal
        view
        returns (bytes32)
    {
        bytes32 actionHash = keccak256(abi.encode(TAG_ACTION, target, value, keccak256(data)));
        return keccak256(
            abi.encode(
                TAG_COMMIT,
                TAG_ENV_ZKSYNC,
                block.chainid,
                address(account),
                actionHash,
                index,
                secretAt(index),
                MAX_FEE_CAP,
                MAX_GAS_CEIL,
                MAX_PUBDATA_CEIL,
                CALL_GAS_LIMIT
            )
        );
    }

    function buildTx(address target, uint256 value, bytes memory data, uint256 index)
        internal
        view
        returns (Transaction memory t)
    {
        t.txType = 0x71;
        t.from = uint256(uint160(address(account)));
        t.to = uint256(uint160(target));
        t.gasLimit = 1_000_000;
        t.gasPerPubdataByteLimit = 50000;
        t.maxFeePerGas = 1 gwei;
        t.maxPriorityFeePerGas = 1 gwei;
        t.nonce = 0;
        t.value = value;
        t.data = data;
        t.signature =
            abi.encode(index, secretAt(index), proofFor(index), MAX_FEE_CAP, MAX_GAS_CEIL, MAX_PUBDATA_CEIL, CALL_GAS_LIMIT);
    }

    // The execute path has no system call, so it is fully exercisable in
    // forge-test. The full validate path (which increments the nonce through
    // the NonceHolder system contract) is exercised on anvil-zksync / testnet,
    // not here; foundry-zksync's test VM does not run that system call.

    function test_executeRunsAndNullifies() public {
        bytes memory data = abi.encodeCall(Receiver.setX, (42));
        address target = address(receiver);
        account.commit(commitmentOf(target, 0, data, 1));
        vm.warp(block.timestamp + MIN_AGE + 1);

        Transaction memory t = buildTx(target, 0, data, 1);
        vm.prank(BOOTLOADER_FORMAL_ADDRESS);
        account.executeTransaction(keccak256("h"), keccak256("h"), t);

        assertEq(receiver.x(), 42, "action did not execute");
        assertTrue(account.usedLeaves(leafAt(1)), "leaf not nullified");
    }

    function test_tooYoungRevertsWithoutBurningLeaf() public {
        bytes memory data = abi.encodeCall(Receiver.setX, (7));
        address target = address(receiver);
        account.commit(commitmentOf(target, 0, data, 1));
        // Not aged: execute must revert and, crucially, NOT consume the leaf
        // (nullification is strictly after the aging check).
        Transaction memory t = buildTx(target, 0, data, 1);
        vm.prank(BOOTLOADER_FORMAL_ADDRESS);
        vm.expectRevert(QCAAccountZkSync.CommitmentTooYoung.selector);
        account.executeTransaction(keccak256("h"), keccak256("h"), t);

        assertFalse(account.usedLeaves(leafAt(1)), "premature reveal must not burn the leaf");
    }

    function test_feeCapBindingRejectsInflatedFee() public {
        bytes memory data = abi.encodeCall(Receiver.setX, (1));
        address target = address(receiver);
        account.commit(commitmentOf(target, 0, data, 1));
        vm.warp(block.timestamp + MIN_AGE + 1);

        Transaction memory t = buildTx(target, 0, data, 1);
        t.maxFeePerGas = MAX_FEE_CAP + 1; // sequencer inflates the fee
        vm.prank(BOOTLOADER_FORMAL_ADDRESS);
        vm.expectRevert(QCAAccountZkSync.FeeCapExceeded.selector);
        account.validateTransaction(keccak256("h"), keccak256("h"), t);
    }

    function test_gasLimitCeilingRejectsInflation() public {
        // Bug 2 (over-charge): the sequencer inflates the whole-tx gasLimit to
        // bill the account for gas it never needed. Bound above, not just below.
        bytes memory data = abi.encodeCall(Receiver.setX, (1));
        address target = address(receiver);
        account.commit(commitmentOf(target, 0, data, 1));
        vm.warp(block.timestamp + MIN_AGE + 1);

        Transaction memory t = buildTx(target, 0, data, 1);
        t.gasLimit = MAX_GAS_CEIL + 1; // sequencer inflates the gas quantity
        vm.prank(BOOTLOADER_FORMAL_ADDRESS);
        vm.expectRevert(QCAAccountZkSync.GasLimitAboveCeiling.selector);
        account.validateTransaction(keccak256("h"), keccak256("h"), t);
    }

    function test_pubdataCeilingRejectsInflation() public {
        // Bug 2 (over-charge, pubdata axis): the sequencer inflates
        // gasPerPubdataByteLimit so the account pays more per pubdata byte. The
        // fee cap bounds price per gas, not this rate, so it needs its own cap.
        bytes memory data = abi.encodeCall(Receiver.setX, (1));
        address target = address(receiver);
        account.commit(commitmentOf(target, 0, data, 1));
        vm.warp(block.timestamp + MIN_AGE + 1);

        Transaction memory t = buildTx(target, 0, data, 1);
        t.gasPerPubdataByteLimit = MAX_PUBDATA_CEIL + 1;
        vm.prank(BOOTLOADER_FORMAL_ADDRESS);
        vm.expectRevert(QCAAccountZkSync.PubdataAboveCeiling.selector);
        account.validateTransaction(keccak256("h"), keccak256("h"), t);
    }

    function test_paymasterRejected() public {
        // Bug 1 (ERC20 seizure): an unbound paymaster lets the bootloader's
        // prepareForPaymaster -> processPaymasterInput grant an attacker-chosen
        // ERC20 allowance from the account. This account is never sponsored, so
        // validation rejects any nonzero paymaster before it can ever run.
        bytes memory data = abi.encodeCall(Receiver.setX, (1));
        address target = address(receiver);
        account.commit(commitmentOf(target, 0, data, 1));
        vm.warp(block.timestamp + MIN_AGE + 1);

        Transaction memory t = buildTx(target, 0, data, 1);
        t.paymaster = uint256(uint160(address(0xBEEF))); // attacker paymaster
        vm.prank(BOOTLOADER_FORMAL_ADDRESS);
        vm.expectRevert(QCAAccountZkSync.PaymasterNotAllowed.selector);
        account.validateTransaction(keccak256("h"), keccak256("h"), t);
    }

    function test_factoryDepsRejected() public {
        // Bug 2 (pubdata via published bytecode): factoryDeps makes the account
        // pay pubdata for bytecode it never asked to deploy. Rejected outright.
        bytes memory data = abi.encodeCall(Receiver.setX, (1));
        address target = address(receiver);
        account.commit(commitmentOf(target, 0, data, 1));
        vm.warp(block.timestamp + MIN_AGE + 1);

        Transaction memory t = buildTx(target, 0, data, 1);
        t.factoryDeps = new bytes32[](1);
        t.factoryDeps[0] = keccak256("junk bytecode hash");
        vm.prank(BOOTLOADER_FORMAL_ADDRESS);
        vm.expectRevert(QCAAccountZkSync.FactoryDepsNotAllowed.selector);
        account.validateTransaction(keccak256("h"), keccak256("h"), t);
    }

    function test_starvedCallDoesNotBurnLeaf() public {
        // Bug 3 (forced leaf burn): if the committed inner-call budget cannot be
        // satisfied from the gas actually available in execute, the guard must
        // revert BEFORE the nullifier write, leaving the leaf live. A sequencer
        // that starves the outer gas therefore cannot burn the leaf with no
        // action (the base-scheme F-2026-02 property, ported to EraVM).
        //
        // Exercised by committing a callGasLimit larger than any gasleft the VM
        // can offer execute, so the guard `gasleft() < callGasLimit + ...` trips
        // deterministically regardless of EraVM's erg magnitudes. (EraVM does
        // not honor an EVM-style {gas:} cap on a cheatcode-driven call, so we
        // drive the shortfall through the committed budget instead.)
        uint256 hugeCGL = uint256(1) << 60;
        bytes memory data = abi.encodeCall(Receiver.setX, (5));
        address target = address(receiver);

        bytes32 actionHash = keccak256(abi.encode(TAG_ACTION, target, uint256(0), keccak256(data)));
        bytes32 c = keccak256(
            abi.encode(
                TAG_COMMIT,
                TAG_ENV_ZKSYNC,
                block.chainid,
                address(account),
                actionHash,
                uint256(1),
                secretAt(1),
                MAX_FEE_CAP,
                MAX_GAS_CEIL,
                MAX_PUBDATA_CEIL,
                hugeCGL
            )
        );
        account.commit(c);
        vm.warp(block.timestamp + MIN_AGE + 1);

        Transaction memory t = buildTx(target, 0, data, 1);
        t.signature = abi.encode(uint256(1), secretAt(1), proofFor(1), MAX_FEE_CAP, MAX_GAS_CEIL, MAX_PUBDATA_CEIL, hugeCGL);
        vm.prank(BOOTLOADER_FORMAL_ADDRESS);
        vm.expectRevert(QCAAccountZkSync.InsufficientGas.selector);
        account.executeTransaction(keccak256("h"), keccak256("h"), t);

        assertFalse(account.usedLeaves(leafAt(1)), "starved copy must not burn the leaf");
        assertEq(receiver.x(), 0, "action must not have run");
    }

    function test_unknownActionRejectedInExecute() public {
        // A bundler/sequencer that reuses the secret for a different action has
        // no matching commitment: execute reverts, leaf survives.
        bytes memory committed = abi.encodeCall(Receiver.setX, (42));
        account.commit(commitmentOf(address(receiver), 0, committed, 1));
        vm.warp(block.timestamp + MIN_AGE + 1);

        bytes memory swapped = abi.encodeCall(Receiver.setX, (999));
        Transaction memory t = buildTx(address(receiver), 0, swapped, 1);
        vm.prank(BOOTLOADER_FORMAL_ADDRESS);
        vm.expectRevert(QCAAccountZkSync.UnknownCommitment.selector);
        account.executeTransaction(keccak256("h"), keccak256("h"), t);
        assertEq(receiver.x(), 0);
    }
}
