// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {TimeLockRevokeAccount} from "../src/TimeLockRevokeAccount.sol";
import {TestTree, Receiver} from "./CommitRevealAccount.t.sol";

/// Tests for the cancellability construction (internal/paper3-cancellation.md).
/// The five load-bearing PoCs: (1) a queued action does not execute during the
/// veto window; (2) the owner cancels within the window with an unused revoke
/// leaf; (3) the adversary cannot forge a revoke; (4) the adversary cannot
/// execute a revoked action; (5) after the window, anyone may execute.
contract TimeLockRevokeAccountTest is Test {
    using TestTree for bytes32[];

    bytes32 constant SEED = keccak256("timelock-seed");
    bytes32 constant TAG_ENQUEUE = keccak256("QCA/v3/enqueue");
    bytes32 constant TAG_COMMIT = keccak256("QCA/v1/commit");

    uint256 constant DEPTH = 4;
    uint256 constant MIN_AGE = 4;
    uint256 constant TTL = 256;
    uint256 constant DELTA = 8; // veto window

    TimeLockRevokeAccount account;
    Receiver receiver;
    bytes32[] leaves;
    bytes32 root;

    function setUp() public {
        leaves = TestTree.leaves(SEED, DEPTH);
        root = TestTree.rootOf(leaves);
        account = new TimeLockRevokeAccount{value: 10 ether}(root, DEPTH, MIN_AGE, TTL, DELTA);
        receiver = new Receiver();
        vm.roll(1000);
    }

    uint256 constant GAS = 100_000; // owner-committed execution budget

    // Compute the enqueue commitment binding action + designated revoke leaf + gas.
    function enqCommit(bytes32 aHash, bytes32 revokeLeaf, uint256 leafIndex, bytes32 secret, uint256 callGasLimit)
        internal
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                TAG_COMMIT, block.chainid, address(account), TAG_ENQUEUE, aHash, revokeLeaf, leafIndex, secret, callGasLimit
            )
        );
    }

    // Enqueue action on leaf `i`, designating leaf `j` as the revoke credential.
    function doEnqueue(address target, uint256 value, bytes memory data, uint256 i, uint256 j)
        internal
        returns (bytes32 queueId)
    {
        bytes32 aHash = TestTree.actionHash(target, value, data);
        bytes32 secret = TestTree.secretAt(SEED, i);
        bytes32 revokeLeaf = TestTree.leafHashAt(SEED, j);
        account.commitEnqueue(enqCommit(aHash, revokeLeaf, i, secret, GAS));
        vm.roll(block.number + MIN_AGE);
        bytes32[] memory proof = TestTree.proofFor(TestTree.leaves(SEED, DEPTH), i);
        account.enqueue(target, value, data, i, secret, revokeLeaf, GAS, proof);
        return TestTree.leafHashAt(SEED, i);
    }

    function doRevoke(bytes32 queueId, uint256 j) internal {
        bytes32 secret = TestTree.secretAt(SEED, j);
        bytes32[] memory proof = TestTree.proofFor(TestTree.leaves(SEED, DEPTH), j);
        account.revoke(queueId, j, secret, proof);
    }

    // (baseline) The happy path: enqueue, wait out the window, execute.
    function test_enqueueThenExecuteAfterWindow() public {
        bytes memory data = abi.encodeCall(Receiver.setX, (42));
        bytes32 queueId = doEnqueue(address(receiver), 0, data, 0, 1);

        vm.roll(block.number + DELTA);
        account.executeQueued(queueId, address(receiver), 0, data);
        assertEq(receiver.x(), 42, "action should execute after the veto window");
    }

    // (1) A queued action cannot execute during the veto window.
    function test_cannotExecuteDuringWindow() public {
        bytes memory data = abi.encodeCall(Receiver.setX, (42));
        bytes32 queueId = doEnqueue(address(receiver), 0, data, 0, 1);

        vm.roll(block.number + DELTA - 1); // still inside the window
        vm.expectRevert(TimeLockRevokeAccount.NotUnlocked.selector);
        account.executeQueued(queueId, address(receiver), 0, data);
        assertEq(receiver.x(), 0, "action must not execute before unlock");
    }

    // (2) The owner cancels within the window with the designated unused leaf.
    function test_ownerRevokesWithinWindow() public {
        bytes memory data = abi.encodeCall(Receiver.setX, (42));
        bytes32 queueId = doEnqueue(address(receiver), 0, data, 0, 1);

        vm.roll(block.number + 2); // inside the window
        doRevoke(queueId, 1);

        // The queue is dead: execute reverts even after the window would open.
        vm.roll(block.number + DELTA);
        vm.expectRevert(TimeLockRevokeAccount.NoSuchQueue.selector);
        account.executeQueued(queueId, address(receiver), 0, data);
        assertEq(receiver.x(), 0, "a revoked action must never execute");
    }

    // (3) The adversary cannot forge a revoke: a revoke leaf whose secret was
    // never revealed is unknown to the adversary, and any other unused leaf does
    // not match this queue's designated revokeLeaf.
    function test_adversaryCannotForgeRevoke() public {
        bytes memory data = abi.encodeCall(Receiver.setX, (42));
        bytes32 queueId = doEnqueue(address(receiver), 0, data, 0, 1);

        vm.roll(block.number + 2);
        // Adversary tries to revoke with a DIFFERENT unused leaf (index 2), which
        // it could reveal, but it does not match the designated revokeLeaf (1).
        address adversary = address(0xBAD);
        vm.prank(adversary);
        bytes32 wrongSecret = TestTree.secretAt(SEED, 2);
        bytes32[] memory wrongProof = TestTree.proofFor(TestTree.leaves(SEED, DEPTH), 2);
        vm.expectRevert(TimeLockRevokeAccount.WrongRevokeLeaf.selector);
        account.revoke(queueId, 2, wrongSecret, wrongProof);

        // And it cannot supply leaf 1's secret, which is not public. (We assert
        // the queue survives; the owner can still execute after the window.)
        vm.roll(block.number + DELTA);
        account.executeQueued(queueId, address(receiver), 0, data);
        assertEq(receiver.x(), 42, "queue survives a forged-revoke attempt");
    }

    // (4) The adversary cannot execute a revoked action even by resubmitting the
    // original enqueue calldata: the leaf is nullified and the queue is dead.
    function test_revokedActionCannotBeExecutedByAnyone() public {
        bytes memory data = abi.encodeCall(Receiver.setX, (42));
        bytes32 queueId = doEnqueue(address(receiver), 0, data, 0, 1);

        vm.roll(block.number + 2);
        doRevoke(queueId, 1);

        vm.roll(block.number + DELTA);
        address adversary = address(0xBAD);
        vm.prank(adversary);
        vm.expectRevert(TimeLockRevokeAccount.NoSuchQueue.selector);
        account.executeQueued(queueId, address(receiver), 0, data);
    }

    // (5) Execute is permissionless (liveness): anyone can execute after the
    // window, so the owner needs no trusted party to complete the action.
    function test_executeIsPermissionless() public {
        bytes memory data = abi.encodeCall(Receiver.setX, (7));
        bytes32 queueId = doEnqueue(address(receiver), 0, data, 0, 1);

        vm.roll(block.number + DELTA);
        vm.prank(address(0xCAFE)); // a random third party
        account.executeQueued(queueId, address(receiver), 0, data);
        assertEq(receiver.x(), 7, "any party may execute after the window");
    }

    // Copying the owner's revoke from the mempool is harmless: it triggers the
    // same cancellation. (Adversary front-runs the owner's revoke with the same
    // calldata; the outcome is identical.)
    function test_copiedRevokeIsHarmless() public {
        bytes memory data = abi.encodeCall(Receiver.setX, (42));
        bytes32 queueId = doEnqueue(address(receiver), 0, data, 0, 1);

        vm.roll(block.number + 2);
        // Adversary copies the owner's revoke calldata and front-runs it.
        address adversary = address(0xBAD);
        bytes32 secret = TestTree.secretAt(SEED, 1);
        bytes32[] memory proof = TestTree.proofFor(TestTree.leaves(SEED, DEPTH), 1);
        vm.prank(adversary);
        account.revoke(queueId, 1, secret, proof);

        // Same result the owner wanted: the action is cancelled.
        vm.roll(block.number + DELTA);
        vm.expectRevert(TimeLockRevokeAccount.NoSuchQueue.selector);
        account.executeQueued(queueId, address(receiver), 0, data);
    }

    // The enqueue is message-bound: an adversary who copies the enqueue secret
    // from the mempool cannot redirect it to a different action, because the
    // aged commitment binds the exact action (paper 1). A fresh commitment on a
    // different action is not aged, so the redirected enqueue reverts.
    function test_enqueueCannotBeRedirected() public {
        bytes memory data = abi.encodeCall(Receiver.setX, (42));
        bytes32 aHash = TestTree.actionHash(address(receiver), 0, data);
        bytes32 secret = TestTree.secretAt(SEED, 0);
        bytes32 revokeLeaf = TestTree.leafHashAt(SEED, 1);
        account.commitEnqueue(enqCommit(aHash, revokeLeaf, 0, secret, GAS));
        vm.roll(block.number + MIN_AGE);

        // Adversary tries to enqueue a DIFFERENT action with the same leaf/secret.
        bytes memory evil = abi.encodeCall(Receiver.setX, (999));
        bytes32[] memory proof = TestTree.proofFor(TestTree.leaves(SEED, DEPTH), 0);
        vm.prank(address(0xBAD));
        vm.expectRevert(TimeLockRevokeAccount.UnknownCommitment.selector);
        account.enqueue(address(receiver), 0, evil, 0, secret, revokeLeaf, GAS, proof);
    }

    // The window cannot be revoked after it closes (revoke is window-bound).
    function test_cannotRevokeAfterWindow() public {
        bytes memory data = abi.encodeCall(Receiver.setX, (42));
        bytes32 queueId = doEnqueue(address(receiver), 0, data, 0, 1);

        vm.roll(block.number + DELTA); // window closed
        vm.expectRevert(TimeLockRevokeAccount.WindowClosed.selector);
        doRevoke(queueId, 1);
    }

    // F1 regression: a permissionless executor who supplies too little OUTER gas
    // cannot burn the queue. The budget is the owner-committed q.callGasLimit, and
    // the pre-consume guard reverts the starved call before live=false, so the
    // queue survives and the owner (or anyone) can still execute properly.
    function test_starvedExecuteDoesNotBurnQueue() public {
        GasHungryTarget hungry = new GasHungryTarget();
        // Owner commits a generous budget for the heavy action.
        bytes memory data = abi.encodeCall(GasHungryTarget.work, ());
        bytes32 aHash = TestTree.actionHash(address(hungry), 0, data);
        bytes32 secret = TestTree.secretAt(SEED, 0);
        bytes32 revokeLeaf = TestTree.leafHashAt(SEED, 1);
        uint256 budget = 500_000;
        account.commitEnqueue(enqCommit(aHash, revokeLeaf, 0, secret, budget));
        vm.roll(block.number + MIN_AGE);
        bytes32[] memory proof = TestTree.proofFor(TestTree.leaves(SEED, DEPTH), 0);
        account.enqueue(address(hungry), 0, data, 0, secret, revokeLeaf, budget, proof);
        bytes32 queueId = TestTree.leafHashAt(SEED, 0);
        vm.roll(block.number + DELTA);

        // Griefer executes with a throttled OUTER gas limit (below the committed
        // budget + EIP-150 margin): must revert without consuming the queue.
        vm.prank(address(0xBAD));
        vm.expectRevert(TimeLockRevokeAccount.InsufficientGas.selector);
        account.executeQueued{gas: 200_000}(queueId, address(hungry), 0, data);
        assertEq(hungry.done(), false, "starved action must not have run");

        // The queue survived: an honest executor with enough gas completes it.
        account.executeQueued{gas: 3_000_000}(queueId, address(hungry), 0, data);
        assertEq(hungry.done(), true, "committed budget executes the action");
    }

    // F1 companion: the committed budget reaches the action regardless of who
    // submits, so a heavy action funded by the owner completes even when a third
    // party executes it.
    function test_committedBudgetExecutesForAnyCaller() public {
        GasHungryTarget hungry = new GasHungryTarget();
        bytes memory data = abi.encodeCall(GasHungryTarget.work, ());
        bytes32 aHash = TestTree.actionHash(address(hungry), 0, data);
        bytes32 secret = TestTree.secretAt(SEED, 0);
        bytes32 revokeLeaf = TestTree.leafHashAt(SEED, 1);
        uint256 budget = 500_000;
        account.commitEnqueue(enqCommit(aHash, revokeLeaf, 0, secret, budget));
        vm.roll(block.number + MIN_AGE);
        bytes32[] memory proof = TestTree.proofFor(TestTree.leaves(SEED, DEPTH), 0);
        account.enqueue(address(hungry), 0, data, 0, secret, revokeLeaf, budget, proof);
        bytes32 queueId = TestTree.leafHashAt(SEED, 0);
        vm.roll(block.number + DELTA);

        vm.prank(address(0xCAFE));
        account.executeQueued{gas: 3_000_000}(queueId, address(hungry), 0, data);
        assertEq(hungry.done(), true, "third party executes with the owner's committed budget");
    }
}

/// A target whose action needs a large, fixed amount of gas; below it, the call
/// OOG-reverts and `done` stays false. Models any real action heavier than a
/// bare transfer, the case the gas-budget binding (F1) exists for.
contract GasHungryTarget {
    bool public done;
    mapping(uint256 => uint256) private slots;

    function work() external {
        for (uint256 i = 0; i < 15; ++i) {
            slots[i] = i + 1; // ~15 fresh SSTOREs (~350k gas), fits a 500k budget
        }
        done = true;
    }
}
