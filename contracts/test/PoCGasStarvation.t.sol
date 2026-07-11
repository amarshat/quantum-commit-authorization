// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {CommitRevealAccount} from "../src/CommitRevealAccount.sol";
import {TestTree} from "./CommitRevealAccount.t.sol";

/// Target whose action needs a large, fixed amount of gas to finish. Below that
/// it OOG-reverts partway through and `done` stays false. This models any real
/// action heavier than a bare value transfer, which is the case the account
/// exists for.
contract GasHungry {
    bool public done;
    mapping(uint256 => uint256) public slots;

    function work() external {
        for (uint256 i = 0; i < 200; ++i) {
            slots[i] = i + 1; // ~200 fresh SSTOREs, over 4M gas
        }
        done = true;
    }
}

/// Regression test for finding 1 (gas-starvation leaf burn). Before the fix the
/// base account consumed the leaf and then swallowed a failed external call, so
/// anyone who copied a pending reveal's public calldata could front-run it under
/// a constrained outer gas limit, starving the action while still burning the
/// victim's leaf, against the victim's own aged commitment, with no fresh
/// commitment or censorship. The fix binds callGasLimit into the commitment and
/// checks, BEFORE consuming the leaf, that the committed budget can actually
/// reach the action under EIP-150; a starved copy now reverts and the leaf
/// survives. These tests pin both halves.
contract GasStarvationRegressionTest is Test {
    uint256 constant DEPTH = 3;
    uint256 constant MIN_AGE = 4;
    uint256 constant TTL = 64;
    bytes32 constant SEED = keccak256("test seed");
    // Committed execution budget, enough for GasHungry.work (~4.4M).
    uint256 constant CALL_GAS = 5_000_000;

    CommitRevealAccount account;
    GasHungry hungry;
    bytes32[] leaves;

    function setUp() public {
        leaves = TestTree.leaves(SEED, DEPTH);
        account = new CommitRevealAccount{value: 10 ether}(TestTree.rootOf(leaves), DEPTH, MIN_AGE, TTL);
        hungry = new GasHungry();
        vm.roll(100);
    }

    function _commitAgedReveal(uint256 leafIndex)
        internal
        returns (bytes memory revealCalldata, bytes32 leafHash)
    {
        bytes memory data = abi.encodeCall(GasHungry.work, ());
        bytes32 secret = TestTree.secretAt(SEED, leafIndex);
        bytes32[] memory proof = TestTree.proofFor(leaves, leafIndex);
        bytes32 c = TestTree.commitmentOf(
            address(account), TestTree.actionHash(address(hungry), 0, data), leafIndex, secret, CALL_GAS
        );
        account.commit(c);
        vm.roll(block.number + MIN_AGE);
        revealCalldata =
            abi.encodeCall(CommitRevealAccount.reveal, (address(hungry), 0, data, leafIndex, secret, CALL_GAS, proof));
        leafHash = TestTree.leafHashAt(SEED, leafIndex);
    }

    function test_starvedCopyRevertsAndLeafSurvives() public {
        (bytes memory revealCalldata, bytes32 leafHash) = _commitAgedReveal(5);

        // Attacker copies the now-public reveal calldata (committed callGasLimit
        // and all) and submits it with a starved outer gas limit. The committed
        // budget cannot be forwarded, so the pre-consume check reverts the whole
        // transaction before the leaf is touched.
        address attacker = makeAddr("attacker");
        vm.prank(attacker);
        (bool outerOk,) = address(account).call{gas: 500_000}(revealCalldata);

        assertFalse(outerOk, "starved reveal should revert, not succeed");
        assertFalse(hungry.done(), "action must not have run");
        assertFalse(account.isLeafUsed(leafHash), "leaf must survive a starved copy");
    }

    function test_honestRevealWithCommittedBudgetStillExecutes() public {
        (bytes memory revealCalldata, bytes32 leafHash) = _commitAgedReveal(6);

        // Same calldata, but forwarded with ample outer gas: the committed
        // budget reaches the action, which completes, and the leaf is consumed.
        (bool outerOk,) = address(account).call{gas: 8_000_000}(revealCalldata);

        assertTrue(outerOk, "honest reveal should succeed");
        assertTrue(hungry.done(), "action should have completed");
        assertTrue(account.isLeafUsed(leafHash), "leaf should be consumed on a real reveal");
    }
}
