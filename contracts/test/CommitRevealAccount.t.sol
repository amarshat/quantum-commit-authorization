// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {CommitRevealAccount} from "../src/CommitRevealAccount.sol";

/// Mirrors the wallet-side key derivation from docs/SPEC.md so tests can
/// build real trees and proofs without external fixtures.
library TestTree {
    bytes32 internal constant TAG_SECRET = keccak256("QCA/v1/secret");
    bytes32 internal constant TAG_LEAF = keccak256("QCA/v1/leaf");
    bytes32 internal constant TAG_NODE = keccak256("QCA/v1/node");
    bytes32 internal constant TAG_ACTION = keccak256("QCA/v1/action");
    bytes32 internal constant TAG_COMMIT = keccak256("QCA/v1/commit");
    bytes32 internal constant TAG_BURN = keccak256("QCA/v1/burn");

    function secretAt(bytes32 seed, uint256 i) internal pure returns (bytes32) {
        return keccak256(abi.encode(TAG_SECRET, seed, i));
    }

    function leaves(bytes32 seed, uint256 depth) internal pure returns (bytes32[] memory out) {
        out = new bytes32[](1 << depth);
        for (uint256 i = 0; i < out.length; ++i) {
            out[i] = keccak256(abi.encode(TAG_LEAF, secretAt(seed, i)));
        }
    }

    function rootOf(bytes32[] memory level) internal pure returns (bytes32) {
        while (level.length > 1) {
            bytes32[] memory next = new bytes32[](level.length / 2);
            for (uint256 i = 0; i < next.length; ++i) {
                next[i] = keccak256(abi.encode(TAG_NODE, level[2 * i], level[2 * i + 1]));
            }
            level = next;
        }
        return level[0];
    }

    function proofFor(bytes32[] memory level, uint256 index) internal pure returns (bytes32[] memory proof) {
        uint256 depth = 0;
        for (uint256 n = level.length; n > 1; n >>= 1) depth++;
        proof = new bytes32[](depth);
        for (uint256 h = 0; h < depth; ++h) {
            proof[h] = level[index ^ 1];
            bytes32[] memory next = new bytes32[](level.length / 2);
            for (uint256 i = 0; i < next.length; ++i) {
                next[i] = keccak256(abi.encode(TAG_NODE, level[2 * i], level[2 * i + 1]));
            }
            level = next;
            index >>= 1;
        }
    }

    function actionHash(address target, uint256 value, bytes memory data) internal pure returns (bytes32) {
        return keccak256(abi.encode(TAG_ACTION, target, value, keccak256(data)));
    }

    function leafHashAt(bytes32 seed, uint256 index) internal pure returns (bytes32) {
        return keccak256(abi.encode(TAG_LEAF, secretAt(seed, index)));
    }

    function commitmentOf(address account, bytes32 aHash, uint256 leafIndex, bytes32 secret)
        internal
        view
        returns (bytes32)
    {
        return keccak256(abi.encode(TAG_COMMIT, block.chainid, account, aHash, leafIndex, secret));
    }

    function burnCommitmentOf(address account, uint256 leafIndex, bytes32 secret) internal view returns (bytes32) {
        return keccak256(abi.encode(TAG_COMMIT, block.chainid, account, TAG_BURN, leafIndex, secret));
    }
}

contract Receiver {
    uint256 public x;
    uint256 public paid;

    function setX(uint256 v) external payable {
        x = v;
        paid += msg.value;
    }

    function boom() external pure {
        revert("boom");
    }
}

contract CommitRevealAccountTest is Test {
    uint256 constant DEPTH = 3;
    uint256 constant MIN_AGE = 4;
    uint256 constant TTL = 64;
    bytes32 constant SEED = keccak256("test seed");

    CommitRevealAccount account;
    Receiver receiver;
    bytes32[] leaves;

    function setUp() public {
        leaves = TestTree.leaves(SEED, DEPTH);
        account = new CommitRevealAccount{value: 10 ether}(TestTree.rootOf(leaves), DEPTH, MIN_AGE, TTL);
        receiver = new Receiver();
        vm.roll(100);
    }

    // Helpers -----------------------------------------------------------

    function commitAction(address target, uint256 value, bytes memory data, uint256 leafIndex)
        internal
        returns (bytes32 c, bytes32 secret, bytes32[] memory proof)
    {
        secret = TestTree.secretAt(SEED, leafIndex);
        proof = TestTree.proofFor(leaves, leafIndex);
        c = TestTree.commitmentOf(address(account), TestTree.actionHash(target, value, data), leafIndex, secret);
        account.commit(c);
    }

    function commitBurn(uint256 leafIndex)
        internal
        returns (bytes32 c, bytes32 secret, bytes32[] memory proof)
    {
        secret = TestTree.secretAt(SEED, leafIndex);
        proof = TestTree.proofFor(leaves, leafIndex);
        c = TestTree.burnCommitmentOf(address(account), leafIndex, secret);
        account.commit(c);
    }

    function age() internal {
        vm.roll(block.number + MIN_AGE);
    }

    // Happy path --------------------------------------------------------

    function test_commitRevealExecutes() public {
        bytes memory data = abi.encodeCall(Receiver.setX, (42));
        (, bytes32 secret, bytes32[] memory proof) = commitAction(address(receiver), 1 ether, data, 5);
        age();

        (bool ok,) = account.reveal(address(receiver), 1 ether, data, 5, secret, proof);
        assertTrue(ok);
        assertEq(receiver.x(), 42);
        assertEq(receiver.paid(), 1 ether);
        assertTrue(account.isLeafUsed(TestTree.leafHashAt(SEED, 5)));
    }

    function testFuzz_anyLeafWorks(uint8 rawIndex) public {
        uint256 leafIndex = bound(rawIndex, 0, (1 << DEPTH) - 1);
        bytes memory data = abi.encodeCall(Receiver.setX, (7));
        (, bytes32 secret, bytes32[] memory proof) = commitAction(address(receiver), 0, data, leafIndex);
        age();
        (bool ok,) = account.reveal(address(receiver), 0, data, leafIndex, secret, proof);
        assertTrue(ok);
    }

    // Commitment lifecycle ----------------------------------------------

    function test_duplicateCommitReverts() public {
        (bytes32 c,,) = commitAction(address(receiver), 0, "", 0);
        vm.expectRevert(CommitRevealAccount.CommitmentExists.selector);
        account.commit(c);
    }

    function test_revealWithoutCommitReverts() public {
        bytes32 secret = TestTree.secretAt(SEED, 1);
        bytes32[] memory proof = TestTree.proofFor(leaves, 1);
        vm.expectRevert(CommitRevealAccount.UnknownCommitment.selector);
        account.reveal(address(receiver), 0, "", 1, secret, proof);
    }

    function test_sameBlockRevealReverts() public {
        (, bytes32 secret, bytes32[] memory proof) = commitAction(address(receiver), 0, "", 1);
        vm.expectRevert(CommitRevealAccount.CommitmentTooYoung.selector);
        account.reveal(address(receiver), 0, "", 1, secret, proof);
    }

    function test_underagedRevealReverts() public {
        (, bytes32 secret, bytes32[] memory proof) = commitAction(address(receiver), 0, "", 1);
        vm.roll(block.number + MIN_AGE - 1);
        vm.expectRevert(CommitRevealAccount.CommitmentTooYoung.selector);
        account.reveal(address(receiver), 0, "", 1, secret, proof);
    }

    function test_expiredRevealReverts() public {
        (, bytes32 secret, bytes32[] memory proof) = commitAction(address(receiver), 0, "", 1);
        vm.roll(block.number + TTL + 1);
        vm.expectRevert(CommitRevealAccount.CommitmentExpired.selector);
        account.reveal(address(receiver), 0, "", 1, secret, proof);
    }

    function test_revealAtExactTTLBoundaryWorks() public {
        bytes memory data = abi.encodeCall(Receiver.setX, (9));
        (, bytes32 secret, bytes32[] memory proof) = commitAction(address(receiver), 0, data, 1);
        vm.roll(block.number + TTL);
        (bool ok,) = account.reveal(address(receiver), 0, data, 1, secret, proof);
        assertTrue(ok);
    }

    // Replay and binding --------------------------------------------------

    function test_leafReplayReverts() public {
        bytes memory data = abi.encodeCall(Receiver.setX, (1));
        (, bytes32 secret, bytes32[] memory proof) = commitAction(address(receiver), 0, data, 2);
        age();
        account.reveal(address(receiver), 0, data, 2, secret, proof);

        // Second commitment for the same leaf, different action: nullifier
        // blocks it even though the commitment itself is valid.
        bytes memory data2 = abi.encodeCall(Receiver.setX, (2));
        account.commit(
            TestTree.commitmentOf(address(account), TestTree.actionHash(address(receiver), 0, data2), 2, secret)
        );
        age();
        vm.expectRevert(CommitRevealAccount.LeafAlreadyUsed.selector);
        account.reveal(address(receiver), 0, data2, 2, secret, proof);
    }

    function test_revealCannotRebindAction() public {
        bytes memory committed = abi.encodeCall(Receiver.setX, (1));
        (, bytes32 secret, bytes32[] memory proof) = commitAction(address(receiver), 0, committed, 3);
        age();

        // Attacker saw the reveal calldata and tries the same secret and
        // proof with a different action. The recomputed commitment does not
        // exist.
        bytes memory hijacked = abi.encodeCall(Receiver.setX, (999));
        vm.expectRevert(CommitRevealAccount.UnknownCommitment.selector);
        account.reveal(address(receiver), 0, hijacked, 3, secret, proof);
    }

    function test_wrongSecretFailsMembership() public {
        (,, bytes32[] memory proof) = commitAction(address(receiver), 0, "", 4);
        age();
        vm.expectRevert(CommitRevealAccount.InvalidProof.selector);
        account.reveal(address(receiver), 0, "", 4, keccak256("wrong"), proof);
    }

    function test_wrongProofLengthReverts() public {
        (, bytes32 secret,) = commitAction(address(receiver), 0, "", 4);
        age();
        bytes32[] memory shortProof = new bytes32[](DEPTH - 1);
        vm.expectRevert(CommitRevealAccount.InvalidProofLength.selector);
        account.reveal(address(receiver), 0, "", 4, secret, shortProof);
    }

    function test_outOfRangeLeafIndexReverts() public {
        bytes32[] memory proof = new bytes32[](DEPTH);
        vm.expectRevert(CommitRevealAccount.LeafIndexOutOfRange.selector);
        account.reveal(address(receiver), 0, "", 1 << DEPTH, bytes32(0), proof);
    }

    // Failure semantics ----------------------------------------------------

    function test_failedActionStillConsumesLeaf() public {
        bytes memory data = abi.encodeCall(Receiver.boom, ());
        (bytes32 c, bytes32 secret, bytes32[] memory proof) = commitAction(address(receiver), 0, data, 6);
        age();

        (bool ok,) = account.reveal(address(receiver), 0, data, 6, secret, proof);
        assertFalse(ok);
        // The secret went public in calldata; the leaf must be burned even
        // though the action reverted.
        assertTrue(account.isLeafUsed(TestTree.leafHashAt(SEED, 6)));
        assertEq(account.commitments(c), 0);
    }

    // Front-running race ---------------------------------------------------

    function test_extractedSecretLosesTheRace() public {
        bytes memory data = abi.encodeCall(Receiver.setX, (42));
        (, bytes32 secret, bytes32[] memory proof) = commitAction(address(receiver), 0, data, 7);
        age();

        // Victim's reveal is now pending in the mempool. Attacker extracts
        // the secret and commits to draining to their own address.
        address attacker = makeAddr("attacker");
        bytes32 theftHash = TestTree.actionHash(attacker, 5 ether, "");
        vm.prank(attacker);
        account.commit(TestTree.commitmentOf(address(account), theftHash, 7, secret));

        // Attacker's commitment must age minCommitAge blocks. The victim's
        // aged reveal lands first and consumes the leaf.
        (bool ok,) = account.reveal(address(receiver), 0, data, 7, secret, proof);
        assertTrue(ok);

        age();
        vm.prank(attacker);
        vm.expectRevert(CommitRevealAccount.LeafAlreadyUsed.selector);
        account.reveal(attacker, 5 ether, "", 7, secret, proof);
    }

    // Rotation ---------------------------------------------------------------

    function test_rotateOnlyViaRevealedAction() public {
        vm.expectRevert(CommitRevealAccount.NotSelf.selector);
        account.rotate(bytes32(uint256(1)), DEPTH);
    }

    bytes32 constant NEW_SEED = keccak256("rotated seed");

    function rotateTo(bytes32 seed) internal returns (bytes32[] memory newLeaves) {
        newLeaves = TestTree.leaves(seed, DEPTH);
        bytes memory data = abi.encodeCall(CommitRevealAccount.rotate, (TestTree.rootOf(newLeaves), DEPTH));
        (, bytes32 secret, bytes32[] memory proof) = commitAction(address(account), 0, data, 0);
        age();
        (bool ok,) = account.reveal(address(account), 0, data, 0, secret, proof);
        assertTrue(ok);
        assertEq(account.root(), TestTree.rootOf(newLeaves));
    }

    function test_rotationCancelsOldTree() public {
        rotateTo(NEW_SEED);

        // A commitment under the old tree can no longer prove membership.
        (, bytes32 oldSecret, bytes32[] memory oldProof) = commitAction(address(receiver), 0, "", 1);
        age();
        vm.expectRevert(CommitRevealAccount.InvalidProof.selector);
        account.reveal(address(receiver), 0, "", 1, oldSecret, oldProof);
    }

    function test_rotationGivesFreshNullifierSpace() public {
        // Consume index 0 in the old tree via the rotate action itself, then
        // the new tree's index 0 (a different secret, different leaf hash)
        // must still be usable. This is the property the old index-keyed
        // nullifier broke.
        bytes32[] memory newLeaves = rotateTo(NEW_SEED);
        assertTrue(account.isLeafUsed(TestTree.leafHashAt(SEED, 0)));
        assertFalse(account.isLeafUsed(TestTree.leafHashAt(NEW_SEED, 0)));

        bytes memory data = abi.encodeCall(Receiver.setX, (77));
        bytes32 newSecret = TestTree.secretAt(NEW_SEED, 0);
        bytes32[] memory newProof = TestTree.proofFor(newLeaves, 0);
        account.commit(
            TestTree.commitmentOf(address(account), TestTree.actionHash(address(receiver), 0, data), 0, newSecret)
        );
        age();
        (bool ok,) = account.reveal(address(receiver), 0, data, 0, newSecret, newProof);
        assertTrue(ok);
        assertEq(receiver.x(), 77);
    }

    // Burn (defensive nullify) ------------------------------------------------

    function test_burnNullifiesLeafWithoutAction() public {
        (, bytes32 secret, bytes32[] memory proof) = commitBurn(3);
        assertFalse(account.isLeafUsed(TestTree.leafHashAt(SEED, 3)));
        age();
        account.burn(3, secret, proof);
        assertTrue(account.isLeafUsed(TestTree.leafHashAt(SEED, 3)));
    }

    function test_burnedLeafCannotBeRevealed() public {
        // Models the reorg/expiry case: the secret leaked, the holder burns
        // the leaf, and no later commit-reveal on it can execute.
        bytes memory data = abi.encodeCall(Receiver.setX, (1));
        (, bytes32 secret, bytes32[] memory proof) = commitBurn(4);
        age();
        account.burn(4, secret, proof);
        // A subsequent action commitment on the same leaf can still be made
        // and aged, but the reveal fails because the leaf is nullified.
        account.commit(TestTree.commitmentOf(address(account), TestTree.actionHash(address(receiver), 0, data), 4, secret));
        age();
        vm.expectRevert(CommitRevealAccount.LeafAlreadyUsed.selector);
        account.reveal(address(receiver), 0, data, 4, secret, proof);
    }

    function test_burnWithoutCommitmentReverts() public {
        // The core of the burn-griefing fix: a burn with no aged commitment
        // (the shape an attacker copies out of a pending reveal) is rejected.
        bytes32 secret = TestTree.secretAt(SEED, 3);
        bytes32[] memory proof = TestTree.proofFor(leaves, 3);
        vm.expectRevert(CommitRevealAccount.UnknownCommitment.selector);
        account.burn(3, secret, proof);
    }

    function test_burnTooYoungReverts() public {
        (, bytes32 secret, bytes32[] memory proof) = commitBurn(3);
        vm.roll(block.number + MIN_AGE - 1);
        vm.expectRevert(CommitRevealAccount.CommitmentTooYoung.selector);
        account.burn(3, secret, proof);
    }

    function test_burnExpiredReverts() public {
        (, bytes32 secret, bytes32[] memory proof) = commitBurn(3);
        vm.roll(block.number + TTL + 1);
        vm.expectRevert(CommitRevealAccount.CommitmentExpired.selector);
        account.burn(3, secret, proof);
    }

    function test_revealCommitmentCannotBurn() public {
        // Domain separation: a commitment made for an action cannot be opened
        // as a burn, and vice versa.
        bytes memory data = abi.encodeCall(Receiver.setX, (1));
        (, bytes32 secret, bytes32[] memory proof) = commitAction(address(receiver), 0, data, 3);
        age();
        vm.expectRevert(CommitRevealAccount.UnknownCommitment.selector);
        account.burn(3, secret, proof);
    }

    function test_burnRejectsBadProof() public {
        bytes32[] memory proof = TestTree.proofFor(leaves, 2);
        vm.expectRevert(CommitRevealAccount.InvalidProof.selector);
        account.burn(2, keccak256("wrong"), proof);
    }

    function test_doubleBurnReverts() public {
        (, bytes32 secret, bytes32[] memory proof) = commitBurn(2);
        age();
        account.burn(2, secret, proof);
        // A second burn needs a second commitment; even with one, the leaf is
        // already nullified.
        (, bytes32 secret2, bytes32[] memory proof2) = commitBurn(2);
        age();
        vm.expectRevert(CommitRevealAccount.LeafAlreadyUsed.selector);
        account.burn(2, secret2, proof2);
    }

    // Prune ---------------------------------------------------------------

    function test_pruneLiveCommitmentReverts() public {
        (bytes32 c,,) = commitAction(address(receiver), 0, "", 1);
        vm.expectRevert(CommitRevealAccount.CommitmentLive.selector);
        account.prune(c);
    }

    function test_pruneExpiredCommitment() public {
        (bytes32 c,,) = commitAction(address(receiver), 0, "", 1);
        vm.roll(block.number + TTL + 1);
        account.prune(c);
        assertEq(account.commitments(c), 0);
    }

    // Constructor guards ----------------------------------------------------

    function test_constructorRejectsBadParams() public {
        vm.expectRevert(CommitRevealAccount.InvalidWindow.selector);
        new CommitRevealAccount(bytes32(0), DEPTH, 0, TTL);
        vm.expectRevert(CommitRevealAccount.InvalidWindow.selector);
        new CommitRevealAccount(bytes32(0), DEPTH, MIN_AGE, MIN_AGE);
        vm.expectRevert(CommitRevealAccount.InvalidDepth.selector);
        new CommitRevealAccount(bytes32(0), 0, MIN_AGE, TTL);
        vm.expectRevert(CommitRevealAccount.InvalidDepth.selector);
        new CommitRevealAccount(bytes32(0), 33, MIN_AGE, TTL);
    }
}
