// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {QCAAccount4337Base, Receiver} from "./QCAAccount4337.t.sol";
import {IEntryPoint} from "@account-abstraction/interfaces/IEntryPoint.sol";
import {IPaymaster} from "@account-abstraction/interfaces/IPaymaster.sol";
import {PackedUserOperation} from "@account-abstraction/interfaces/PackedUserOperation.sol";

/// A bundler-chosen paymaster that sponsors anything and then reverts in
/// postOp. A non-empty context makes the EntryPoint call postOp; its revert
/// rolls back the executed action while the account's nullifier survives,
/// which was F10.
contract HostilePaymaster is IPaymaster {
    function validatePaymasterUserOp(PackedUserOperation calldata, bytes32, uint256)
        external
        pure
        returns (bytes memory, uint256)
    {
        return ("x", 0);
    }

    function postOp(PostOpMode, bytes calldata, uint256, uint256) external pure {
        revert("postOp");
    }
}

/// The binding surface of the 4337 account, measured rather than listed.
///
/// Every input the bundler controls is one test below: each field of
/// PackedUserOperation (EntryPoint v0.8), each subfield the EntryPoint unpacks
/// from a packed field (UserOperationLib.unpack*), and the beneficiary argument
/// of handleOps. binding/enumerate.py derives that list from the pinned sources
/// and fails if a test is missing, so the list is not hand-written.
///
/// Each test takes an honest reveal, moves one input to the most adversarial
/// value we can construct, and checks one of two outcomes:
///   rejected  the bundle reverts, the leaf survives and the action does not run;
///   bound     the committed action runs unchanged, carrying its committed
///             value; the account's ETH balance falls by exactly that value,
///             so nothing is moved into the deposit; and the deposit's loss is
///             no more than the worst case at the committed ceilings: every
///             committed bound at its limit and every unbound input honest.
/// The action carries value so that a failed transfer shows up: F8 moved the
/// balance into the deposit, the 5 ETH transfer failed and the leaf burned,
/// which a value-free action and a combined deposit-plus-balance metric hid.
/// An input whose adversarial value is accepted and raises the loss above that
/// worst case is unbound, which is what F1 (preVerificationGas) was and what
/// F7 (callGasLimit with no ceiling) was until the fix.
contract BindingSurface4337Test is QCAAccount4337Base {
    uint256 constant HONEST_VGL = 1_500_000;
    uint256 constant HUGE = 25_000_000;
    // EntryPoint v0.8 charges no unused-gas penalty within 40,000 of the limit.
    uint256 constant CALL_GAS_SLACK = 40_000;

    uint256 constant VALUE = 5 ether;

    bytes data42;

    function setUp() public override {
        super.setUp();
        data42 = abi.encodeCall(Receiver.setX, (42));
        account.commit(commitmentOf(address(receiver), VALUE, data42));
        vm.warp(block.timestamp + MIN_AGE + 1);
    }

    function honest() internal view returns (PackedUserOperation memory op) {
        op = buildOp(address(receiver), VALUE, data42, 1 gwei, CALL_GAS_FLOOR);
    }

    /// Every committed bound at its limit, every unbound input honest.
    function worstAtCeilings() internal view returns (PackedUserOperation memory op) {
        op = honest();
        op.gasFees = bytes32((MAX_FEE_CAP << 128) | MAX_FEE_CAP);
        op.accountGasLimits = bytes32((HONEST_VGL << 128) | (CALL_GAS_FLOOR + CALL_GAS_SLACK));
        op.preVerificationGas = MAX_PVG_CEIL;
    }

    /// Returns whether the bundle went through, the deposit's loss, and the
    /// balance's loss (which for an included op must equal VALUE exactly).
    function run(PackedUserOperation memory op, address payable beneficiary)
        internal
        returns (bool included, uint256 loss, uint256 spent)
    {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        uint256 deposit = entryPoint.balanceOf(address(account));
        uint256 balance = address(account).balance;
        try entryPoint.handleOps{gas: 30_000_000}(ops, beneficiary) {
            included = true;
            loss = deposit - entryPoint.balanceOf(address(account));
            spent = balance - address(account).balance;
        } catch {}
    }

    function bound() internal returns (uint256 loss) {
        uint256 snap = vm.snapshotState();
        bool ok;
        (ok, loss,) = run(worstAtCeilings(), payable(address(0xB0B)));
        require(ok, "worst case at the ceilings must be valid");
        vm.revertToState(snap);
    }

    function leafUsed() internal view returns (bool) {
        return account.usedLeaves(keccak256(abi.encode(TAG_LEAF, secret)));
    }

    function expectRejected(PackedUserOperation memory op) internal {
        expectRejected(op, payable(address(0xB0B)));
    }

    function expectRejected(PackedUserOperation memory op, address payable beneficiary) internal {
        (bool included,,) = run(op, beneficiary);
        assertFalse(included, "adversarial value accepted");
        assertFalse(leafUsed(), "leaf burned");
        assertEq(receiver.x(), 0, "action ran");
    }

    function expectBound(PackedUserOperation memory op) internal {
        expectBound(op, payable(address(0xB0B)));
    }

    function expectBound(PackedUserOperation memory op, address payable beneficiary) internal {
        uint256 limit = bound();
        (bool included, uint256 loss, uint256 spent) = run(op, beneficiary);
        assertTrue(included, "honest-shaped op rejected");
        assertEq(receiver.x(), 42, "committed action did not run");
        assertEq(receiver.paid(), VALUE, "committed value not delivered");
        assertEq(spent, VALUE, "balance moved beyond the committed value");
        assertLe(loss, limit, "loss above the worst case at the committed ceilings");
    }

    function withPaymaster(PackedUserOperation memory op, uint256 vgl, uint256 postOp, bytes memory pmData)
        internal
        returns (PackedUserOperation memory)
    {
        HostilePaymaster pm = new HostilePaymaster();
        entryPoint.depositTo{value: 1 ether}(address(pm));
        op.paymasterAndData = abi.encodePacked(address(pm), uint128(vgl), uint128(postOp), pmData);
        return op;
    }

    // --- PackedUserOperation fields ------------------------------------------

    function test_field_sender() public {
        PackedUserOperation memory op = honest();
        op.sender = address(0xdead);
        expectRejected(op);
    }

    function test_field_nonce() public {
        // The 192-bit nonce key is free to whoever builds the op; any key whose
        // sequence is current is valid.
        PackedUserOperation memory op = honest();
        op.nonce = uint256(7) << 64;
        expectBound(op);
    }

    function test_field_initCode() public {
        PackedUserOperation memory op = honest();
        op.initCode = abi.encodePacked(address(0xdead), hex"00");
        expectRejected(op);
    }

    function test_field_callData() public {
        PackedUserOperation memory op = honest();
        op.callData = abi.encodeCall(account.execute, (address(receiver), VALUE, abi.encodeCall(Receiver.setX, (999))));
        expectRejected(op);
    }

    function test_field_callData_padding() public {
        // F9: trailing bytes decode away but are copied and billed.
        PackedUserOperation memory op = honest();
        op.callData = abi.encodePacked(op.callData, new bytes(100_000));
        expectRejected(op);
    }

    function test_field_preVerificationGas() public {
        PackedUserOperation memory op = honest();
        op.preVerificationGas = MAX_PVG_CEIL + 1;
        expectRejected(op);
    }

    function test_field_signature() public {
        // F9: trailing bytes after the ABI-encoded authorization decode away,
        // but the EntryPoint copies and bills them, so the length is exact.
        PackedUserOperation memory op = honest();
        op.signature = abi.encodePacked(op.signature, new bytes(100_000));
        expectRejected(op);
    }

    function test_field_signature_ceilings() public {
        // Raising a ceiling inside the signature changes the commitment preimage.
        PackedUserOperation memory op = honest();
        op.signature = abi.encode(leafIndex, secret, proof, MAX_FEE_CAP * 100, CALL_GAS_FLOOR, MAX_PVG_CEIL * 100);
        op.gasFees = bytes32((MAX_FEE_CAP * 100 << 128) | MAX_FEE_CAP * 100);
        expectRejected(op);
    }

    // --- subfields the EntryPoint unpacks ------------------------------------

    function test_field_verificationGasLimit() public {
        // Unused verification gas is refunded, not penalized, while the
        // prefund it implies fits the deposit.
        PackedUserOperation memory op = honest();
        op.accountGasLimits = bytes32((HUGE << 128) | CALL_GAS_FLOOR);
        expectBound(op);
    }

    function test_field_verificationGasLimit_sweep() public {
        // F8: a prefund beyond the deposit used to be paid from the balance,
        // starving the committed transfer and burning the leaf.
        PackedUserOperation memory op = honest();
        op.gasFees = bytes32((MAX_FEE_CAP << 128) | MAX_FEE_CAP);
        op.accountGasLimits = bytes32((uint256(99_000_000) << 128) | CALL_GAS_FLOOR);
        expectRejected(op);
    }

    function test_field_callGasLimit() public {
        // F7: the EntryPoint bills 10% of unused call gas, so a call-gas limit
        // far above the action's need drains the deposit unless it is capped.
        PackedUserOperation memory op = honest();
        op.accountGasLimits = bytes32((HONEST_VGL << 128) | HUGE);
        expectRejected(op);
    }

    function test_field_maxPriorityFeePerGas() public {
        // The price paid is min(maxFeePerGas, priority + basefee), so a priority
        // above the cap is clipped by the committed fee cap.
        PackedUserOperation memory op = honest();
        op.gasFees = bytes32((uint256(1000 gwei) << 128) | MAX_FEE_CAP);
        expectBound(op);
    }

    function test_field_maxFeePerGas() public {
        PackedUserOperation memory op = honest();
        op.gasFees = bytes32((uint256(1 gwei) << 128) | (MAX_FEE_CAP + 1));
        expectRejected(op);
    }

    function test_field_paymaster() public {
        // F10: a bundler-chosen paymaster could revert in postOp after the
        // nullifier was set; the account accepts no paymaster.
        PackedUserOperation memory op = withPaymaster(honest(), 100_000, 0, "");
        expectRejected(op);
    }

    function test_field_paymasterVerificationGasLimit() public {
        PackedUserOperation memory op = withPaymaster(honest(), HUGE, 0, "");
        expectRejected(op);
    }

    function test_field_postOpGasLimit() public {
        PackedUserOperation memory op = withPaymaster(honest(), 100_000, HUGE, "");
        expectRejected(op);
    }

    function test_field_paymasterData() public {
        PackedUserOperation memory op = withPaymaster(honest(), 100_000, 0, hex"deadbeef");
        expectRejected(op);
    }

    // --- handleOps arguments -------------------------------------------------

    function test_field_beneficiary() public {
        expectBound(honest(), payable(address(0xBAD)));
    }
}
