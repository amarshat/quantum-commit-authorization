// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IAccount, ACCOUNT_VALIDATION_SUCCESS_MAGIC} from
    "@matterlabs/zksync-contracts/contracts/system-contracts/interfaces/IAccount.sol";
import {Transaction, TransactionHelper} from
    "@matterlabs/zksync-contracts/contracts/system-contracts/libraries/TransactionHelper.sol";
import {SystemContractsCaller} from
    "@matterlabs/zksync-contracts/contracts/system-contracts/libraries/SystemContractsCaller.sol";
import {INonceHolder} from
    "@matterlabs/zksync-contracts/contracts/system-contracts/interfaces/INonceHolder.sol";
import {
    BOOTLOADER_FORMAL_ADDRESS,
    NONCE_HOLDER_SYSTEM_CONTRACT
} from "@matterlabs/zksync-contracts/contracts/system-contracts/Constants.sol";

/// @title QCAAccountZkSync
/// @notice A zkSync Era native-AA account (IAccount / tx type 0x71) authorized
///         by the hash-based commit-reveal of docs/SPEC.md. This is the
///         end-to-end existence proof: under native account abstraction the
///         account's authorization path has no elliptic-curve assumption AND no
///         ECDSA envelope, because a type-0x71 transaction is validated only by
///         this contract's validateTransaction, with no protocol-level
///         secp256k1 signature anywhere. Contrast the L1/4337 result, where
///         inclusion still requires an ECDSA-signed handleOps (see docs/AA.md).
///
/// @dev    Two zkSync-specific design points, both from the native-AA
///         validation constraints (see docs/AA-ZKSYNC.md):
///
///         1. Aging is enforced in executeTransaction, not validation.
///         Validation may not read block.timestamp (the zkSync validation
///         rules keep the 4337 forbidden-opcode set relevant), and unlike
///         ERC-4337 there is no EntryPoint to hand a validAfter range to. So
///         validation verifies membership, the gas-envelope binding, and that
///         a matching commitment exists, but the min-age and expiry gates run
///         in executeTransaction, where block.timestamp is available. The leaf
///         is nullified there, strictly after the aging check and before the
///         external call, so a too-young reveal reverts WITHOUT consuming the
///         leaf (it leaks the secret, recoverable via burn, exactly as in the
///         base scheme), while an aged reveal consumes the leaf even if the
///         action reverts.
///
///         2. The security-critical caveat is the sequencer. zkSync Era runs a
///         private mempool behind a single sequencer, so the reveal (secret +
///         proof in the tx) is seen only by that one party before inclusion,
///         which can withhold the victim's reveal and age its own competing
///         commitment. That is the base scheme's relay-capitulation theorem in
///         its strongest form: native AA removes the ECDSA envelope but
///         relocates the aging window's front-running security onto trust in
///         the sequencer. This contract cannot fix that; it is a property of
///         the platform, documented, not solved.
contract QCAAccountZkSync is IAccount {
    using TransactionHelper for Transaction;

    bytes32 internal constant TAG_LEAF = keccak256("QCA/v1/leaf");
    bytes32 internal constant TAG_NODE = keccak256("QCA/v1/node");
    bytes32 internal constant TAG_ACTION = keccak256("QCA/v1/action");
    bytes32 internal constant TAG_COMMIT = keccak256("QCA/v1/commit");
    bytes32 internal constant TAG_BURN = keccak256("QCA/v1/burn");

    bytes32 public root;
    uint256 public depth;
    uint256 public immutable minCommitAge; // seconds (wall-clock)
    uint256 public immutable commitTTL; // seconds

    mapping(bytes32 => bool) public usedLeaves;
    mapping(bytes32 => uint256) public commitments; // c => post timestamp

    event Committed(bytes32 indexed commitment);
    event LeafConsumed(bytes32 indexed leafHash, uint256 leafIndex);
    event Executed(bytes32 indexed actionHash, bool success);
    event LeafBurned(bytes32 indexed leafHash, uint256 leafIndex);
    event RootRotated(bytes32 indexed newRoot, uint256 newDepth);
    event Pruned(bytes32 indexed commitment);

    error NotBootloader();
    error NotSelf();
    error CommitmentExists();
    error UnknownCommitment();
    error CommitmentTooYoung();
    error CommitmentExpired();
    error CommitmentLive();
    error LeafAlreadyUsed();
    error InvalidProofLength();
    error LeafIndexOutOfRange();
    error InvalidProof();
    error InvalidDepth();
    error InvalidWindow();
    error FeeCapExceeded();
    error CallGasBelowFloor();
    error InsufficientBalance();

    modifier onlyBootloader() {
        if (msg.sender != BOOTLOADER_FORMAL_ADDRESS) revert NotBootloader();
        _;
    }

    constructor(bytes32 root_, uint256 depth_, uint256 minCommitAge_, uint256 commitTTL_) payable {
        _checkDepth(depth_);
        if (minCommitAge_ == 0 || commitTTL_ <= minCommitAge_) revert InvalidWindow();
        root = root_;
        depth = depth_;
        minCommitAge = minCommitAge_;
        commitTTL = commitTTL_;
    }

    receive() external payable {}

    /// @notice Post a commitment. Permissionless, stores the wall-clock time.
    function commit(bytes32 c) external {
        if (commitments[c] != 0) revert CommitmentExists();
        commitments[c] = block.timestamp;
        emit Committed(c);
    }

    // --- IAccount ----------------------------------------------------------

    function validateTransaction(bytes32, bytes32, Transaction calldata transaction)
        external
        payable
        onlyBootloader
        returns (bytes4 magic)
    {
        return _validate(transaction);
    }

    function _validate(Transaction calldata transaction) internal returns (bytes4) {
        // Authorization checks first, so an invalid transaction is rejected
        // before any system call (and, on a revert, the nonce is untouched).
        _authorize(transaction);

        // Increment the account nonce through the NonceHolder system contract,
        // as every native-AA account must.
        SystemContractsCaller.systemCallWithPropagatedRevert(
            uint32(gasleft()),
            address(NONCE_HOLDER_SYSTEM_CONTRACT),
            0,
            abi.encodeCall(INonceHolder.incrementMinNonceIfEquals, (transaction.nonce))
        );

        return ACCOUNT_VALIDATION_SUCCESS_MAGIC;
    }

    /// @dev The signature-free authorization: membership, the gas-envelope
    ///      binding, and a matching commitment. No system call, no time read
    ///      (aging is in executeTransaction). Reverts on any failure.
    function _authorize(Transaction calldata transaction) internal view {
        (uint256 leafIndex, bytes32 secret, bytes32[] memory proof, uint256 maxFeeCap, uint256 callGasFloor) =
            abi.decode(transaction.signature, (uint256, bytes32, bytes32[], uint256, uint256));

        // Bind the gas envelope: a sequencer must not inflate the fee (which
        // the account pays to the bootloader) or starve the call gas.
        if (transaction.maxFeePerGas > maxFeeCap) revert FeeCapExceeded();
        if (transaction.gasLimit < callGasFloor) revert CallGasBelowFloor();

        bytes32 leafHash = _verifyMembership(leafIndex, secret, proof);
        if (usedLeaves[leafHash]) revert LeafAlreadyUsed();

        bytes32 c = _commitmentOf(transaction, leafIndex, secret, maxFeeCap, callGasFloor);
        if (commitments[c] == 0) revert UnknownCommitment();

        if (address(this).balance < transaction.totalRequiredBalance()) revert InsufficientBalance();
    }

    function executeTransaction(bytes32, bytes32, Transaction calldata transaction)
        external
        payable
        onlyBootloader
    {
        _execute(transaction);
    }

    function _execute(Transaction calldata transaction) internal {
        (uint256 leafIndex, bytes32 secret,, uint256 maxFeeCap, uint256 callGasFloor) =
            abi.decode(transaction.signature, (uint256, bytes32, bytes32[], uint256, uint256));

        bytes32 c = _commitmentOf(transaction, leafIndex, secret, maxFeeCap, callGasFloor);
        uint256 committedAt = commitments[c];
        if (committedAt == 0) revert UnknownCommitment();

        // Aging and expiry, enforced here because validation cannot read time.
        if (block.timestamp < committedAt + minCommitAge) revert CommitmentTooYoung();
        if (block.timestamp > committedAt + commitTTL) revert CommitmentExpired();

        // Effects strictly after the aging check and before the call: a
        // too-young reveal reverts without consuming the leaf; an aged reveal
        // consumes it even if the action reverts.
        bytes32 leafHash = keccak256(abi.encode(TAG_LEAF, secret));
        if (usedLeaves[leafHash]) revert LeafAlreadyUsed();
        usedLeaves[leafHash] = true;
        delete commitments[c];
        emit LeafConsumed(leafHash, leafIndex);

        address target = address(uint160(transaction.to));
        (bool success,) = target.call{value: transaction.value}(transaction.data);
        bytes32 actionHash = keccak256(abi.encode(TAG_ACTION, target, transaction.value, keccak256(transaction.data)));
        emit Executed(actionHash, success);
    }

    function executeTransactionFromOutside(Transaction calldata transaction) external payable {
        // Priority-mode fallback. Runs the same checks in one call (no
        // bootloader nonce management). Kept minimal; the main path is
        // validate-then-execute via the bootloader.
        _validate(transaction);
        _execute(transaction);
    }

    function payForTransaction(bytes32, bytes32, Transaction calldata transaction) external payable onlyBootloader {
        bool ok = transaction.payToTheBootloader();
        require(ok, "pay failed");
    }

    function prepareForPaymaster(bytes32, bytes32, Transaction calldata transaction)
        external
        payable
        onlyBootloader
    {
        transaction.processPaymasterInput();
    }

    // --- recovery (plain transactions, block.timestamp available) -----------

    function burn(uint256 leafIndex, bytes32 secret, bytes32[] calldata proof) external {
        bytes32 leafHash = _verifyMembership(leafIndex, secret, proof);
        if (usedLeaves[leafHash]) revert LeafAlreadyUsed();
        bytes32 c = keccak256(abi.encode(TAG_COMMIT, block.chainid, address(this), TAG_BURN, leafIndex, secret));
        uint256 committedAt = commitments[c];
        if (committedAt == 0) revert UnknownCommitment();
        if (block.timestamp < committedAt + minCommitAge) revert CommitmentTooYoung();
        if (block.timestamp > committedAt + commitTTL) revert CommitmentExpired();
        usedLeaves[leafHash] = true;
        delete commitments[c];
        emit LeafBurned(leafHash, leafIndex);
    }

    function rotate(bytes32 newRoot, uint256 newDepth) external {
        if (msg.sender != address(this)) revert NotSelf();
        _checkDepth(newDepth);
        root = newRoot;
        depth = newDepth;
        emit RootRotated(newRoot, newDepth);
    }

    function prune(bytes32 c) external {
        uint256 committedAt = commitments[c];
        if (committedAt == 0) revert UnknownCommitment();
        if (block.timestamp <= committedAt + commitTTL) revert CommitmentLive();
        delete commitments[c];
        emit Pruned(c);
    }

    // --- helpers -----------------------------------------------------------

    function _commitmentOf(
        Transaction calldata transaction,
        uint256 leafIndex,
        bytes32 secret,
        uint256 maxFeeCap,
        uint256 callGasFloor
    ) internal view returns (bytes32) {
        address target = address(uint160(transaction.to));
        bytes32 actionHash = keccak256(abi.encode(TAG_ACTION, target, transaction.value, keccak256(transaction.data)));
        return keccak256(
            abi.encode(
                TAG_COMMIT, block.chainid, address(this), actionHash, leafIndex, secret, maxFeeCap, callGasFloor
            )
        );
    }

    function _verifyMembership(uint256 leafIndex, bytes32 secret, bytes32[] memory proof)
        internal
        view
        returns (bytes32 leafHash)
    {
        uint256 d = depth;
        if (proof.length != d) revert InvalidProofLength();
        if (leafIndex >= (1 << d)) revert LeafIndexOutOfRange();
        leafHash = keccak256(abi.encode(TAG_LEAF, secret));
        bytes32 node = leafHash;
        uint256 idx = leafIndex;
        for (uint256 i = 0; i < d; ++i) {
            node = idx & 1 == 0
                ? keccak256(abi.encode(TAG_NODE, node, proof[i]))
                : keccak256(abi.encode(TAG_NODE, proof[i], node));
            idx >>= 1;
        }
        if (node != root) revert InvalidProof();
    }

    function _checkDepth(uint256 d) internal pure {
        if (d == 0 || d > 32) revert InvalidDepth();
    }
}
