// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IAccount} from "@account-abstraction/interfaces/IAccount.sol";
import {IEntryPoint} from "@account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@account-abstraction/interfaces/PackedUserOperation.sol";

/// @title QCAAccount4337
/// @notice An ERC-4337 (v0.8) smart account whose authorization is the
///         hash-based commit-reveal of docs/SPEC.md, carried entirely inside
///         validateUserOp. There is no signature and no elliptic-curve
///         assumption in the account's authorization path.
/// @dev    This is the paper-2 artifact: it moves the commit-reveal
///         authorization into account abstraction. What it does NOT do is
///         remove ECDSA end-to-end: the bundler's handleOps (or a self-bundled
///         call) is still an ECDSA-signed outer transaction. On post-Pectra
///         mainnet every inclusion path bottoms out at ECDSA; 4337 relocates
///         the envelope from the owner's EOA to a bundler's, it does not
///         eliminate it. Full elimination needs native AA (EIP-7701/RIP-7560),
///         which is not live. See docs/AA.md.
///
///         Two design constraints come from the 4337 validation rules
///         (ERC-7562), and both are honored here:
///         1. Validation may read only the account's OWN storage for an
///            arbitrary key (rule STO-010), so the commitments mapping and the
///            authorization root live in THIS contract, never in a shared
///            registry.
///         2. Validation may not use block.timestamp or block.number (rule
///            OP-011). Aging is therefore expressed by returning a validAfter
///            time range that the EntryPoint enforces, and commitments store
///            block.timestamp (a wall-clock instant), not a block number. This
///            changes the aging unit from blocks to seconds; see docs/AA.md.
contract QCAAccount4337 is IAccount {
    bytes32 internal constant TAG_LEAF = keccak256("QCA/v1/leaf");
    bytes32 internal constant TAG_NODE = keccak256("QCA/v1/node");
    bytes32 internal constant TAG_ACTION = keccak256("QCA/v1/action");
    bytes32 internal constant TAG_COMMIT = keccak256("QCA/v1/commit");
    bytes32 internal constant TAG_BURN = keccak256("QCA/v1/burn");

    // ERC-4337 validationData: 0 authorizer == success, 1 == signature failure.
    uint256 internal constant SIG_OK = 0;
    uint256 internal constant SIG_FAIL = 1;

    IEntryPoint public immutable entryPoint;

    bytes32 public root;
    uint256 public depth;

    /// @notice Minimum age a commitment must reach before its reveal is valid,
    ///         in SECONDS (wall-clock), because validation cannot read block
    ///         numbers. The anti-front-running semantics are unchanged: an
    ///         observer who extracts a secret still needs a commitment of their
    ///         own to age this long while the victim's is already aged.
    uint256 public immutable minCommitAge;
    /// @notice Seconds after which a commitment expires.
    uint256 public immutable commitTTL;

    /// @notice Nullifier set, keyed by leaf hash H(TAG_LEAF, secret).
    mapping(bytes32 => bool) public usedLeaves;
    /// @notice Commitment hash => unix timestamp it was posted at (0 = absent).
    mapping(bytes32 => uint256) public commitments;

    event Committed(bytes32 indexed commitment);
    /// Emitted at nullification (in validation), so a scanning wallet can
    /// reconstruct which leaf a reveal consumed. The base scheme relies on
    /// this for write-ahead recovery; the 4337 path must not lose it.
    event LeafConsumed(bytes32 indexed leafHash, uint256 leafIndex);
    event Executed(bytes32 indexed actionHash, bool success);
    event LeafBurned(bytes32 indexed leafHash, uint256 leafIndex);
    event RootRotated(bytes32 indexed newRoot, uint256 newDepth);
    event Pruned(bytes32 indexed commitment);

    error NotEntryPoint();
    error CommitmentExists();
    error InvalidProofLength();
    error LeafIndexOutOfRange();
    error InvalidProof();
    error InvalidDepth();
    error InvalidWindow();
    error UnknownCommitment();
    error CommitmentTooYoung();
    error CommitmentExpired();
    error CommitmentLive();
    error LeafAlreadyUsed();
    error BadCallData();
    error FeeCapExceeded();
    error CallGasBelowFloor();
    error NotSelf();

    modifier onlyEntryPoint() {
        if (msg.sender != address(entryPoint)) revert NotEntryPoint();
        _;
    }

    constructor(IEntryPoint entryPoint_, bytes32 root_, uint256 depth_, uint256 minCommitAge_, uint256 commitTTL_)
        payable
    {
        _checkDepth(depth_);
        if (minCommitAge_ == 0 || commitTTL_ <= minCommitAge_) revert InvalidWindow();
        entryPoint = entryPoint_;
        root = root_;
        depth = depth_;
        minCommitAge = minCommitAge_;
        commitTTL = commitTTL_;
    }

    receive() external payable {}

    /// @notice Post a commitment. Permissionless, exactly as in the base
    ///         scheme; the hash binds the account, the exact action, a leaf
    ///         index and a secret. Stores the current wall-clock time.
    function commit(bytes32 c) external {
        if (commitments[c] != 0) revert CommitmentExists();
        commitments[c] = block.timestamp;
        emit Committed(c);
    }

    /// @notice ERC-4337 validation. The reveal material (leaf index, secret,
    ///         Merkle proof, and the committed fee cap and call-gas floor) is
    ///         carried in userOp.signature; the action is userOp.callData,
    ///         which the EntryPoint executes verbatim if this returns success.
    ///
    ///         Binding is the whole game. The commitment binds not only the
    ///         action (target, value, data, parsed from the same callData bytes
    ///         the EntryPoint executes, so a bundler cannot retarget) but also
    ///         a maximum fee-per-gas and a minimum call-gas limit. Both are
    ///         necessary: without a fee cap a bundler replays the reveal with
    ///         maxFeePerGas set astronomically and drains the account's
    ///         EntryPoint deposit as fees to itself (theft, not griefing);
    ///         without a call-gas floor a bundler sets callGasLimit just low
    ///         enough to starve execute, so the leaf is consumed (nullified
    ///         below) while the action never runs, a forced irrecoverable leaf
    ///         burn. Binding both closes those surfaces. Even so, a bundler
    ///         that receives the reveal privately can still withhold it and win
    ///         a withhold-and-age race (GAME.md Theorem 3); this construction
    ///         downgrades a PUBLIC-mempool bundler to censorship, not a trusted
    ///         private one. See docs/AA.md.
    /// @dev    Effects (nullifier set, commitment cleared, LeafConsumed event)
    ///         happen here. If the EntryPoint later rejects the op because the
    ///         returned time range excludes the current block, the whole
    ///         handleOps reverts and these writes roll back. Note "consumed"
    ///         means validation passed and the bundle did not revert; the
    ///         action itself may still revert (it consumes the leaf anyway,
    ///         because the secret is already public), but it cannot be starved
    ///         below the committed call-gas floor.
    function validateUserOp(PackedUserOperation calldata userOp, bytes32, uint256 missingAccountFunds)
        external
        onlyEntryPoint
        returns (uint256 validationData)
    {
        (uint256 leafIndex, bytes32 secret, bytes32[] memory proof, uint256 maxFeeCap, uint256 callGasFloor) =
            _decodeAuth(userOp.signature);
        (address target, uint256 value, bytes memory data) = _decodeExecute(userOp.callData);

        // Enforce the committed gas envelope against the actual UserOp fields.
        // gasFees packs maxPriorityFeePerGas (high 128) | maxFeePerGas (low
        // 128); accountGasLimits packs verificationGasLimit | callGasLimit.
        if (uint128(uint256(userOp.gasFees)) > maxFeeCap) revert FeeCapExceeded();
        if (uint128(uint256(userOp.accountGasLimits)) < callGasFloor) revert CallGasBelowFloor();

        bytes32 leafHash = _verifyMembership(leafIndex, secret, proof);
        if (usedLeaves[leafHash]) revert LeafAlreadyUsed();

        bytes32 actionHash = keccak256(abi.encode(TAG_ACTION, target, value, keccak256(data)));
        bytes32 c = keccak256(
            abi.encode(TAG_COMMIT, block.chainid, address(this), actionHash, leafIndex, secret, maxFeeCap, callGasFloor)
        );

        uint256 committedAt = commitments[c];
        if (committedAt == 0) revert UnknownCommitment();

        // Effects strictly before the EntryPoint executes callData.
        usedLeaves[leafHash] = true;
        delete commitments[c];
        emit LeafConsumed(leafHash, leafIndex);

        _payPrefund(missingAccountFunds);

        // The aging and expiry gates are handed to the EntryPoint as a time
        // range; it enforces validAfter <= block.timestamp <= validUntil
        // outside the banned-opcode scope. We never read block.timestamp here.
        uint48 validAfter = uint48(committedAt + minCommitAge);
        uint48 validUntil = uint48(committedAt + commitTTL);
        return _packValidationData(validAfter, validUntil);
    }

    /// @notice Execute the committed action. Only the EntryPoint may call this,
    ///         and it does so only after validateUserOp authorized this exact
    ///         callData with a call-gas limit at or above the committed floor.
    ///         A reverted action still counts as executed: the leaf was already
    ///         nullified in validation, because the secret became public the
    ///         moment the UserOp entered the mempool.
    function execute(address target, uint256 value, bytes calldata data)
        external
        onlyEntryPoint
        returns (bool success, bytes memory result)
    {
        (success, result) = target.call{value: value}(data);
        bytes32 actionHash = keccak256(abi.encode(TAG_ACTION, target, value, keccak256(data)));
        emit Executed(actionHash, success);
    }

    /// @notice Rotate to a new authorization tree. Reachable only as a
    ///         committed, revealed self-action (execute with target == this),
    ///         so it inherits the full commit-reveal authorization. This is the
    ///         break-glass response to suspected seed exposure and to sustained
    ///         griefing, and it must exist in the 4337 account for the same
    ///         reason it does in the base scheme.
    function rotate(bytes32 newRoot, uint256 newDepth) external {
        if (msg.sender != address(this)) revert NotSelf();
        _checkDepth(newDepth);
        root = newRoot;
        depth = newDepth;
        emit RootRotated(newRoot, newDepth);
    }

    /// @notice Delete an expired commitment for the storage refund. Anyone may
    ///         call; live commitments cannot be pruned.
    function prune(bytes32 c) external {
        uint256 committedAt = commitments[c];
        if (committedAt == 0) revert UnknownCommitment();
        if (block.timestamp <= committedAt + commitTTL) revert CommitmentLive();
        delete commitments[c];
        emit Pruned(c);
    }

    /// @notice Age-gated defensive nullify, matching the base scheme's burn.
    ///         Callable directly (not through the EntryPoint) as an ordinary
    ///         transaction, because it must remain available even when the
    ///         account cannot produce a UserOp. It opens its own aged burn
    ///         commitment (domain-separated by TAG_BURN) and reads block
    ///         numbers freely, since it is not validation code.
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

    // --- decoding -----------------------------------------------------------

    /// @dev userOp.signature = abi.encode(leafIndex, secret, proof, maxFeeCap,
    ///      callGasFloor). maxFeeCap and callGasFloor are the gas-envelope
    ///      bounds bound into the commitment; validation both recomputes the
    ///      commitment from them and enforces the actual UserOp gas fields
    ///      against them.
    function _decodeAuth(bytes calldata sig)
        internal
        pure
        returns (uint256 leafIndex, bytes32 secret, bytes32[] memory proof, uint256 maxFeeCap, uint256 callGasFloor)
    {
        return abi.decode(sig, (uint256, bytes32, bytes32[], uint256, uint256));
    }

    /// @dev userOp.callData = execute.selector ++ abi.encode(target,value,data).
    ///      Requiring the selector binds validation to the exact call the
    ///      EntryPoint will make, so authorization and execution cannot diverge.
    function _decodeExecute(bytes calldata callData)
        internal
        pure
        returns (address target, uint256 value, bytes memory data)
    {
        if (callData.length < 4 || bytes4(callData[:4]) != this.execute.selector) revert BadCallData();
        (target, value, data) = abi.decode(callData[4:], (address, uint256, bytes));
    }

    // --- helpers ------------------------------------------------------------

    function _payPrefund(uint256 missingAccountFunds) internal {
        if (missingAccountFunds != 0) {
            (bool ok,) = payable(msg.sender).call{value: missingAccountFunds}("");
            (ok); // EntryPoint handles a failed prefund; ignore per 4337 pattern.
        }
    }

    /// @dev Pack a time range into ERC-4337 validationData with a passing
    ///      authorizer: <20B 0><6B validUntil><6B validAfter>.
    function _packValidationData(uint48 validAfter, uint48 validUntil) internal pure returns (uint256) {
        return SIG_OK | (uint256(validUntil) << 160) | (uint256(validAfter) << (160 + 48));
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
