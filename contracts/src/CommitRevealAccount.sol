// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title CommitRevealAccount
/// @notice Smart account authorized by one-time hash secrets under a Merkle
///         root instead of per-transaction signatures. Spending is two-phase:
///         commit a hash binding the exact action and a leaf secret, wait
///         minCommitAge blocks, then reveal the secret and Merkle path to
///         execute. Security rests on keccak256 preimage and collision
///         resistance, which survive a quantum adversary; no elliptic-curve
///         assumption exists anywhere in the authorization path.
/// @dev    Normative reference: docs/SPEC.md. The Rust tooling in tooling/
///         must produce byte-identical hashes for every structure here.
contract CommitRevealAccount {
    // Every hash in the protocol carries a distinct domain tag as its first
    // abi.encode field, so a value computed in one role (leaf, node,
    // commitment) can never be replayed in another.
    bytes32 internal constant TAG_LEAF = keccak256("QCA/v1/leaf");
    bytes32 internal constant TAG_NODE = keccak256("QCA/v1/node");
    bytes32 internal constant TAG_ACTION = keccak256("QCA/v1/action");
    bytes32 internal constant TAG_COMMIT = keccak256("QCA/v1/commit");

    /// @notice Active authorization tree root.
    bytes32 public root;
    /// @notice Depth of the active tree; proofs must have exactly this length.
    uint256 public depth;

    /// @notice Blocks a commitment must age before it can be revealed. This
    ///         is the anti-front-running parameter: an observer who extracts
    ///         a secret from a pending reveal must post their own commitment
    ///         and wait this long, while the victim's reveal is already
    ///         eligible for inclusion.
    uint256 public immutable minCommitAge;
    /// @notice Blocks after which a commitment expires. Bounds how long
    ///         secret-bound state can linger on-chain.
    uint256 public immutable commitTTL;

    /// @notice Nullifier set, one bit per leaf index, 256 leaves per slot.
    ///         Bits are never cleared, including across root rotations.
    mapping(uint256 => uint256) public usedLeaves;
    /// @notice Commitment hash => block number it was posted in (0 = absent).
    mapping(bytes32 => uint256) public commitments;

    event Committed(bytes32 indexed commitment);
    event Revealed(uint256 indexed leafIndex, bytes32 indexed actionHash, bool success);
    event RootRotated(bytes32 indexed newRoot, uint256 newDepth);
    event Pruned(bytes32 indexed commitment);

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
    error NotSelf();

    constructor(bytes32 root_, uint256 depth_, uint256 minCommitAge_, uint256 commitTTL_) payable {
        _checkDepth(depth_);
        // A zero minimum age would allow commit and reveal in the same block,
        // which voids the anti-front-running property entirely.
        if (minCommitAge_ == 0 || commitTTL_ <= minCommitAge_) revert InvalidWindow();
        root = root_;
        depth = depth_;
        minCommitAge = minCommitAge_;
        commitTTL = commitTTL_;
    }

    receive() external payable {}

    /// @notice Post a commitment. Permissionless: the hash binds the account,
    ///         the exact action and a leaf secret, so a copied or front-run
    ///         commit is either identical (harmless) or useless.
    function commit(bytes32 c) external {
        // First write wins. Allowing overwrites would let an observer refresh
        // a victim's commitment block forever, holding their reveal below
        // minCommitAge.
        if (commitments[c] != 0) revert CommitmentExists();
        commitments[c] = block.number;
        emit Committed(c);
    }

    /// @notice Open a commitment and execute its action.
    /// @dev    A failed action still consumes the leaf and the commitment:
    ///         the secret became public the moment this transaction hit the
    ///         mempool, so it must never authorize anything again. Reverting
    ///         here would roll the nullifier back and hand the leaf to
    ///         whoever saw the calldata.
    function reveal(
        address target,
        uint256 value,
        bytes calldata data,
        uint256 leafIndex,
        bytes32 secret,
        bytes32[] calldata proof
    ) external returns (bool success, bytes memory result) {
        uint256 d = depth;
        if (proof.length != d) revert InvalidProofLength();
        if (leafIndex >= (1 << d)) revert LeafIndexOutOfRange();

        uint256 word = leafIndex >> 8;
        uint256 bit = 1 << (leafIndex & 0xff);
        if (usedLeaves[word] & bit != 0) revert LeafAlreadyUsed();

        // Merkle membership: fold the leaf up the path, direction from the
        // index bits.
        bytes32 node = keccak256(abi.encode(TAG_LEAF, secret));
        uint256 idx = leafIndex;
        for (uint256 i = 0; i < d; ++i) {
            node = idx & 1 == 0
                ? keccak256(abi.encode(TAG_NODE, node, proof[i]))
                : keccak256(abi.encode(TAG_NODE, proof[i], node));
            idx >>= 1;
        }
        if (node != root) revert InvalidProof();

        // Recompute the commitment from what is being revealed. Binding to
        // chainid and address(this) kills cross-chain and cross-account
        // replay; binding actionHash and secret in one preimage means the
        // opening cannot be rebound to a different action.
        bytes32 actionHash = keccak256(abi.encode(TAG_ACTION, target, value, keccak256(data)));
        bytes32 c = keccak256(abi.encode(TAG_COMMIT, block.chainid, address(this), actionHash, leafIndex, secret));

        uint256 committedAt = commitments[c];
        if (committedAt == 0) revert UnknownCommitment();
        if (block.number < committedAt + minCommitAge) revert CommitmentTooYoung();
        if (block.number > committedAt + commitTTL) revert CommitmentExpired();

        // Effects strictly before the external call.
        usedLeaves[word] |= bit;
        delete commitments[c];

        (success, result) = target.call{value: value}(data);
        emit Revealed(leafIndex, actionHash, success);
    }

    /// @notice Rotate to a new authorization tree. Only callable by the
    ///         account itself, i.e. through a revealed action. This is the
    ///         break-glass response to suspected seed exposure; it cancels
    ///         every in-flight commitment whose leaf is not in the new tree.
    ///         The nullifier bitmap survives rotation, so new trees must use
    ///         fresh leaf indices (the tooling tracks a global offset).
    function rotate(bytes32 newRoot, uint256 newDepth) external {
        if (msg.sender != address(this)) revert NotSelf();
        _checkDepth(newDepth);
        root = newRoot;
        depth = newDepth;
        emit RootRotated(newRoot, newDepth);
    }

    /// @notice Delete an expired commitment for the storage refund. Anyone
    ///         may call; live commitments cannot be pruned.
    function prune(bytes32 c) external {
        uint256 committedAt = commitments[c];
        if (committedAt == 0) revert UnknownCommitment();
        if (block.number <= committedAt + commitTTL) revert CommitmentLive();
        delete commitments[c];
        emit Pruned(c);
    }

    /// @notice Whether a leaf index has been consumed.
    function isLeafUsed(uint256 leafIndex) external view returns (bool) {
        return usedLeaves[leafIndex >> 8] & (1 << (leafIndex & 0xff)) != 0;
    }

    function _checkDepth(uint256 d) internal pure {
        // 2^32 leaves is far beyond any realistic account lifetime; the cap
        // bounds proof length and keeps 1 << d well-defined.
        if (d == 0 || d > 32) revert InvalidDepth();
    }
}
