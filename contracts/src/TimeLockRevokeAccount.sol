// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title TimeLockRevokeAccount
/// @notice A post-quantum account that makes an authorized action CANCELLABLE by
///         the owner without any party trusted with the funds. This is the
///         reference construction for the cancellability trilemma
///         (internal/paper3-cancellation.md): authorization does not execute
///         immediately, it enters a `delta`-block veto window during which the
///         owner may revoke it by revealing a *pre-designated, unused* one-time
///         leaf. An adversary who controls transaction inclusion can only CENSOR
///         the revoke, so cancellation fails only if the adversary suppresses it
///         for all `delta` blocks (probability beta^delta against a builder of
///         share beta, race-free under fair ordering).
///
/// @dev    Corrects the impossibility of docs/GAME.md Section 8 (which held only
///         for immediate-execution bearer instruments): with a latency budget
///         `delta`, a message-bound account achieves public + race-free +
///         trustless cancellation. The price is `delta` latency on every action,
///         which is the trilemma's priced corner and is unpayable for urgent /
///         MEV-sensitive actions.
///
///         Authorization uses the same one-time-secret + Merkle-membership
///         primitive as CommitRevealAccount (docs/SPEC.md): the enqueue is a
///         message-bound aged-commitment reveal (paper 1, so it cannot be
///         redirected to a different action), and the revoke reveals a leaf the
///         enqueue pre-committed as this queue's cancel credential (so it needs
///         no aging of its own and an adversary who copies it from the mempool
///         can only trigger the very cancellation the owner intended). The
///         construction is signature-scheme-agnostic; a message-bound one-time
///         hash signature (docs/SPEC-HASHSIG.md) substitutes for the aged
///         commitment with the same properties and less latency.
contract TimeLockRevokeAccount {
    bytes32 internal constant TAG_LEAF = keccak256("QCA/v1/leaf");
    bytes32 internal constant TAG_NODE = keccak256("QCA/v1/node");
    bytes32 internal constant TAG_ACTION = keccak256("QCA/v1/action");
    bytes32 internal constant TAG_COMMIT = keccak256("QCA/v1/commit");
    // Sits in the action-hash slot to domain-separate an enqueue commitment from
    // any reveal/burn commitment of the base account, so a commitment aged for
    // one role can never be opened in another.
    bytes32 internal constant TAG_ENQUEUE = keccak256("QCA/v3/enqueue");

    bytes32 public root;
    uint256 public depth;

    /// @notice Blocks an enqueue commitment must age before it opens. This is
    ///         paper 1's anti-front-running margin for the enqueue itself, and
    ///         is unrelated to the veto window: it is spent before the action is
    ///         queued, so it is not part of the cancellation latency.
    uint256 public immutable minCommitAge;
    /// @notice Blocks after which an enqueue commitment expires.
    uint256 public immutable commitTTL;
    /// @notice The veto window, in blocks: a queued action executes only at
    ///         `enqueueBlock + delta` and may be revoked before then. This is
    ///         the cancellation latency the trilemma prices. Operationally it
    ///         MUST be at least chain finality, so the queued entry is final
    ///         before it can execute and a sub-final reorg cannot carry the
    ///         action past a revoke the owner already intends (the reorg cushion
    ///         and the cancellation window are the same knob).
    uint256 public immutable delta;

    /// @notice Nullifier set, keyed by leaf hash H(TAG_LEAF, secret). Shared by
    ///         enqueue leaves and revoke leaves: every leaf is one-time.
    mapping(bytes32 => bool) public usedLeaves;
    /// @notice Enqueue commitment hash => block posted (0 = absent).
    mapping(bytes32 => uint256) public commitments;

    struct Queued {
        bytes32 actionHash; // binds (target, value, data); execute must match
        bytes32 revokeLeaf; // H(TAG_LEAF, secret_j): the designated cancel credential
        uint256 unlock; // block at/after which execute is allowed
        uint256 callGasLimit; // owner-committed execution budget (F1: not caller-chosen)
        bool live;
    }

    /// @notice queueId (= the enqueue leaf hash) => queued entry.
    mapping(bytes32 => Queued) public queue;

    event Committed(bytes32 indexed commitment);
    event Enqueued(bytes32 indexed queueId, bytes32 indexed actionHash, uint256 unlock);
    event Executed(bytes32 indexed queueId, bytes32 indexed actionHash, bool success);
    event Revoked(bytes32 indexed queueId, bytes32 indexed revokeLeaf);
    event RootRotated(bytes32 indexed newRoot, uint256 newDepth);

    error CommitmentExists();
    error UnknownCommitment();
    error CommitmentTooYoung();
    error CommitmentExpired();
    error LeafAlreadyUsed();
    error InvalidProofLength();
    error LeafIndexOutOfRange();
    error InvalidProof();
    error InvalidDepth();
    error InvalidWindow();
    error QueueExists();
    error BadRevokeLeaf();
    error NoSuchQueue();
    error NotUnlocked();
    error WindowClosed();
    error ActionMismatch();
    error WrongRevokeLeaf();
    error NotSelf();
    error InsufficientGas();

    constructor(bytes32 root_, uint256 depth_, uint256 minCommitAge_, uint256 commitTTL_, uint256 delta_) payable {
        _checkDepth(depth_);
        if (minCommitAge_ == 0 || commitTTL_ <= minCommitAge_ || delta_ == 0) revert InvalidWindow();
        root = root_;
        depth = depth_;
        minCommitAge = minCommitAge_;
        commitTTL = commitTTL_;
        delta = delta_;
    }

    receive() external payable {}

    /// @notice Post an enqueue commitment. Permissionless; binds the account, the
    ///         action, the designated revoke leaf, and the enqueue secret, so a
    ///         copied commit is either identical (harmless) or useless.
    function commitEnqueue(bytes32 c) external {
        if (commitments[c] != 0) revert CommitmentExists();
        commitments[c] = block.number;
        emit Committed(c);
    }

    /// @notice Open an aged enqueue commitment and QUEUE the action (does not
    ///         execute it). The owner designates, at commit time, a distinct
    ///         unused leaf `revokeLeaf` as this queue's cancel credential.
    /// @param  revokeLeaf H(TAG_LEAF, secret_j) for a distinct unused leaf j; the
    ///         only credential that can later revoke this queue.
    /// @param  callGasLimit the execution budget bound into the queue and forwarded
    ///         to the action at execute time. Binding it (F1) closes a
    ///         gas-starvation grief: because execute is permissionless, a
    ///         caller-chosen budget would let anyone execute with too little gas so
    ///         the action OOGs while the queue is consumed. The owner commits the
    ///         budget here; execute forwards exactly it, regardless of who submits.
    function enqueue(
        address target,
        uint256 value,
        bytes calldata data,
        uint256 leafIndex,
        bytes32 secret,
        bytes32 revokeLeaf,
        uint256 callGasLimit,
        bytes32[] calldata proof
    ) external {
        bytes32 leafHash = _verifyMembership(leafIndex, secret, proof);
        if (usedLeaves[leafHash]) revert LeafAlreadyUsed();
        // The designated revoke leaf must be a distinct, still-unused leaf, or the
        // queue would be silently uncancellable (F2). Only the owner can enqueue,
        // so this is a footgun guard, not an adversary defense.
        if (revokeLeaf == leafHash || usedLeaves[revokeLeaf]) revert BadRevokeLeaf();

        bytes32 actionHash = keccak256(abi.encode(TAG_ACTION, target, value, keccak256(data)));
        bytes32 c = keccak256(
            abi.encode(
                TAG_COMMIT,
                block.chainid,
                address(this),
                TAG_ENQUEUE,
                actionHash,
                revokeLeaf,
                leafIndex,
                secret,
                callGasLimit
            )
        );
        uint256 committedAt = commitments[c];
        if (committedAt == 0) revert UnknownCommitment();
        if (block.number < committedAt + minCommitAge) revert CommitmentTooYoung();
        if (block.number > committedAt + commitTTL) revert CommitmentExpired();

        // queueId is the enqueue leaf hash: one queue slot per one-time leaf, so
        // it can never collide across the account's life.
        if (queue[leafHash].live) revert QueueExists();

        usedLeaves[leafHash] = true;
        delete commitments[c];

        uint256 unlockAt = block.number + delta;
        queue[leafHash] = Queued({
            actionHash: actionHash,
            revokeLeaf: revokeLeaf,
            unlock: unlockAt,
            callGasLimit: callGasLimit,
            live: true
        });
        emit Enqueued(leafHash, actionHash, unlockAt);
    }

    /// @notice Execute a queued action after its veto window closes. Permissionless
    ///         (the design's liveness guarantee: the owner does not need any party
    ///         to execute). Reverts if the queue was revoked. The execution budget
    ///         is the owner-committed `q.callGasLimit`, not a caller argument (F1):
    ///         a submitter who cannot supply that budget reverts BEFORE the queue
    ///         is consumed, so a low-gas call cannot burn the action.
    function executeQueued(bytes32 queueId, address target, uint256 value, bytes calldata data)
        external
        returns (bool success, bytes memory result)
    {
        Queued memory q = queue[queueId];
        if (!q.live) revert NoSuchQueue();
        if (block.number < q.unlock) revert NotUnlocked();
        bytes32 actionHash = keccak256(abi.encode(TAG_ACTION, target, value, keccak256(data)));
        if (actionHash != q.actionHash) revert ActionMismatch();
        // Guarantee the committed budget can reach the action before consuming the
        // queue. Revert-before-mutate, exactly as the base account's reveal.
        if (gasleft() < q.callGasLimit + q.callGasLimit / 63 + 40_000) revert InsufficientGas();

        queue[queueId].live = false;
        (success, result) = target.call{gas: q.callGasLimit, value: value}(data);
        emit Executed(queueId, actionHash, success);
    }

    /// @notice Cancel a queued action before its unlock, by revealing the unused
    ///         leaf the enqueue designated as this queue's revoke credential.
    /// @dev    No aging: binding is by the pre-designated `revokeLeaf`, so an
    ///         adversary who copies this call from the mempool can only revoke the
    ///         SAME queue (the reveal only matches this queue's `revokeLeaf`),
    ///         which is exactly the owner's intent and therefore harmless. The
    ///         adversary cannot forge a revoke for a queue whose revoke secret was
    ///         never revealed (an unused leaf's secret is not public), and cannot
    ///         redirect it to a different queue. Its only move is to censor this
    ///         call for the whole veto window.
    function revoke(bytes32 queueId, uint256 revokeLeafIndex, bytes32 revokeSecret, bytes32[] calldata proof)
        external
    {
        Queued memory q = queue[queueId];
        if (!q.live) revert NoSuchQueue();
        if (block.number >= q.unlock) revert WindowClosed();

        bytes32 leafHash = _verifyMembership(revokeLeafIndex, revokeSecret, proof);
        if (leafHash != q.revokeLeaf) revert WrongRevokeLeaf();
        if (usedLeaves[leafHash]) revert LeafAlreadyUsed();

        // Spend the revoke leaf and cancel the queue. The queued action can never
        // execute (executeQueued requires q.live).
        usedLeaves[leafHash] = true;
        queue[queueId].live = false;
        delete queue[queueId];
        emit Revoked(queueId, leafHash);
    }

    /// @notice Rotate to a new tree; only via a queued+executed self-call. The
    ///         break-glass response to seed exposure.
    function rotate(bytes32 newRoot, uint256 newDepth) external {
        if (msg.sender != address(this)) revert NotSelf();
        _checkDepth(newDepth);
        root = newRoot;
        depth = newDepth;
        emit RootRotated(newRoot, newDepth);
    }

    function _verifyMembership(uint256 leafIndex, bytes32 secret, bytes32[] calldata proof)
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
