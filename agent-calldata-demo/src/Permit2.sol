// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @title Permit2
/// @notice A minimal, faithful model of Uniswap's canonical Permit2
///         SignatureTransfer surface. Permit2 is the universal approval
///         contract: a user (or agent) approves it once for the maximum amount,
///         and every wallet, policy, and allowlist treats that approval as
///         normal because you cannot use most of DeFi without it. From then on,
///         token security reduces entirely to off-chain Permit2 signatures:
///         `permitTransferFrom` moves the owner's tokens on presentation of a
///         signed message, pulling through the standing approval. A poisoned
///         tool that gets the agent to sign one such message (spender = the
///         attacker) drains the account, and the on-chain approval that enabled
///         it looked completely benign.
contract Permit2 {
    bytes32 public immutable DOMAIN_SEPARATOR;

    bytes32 public constant TOKEN_PERMISSIONS_TYPEHASH =
        keccak256("TokenPermissions(address token,uint256 amount)");
    bytes32 public constant PERMIT_TRANSFER_TYPEHASH = keccak256(
        "PermitTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline)"
        "TokenPermissions(address token,uint256 amount)"
    );

    mapping(address => mapping(uint256 => bool)) public usedNonce;

    constructor() {
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("Permit2")),
                block.chainid,
                address(this)
            )
        );
    }

    // The spender committed in the signature is msg.sender: only the party the
    // owner authorized can execute the transfer, but it chooses the recipient.
    function permitTransferFrom(
        address token,
        uint256 amount,
        uint256 nonce,
        uint256 deadline,
        address to,
        address owner,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(deadline >= block.timestamp, "permit expired");
        require(!usedNonce[owner][nonce], "nonce used");
        usedNonce[owner][nonce] = true;

        bytes32 tokenPermissions = keccak256(
            abi.encode(TOKEN_PERMISSIONS_TYPEHASH, token, amount)
        );
        bytes32 structHash = keccak256(
            abi.encode(PERMIT_TRANSFER_TYPEHASH, tokenPermissions, msg.sender, nonce, deadline)
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        address recovered = ecrecover(digest, v, r, s);
        require(recovered != address(0) && recovered == owner, "bad permit2 signature");

        // pulls via the owner's standing max approval to this contract
        IERC20(token).transferFrom(owner, to, amount);
    }
}
