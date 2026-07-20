// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address who) external view returns (uint256);
}

/// @title AAHelper
/// @notice A stand-in for an EIP-7702 "smart account" delegate: the kind of
///         helper contract an agent's EOA delegates itself to for batching or
///         gasless UX. Once the agent signs an authorization pointing its
///         account at this code, calls to the agent's own address run this
///         code in the agent's context (address(this) == the agent), so
///         `sweep` moves the agent's own tokens.
///
///         A hardened delegate gates `sweep` to the account owner or a trusted
///         entry point. This one does not, modelling the well-documented class
///         of 7702 delegate contracts with missing caller checks that let
///         anyone drain a delegated account. The point stands even for a
///         hardened delegate: signing the authorization hands over arbitrary
///         execution, and a policy that vets the delegate's address cannot see
///         what its code is allowed to do.
contract AAHelper {
    function sweep(address token, address to) external {
        IERC20 t = IERC20(token);
        t.transfer(to, t.balanceOf(address(this)));
    }
}
