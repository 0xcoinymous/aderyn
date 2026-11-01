// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Safe: checks written as `if (..) revert`, inside an unchecked block, with the nonce of the recovered
// signer advanced in the condition.
contract RevertGuardDelegate {
    error InvalidSig();
    error Expired();
    mapping(address => uint256) public nonces;
    mapping(address => address) public delegates;

    function delegateBySig(address delegatee, uint256 nonce, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
        if (block.timestamp > deadline) revert Expired();
        address recoveredAddress = ecrecover(
            keccak256(abi.encode(delegatee, nonce, deadline, address(this), block.chainid)), v, r, s
        );
        if (recoveredAddress == address(0)) revert InvalidSig();
        unchecked {
            if (nonce != nonces[recoveredAddress]++) revert InvalidSig();
        }
        delegates[recoveredAddress] = delegatee;
    }
}
