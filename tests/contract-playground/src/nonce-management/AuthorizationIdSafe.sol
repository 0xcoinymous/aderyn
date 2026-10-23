// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Safe: a random authorization id (EIP-3009 style) is signed, checked unused, and marked used.
contract AuthorizationIdSafe {
    mapping(address => mapping(bytes32 => bool)) public authorizationState;
    mapping(address => uint256) public credits;

    function transferWithAuthorization(address signer, address recipient, uint256 amount, bytes32 authorizationId, uint8 v, bytes32 r, bytes32 s) external {
        require(!authorizationState[signer][authorizationId], "authorization used");
        bytes32 digest = keccak256(abi.encode(signer, recipient, amount, authorizationId));
        require(ecrecover(digest, v, r, s) == signer, "invalid signature");
        authorizationState[signer][authorizationId] = true;
        credits[recipient] += amount;
    }
}
