// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Vulnerable: the nonce is checked and consumed but is not part of the signed digest,
// so one signature authorizes the action for every nonce value.
contract NonceNotAuthenticated {
    mapping(address => uint256) public nonces;
    mapping(address => uint256) public credits;

    function claim(address signer, address recipient, uint256 amount, uint256 nonce, uint8 v, bytes32 r, bytes32 s) external {
        require(nonce == nonces[signer], "wrong nonce");
        bytes32 digest = keccak256(abi.encode(signer, recipient, amount));
        require(ecrecover(digest, v, r, s) == signer, "invalid signature");
        nonces[signer] = nonce + 1;
        credits[recipient] += amount;
    }
}
