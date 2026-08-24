// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SignatureReplayNonceSafe {
    address public signer;
    mapping(address => uint256) public nonces;
    mapping(address => uint256) public paid;

    constructor(address signer_) { signer = signer_; }

    function claim(address account, uint256 amount, uint256 nonce, uint8 v, bytes32 r, bytes32 s) external {
        require(nonce == nonces[account], "bad nonce");
        bytes32 digest = keccak256(abi.encode(account, amount, nonce));
        require(ecrecover(digest, v, r, s) == signer, "bad sig");
        nonces[account] = nonce + 1;
        paid[account] += amount;
    }
}
