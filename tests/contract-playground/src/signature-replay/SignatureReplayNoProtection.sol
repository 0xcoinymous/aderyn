// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SignatureReplayNoProtection {
    address public signer;
    mapping(address => uint256) public paid;

    constructor(address signer_) { signer = signer_; }

    function claim(address account, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encode(account, amount));
        require(ecrecover(digest, v, r, s) == signer, "bad sig");
        paid[account] += amount;
    }
}
