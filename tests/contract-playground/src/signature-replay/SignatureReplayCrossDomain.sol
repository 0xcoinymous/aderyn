// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// The authorization is consumed, but the digest binds neither this contract nor the chain: the same
// signature can be replayed on every other deployment and chain that trusts the same signer.
contract SignatureReplayCrossDomain {
    address public signer;
    mapping(bytes32 => bool) public used;
    mapping(address => uint256) public credits;

    constructor(address signer_) { signer = signer_; }

    function claim(address account, uint256 amount, bytes32 id, uint8 v, bytes32 r, bytes32 s) external {
        require(!used[id], "used");
        bytes32 digest = keccak256(abi.encode(account, amount, id));
        require(ecrecover(digest, v, r, s) == signer, "bad sig");
        used[id] = true;
        credits[account] += amount;
    }
}
