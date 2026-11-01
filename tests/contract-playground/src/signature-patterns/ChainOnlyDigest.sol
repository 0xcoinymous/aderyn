// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Vulnerable: the digest binds the chain but not the contract, so another deployment that trusts the
// same signer accepts the same signature (cross-contract replay).
contract ChainOnlyDigest {
    address public immutable signer;
    mapping(uint256 => bool) public used;
    mapping(address => uint256) public balances;

    constructor(address signer_) { signer = signer_; }

    function claim(uint256 id, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        require(!used[id], "used");
        bytes32 digest = keccak256(abi.encodePacked(msg.sender, block.chainid, id, amount));
        require(ecrecover(digest, v, r, s) == signer, "bad sig");
        used[id] = true;
        balances[msg.sender] += amount;
    }
}
