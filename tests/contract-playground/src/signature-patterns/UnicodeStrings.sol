// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Multi-byte characters in strings and comments (🎆) must not break the analysis.
contract UnicodeStrings {
    string public name = unicode"🎇 Fireworks 🎆";
    address public immutable signer;
    mapping(address => uint256) public nonces;

    constructor(address signer_) { signer = signer_; }

    function claim(uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        if (amount == 0) { revert(unicode"zero 🎆"); }
        bytes32 digest = keccak256(abi.encode(msg.sender, amount, nonces[msg.sender]++, address(this), block.chainid));
        require(ecrecover(digest, v, r, s) == signer, "bad sig");
    }
}
