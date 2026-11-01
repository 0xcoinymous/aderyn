// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Vulnerable: the claim marks the signed hash used but never checks the mark, so the same signature
// pays out again.
contract NonceUsedFlagNeverChecked {
    address public signer;
    mapping(bytes32 => bool) public usedHash;
    mapping(address => uint256) public balances;
    function claim(uint256 amount, uint256 nonce, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 hash = keccak256(abi.encode(address(this), block.chainid, msg.sender, amount, nonce));
        require(ecrecover(hash, v, r, s) == signer, "sig");
        usedHash[hash] = true;
        balances[msg.sender] += amount;
    }
}
