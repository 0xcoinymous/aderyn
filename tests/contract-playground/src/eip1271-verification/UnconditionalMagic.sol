// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Vulnerable implementation: returns the magic value for every hash and signature.
contract UnconditionalMagic {
    address public immutable owner;

    constructor(address owner_) { owner = owner_; }

    function isValidSignature(bytes32 hash, bytes calldata signature) external pure returns (bytes4) {
        hash;
        signature;
        return 0x1626ba7e;
    }
}
