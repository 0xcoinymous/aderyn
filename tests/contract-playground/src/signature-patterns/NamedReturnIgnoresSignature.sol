// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Vulnerable: the named return variable receives the magic value without the signature being checked.
contract NamedReturnIgnoresSignature {
    bytes4 internal constant _ERC_1271_MAGIC_VALUE = 0x1626ba7e;
    mapping(bytes32 => bool) public known;

    function isValidSignature(bytes32 digest, bytes calldata signature) external view returns (bytes4 magicValue) {
        require(signature.length == 65, "length");
        require(known[digest], "unknown");
        magicValue = _ERC_1271_MAGIC_VALUE;
    }
}
