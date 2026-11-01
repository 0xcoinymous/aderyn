// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Not ERC-1271: a library ECDSA helper called isValidSignature(hash, signer, signature).
library SignatureValidator {
    function isValidSignature(bytes32 hash, address signer, bytes memory signature) internal pure returns (bool) {
        require(signature.length == 65, "length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }
        return ecrecover(hash, v, r, s) == signer;
    }
}

contract EcdsaNamedIsValidSignature {
    mapping(bytes32 => uint256) public fills;

    function trade(bytes32 hash, address maker, bytes calldata signature) external {
        require(SignatureValidator.isValidSignature(hash, maker, signature), "signature");
        fills[hash] += 1;
    }
}
